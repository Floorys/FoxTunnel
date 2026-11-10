"""Firefox native messaging host. Stdlib only; never writes text to stdout.

One foreground sing-box child per native port. No shell execution, no HTTP API,
no TUN device and no changes to the OS proxy/DNS. Windows Job Object kills the
child even if Firefox forcibly kills this host.
"""
from __future__ import annotations

from collections import deque
import copy
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parent
CORE = ROOT / "bin" / ("sing-box.exe" if os.name == "nt" else "sing-box")
DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share"))) / "FoxTunnel"
MAX_MESSAGE = 1024 * 1024
MAX_LOG = 512 * 1024
DEFAULT_PROBE_URL = "https://cp.cloudflare.com/generate_204"
TYPES = {"vless", "vmess", "hysteria2", "hysteria", "trojan", "shadowsocks", "tuic", "anytls", "socks", "http", "shadowtls", "naive"}
FORBIDDEN_KEYS = {"detour", "outbounds", "inbounds", "endpoints", "providers", "route", "dns", "experimental", "ntp", "log"}
CREATE_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def _chmod_private(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _secure_unlink(path: Path | None) -> None:
    if path is None:
        return
    try:
        if path.is_file():
            size = path.stat().st_size
            if size > 0:
                with path.open("r+b") as stream:
                    stream.write(b"\x00" * min(size, 1024 * 1024))
                    stream.flush()
    except OSError:
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def validate_outbound(value):
    if not isinstance(value, dict) or value.get("type") not in TYPES:
        raise ValueError("Unsupported sing-box outbound type")
    result = copy.deepcopy(value)
    server = result.get("server")
    if (
        not isinstance(server, str)
        or not server.strip()
        or any(c.isspace() or ord(c) < 32 or c in "/\\[]" for c in server)
    ):
        raise ValueError("Invalid server address")
    port = result.get("server_port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid server_port")

    def walk(obj):
        if isinstance(obj, dict):
            for key, child in obj.items():
                if not isinstance(key, str):
                    raise ValueError("Invalid object key")
                if key.endswith("_path") or key in FORBIDDEN_KEYS:
                    raise ValueError(f"Profile field {key} is not allowed")
                walk(child)
        elif isinstance(obj, list):
            for child in obj:
                walk(child)

    walk(result)
    if result["type"] in {"vless", "vmess", "tuic"}:
        try:
            uuid.UUID(result.get("uuid", ""))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Invalid UUID") from None
    if result["type"] == "shadowsocks":
        method = result.get("method")
        password = result.get("password")
        if not isinstance(method, str) or not method.strip() or not isinstance(password, str) or not password:
            raise ValueError("Shadowsocks requires non-empty method and password")
    if result["type"] in {"trojan", "anytls", "hysteria2"}:
        password = result.get("password")
        if not isinstance(password, str) or not password:
            raise ValueError(f"{result['type']} requires non-empty password")
    if result["type"] == "vmess" and "alter_id" in result:
        aid = result["alter_id"]
        if isinstance(aid, bool) or not isinstance(aid, int) or aid < 0:
            raise ValueError("VMess alter_id must be a non-negative integer")
    for obj_key in ("tls", "transport"):
        if obj_key in result and not isinstance(result[obj_key], dict):
            raise ValueError(f"Outbound {obj_key} must be an object")

    result["tag"] = "proxy"
    # Bootstrap resolution must not recurse through the outbound itself.
    result["domain_resolver"] = "bootstrap"
    return result


def build_config(outbound, settings):
    outbound = validate_outbound(outbound)
    if not isinstance(settings, dict):
        raise ValueError("Invalid settings")
    port = settings.get("port", 2080)
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("Local port must be between 1024 and 65535")
    level = settings.get("logLevel", "warn")
    if level not in {"trace", "debug", "info", "warn", "error"}:
        raise ValueError("Invalid log level")
    dns_mode = settings.get("dnsMode", "remote")
    if dns_mode not in {"remote", "doh"}:
        raise ValueError("Invalid DNS mode")
    mode = settings.get("mode", "rules")
    if mode not in {"rules", "global"}:
        raise ValueError("Invalid routing mode")
    default_action = settings.get("defaultAction", "direct")
    if default_action not in {"direct", "proxy", "block"}:
        raise ValueError("Invalid default routing action")

    config = {
        "log": {"level": level, "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "bootstrap"}], "final": "bootstrap"},
        "inbounds": [{"type": "socks", "tag": "firefox", "listen": "127.0.0.1", "listen_port": port}],
        # Only the proxy outbound is exposed here: Firefox routes direct traffic itself,
        # so sing-box must never leak SOCKS traffic directly.
        "outbounds": [outbound],
        "route": {"default_domain_resolver": "bootstrap", "rules": [], "final": "proxy"},
    }
    if dns_mode == "doh":
        raw_server = settings.get("dnsServer", "1.1.1.1")
        if not isinstance(raw_server, str):
            raise ValueError("Invalid DoH server IP")
        server = str(ipaddress.ip_address(raw_server.strip("[]")))
        server_name = settings.get("dnsServerName", "cloudflare-dns.com")
        path = settings.get("dnsPath", "/dns-query")
        if (
            not isinstance(server_name, str)
            or not server_name
            or any(c.isspace() or ord(c) < 32 or c in "/\\?#" for c in server_name)
        ):
            raise ValueError("Invalid DoH TLS server name")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(c.isspace() or ord(c) < 32 for c in path)
            or len(path) > 512
        ):
            raise ValueError("Invalid DoH path")
        config["dns"]["servers"].append({
            "type": "https",
            "tag": "secure",
            "server": server,
            "server_port": 443,
            "path": path,
            "tls": {"enabled": True, "server_name": server_name},
            "detour": "proxy",
        })

    rules = settings.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 2000:
        raise ValueError("Invalid routing rules")
    mapping = {"domain": "domain", "suffix": "domain_suffix", "keyword": "domain_keyword"}
    leading_rejects = []
    tail_rules = []
    saw_proxy_rule = False

    for rule in rules:
        if not isinstance(rule, dict) or rule.get("kind") not in mapping or rule.get("action") not in {"proxy", "direct", "block"}:
            raise ValueError("Invalid domain rule")
        value = rule.get("value")
        if not isinstance(value, str) or not value or len(value) > 253:
            raise ValueError("Invalid domain rule value")
        if any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError("Invalid characters in domain rule value")
        if rule["kind"] in {"domain", "suffix"} and any(c in "/?#@*\\[]" for c in value):
            raise ValueError("Invalid domain characters in domain rule")
        if rule.get("enabled") is False:
            continue
        if rule["action"] == "direct":
            # Direct rules are executed by Firefox before SOCKS and must not create
            # a direct route inside sing-box.
            continue
        entry = {mapping[rule["kind"]]: [value]}
        if rule["action"] == "block":
            entry["action"] = "reject"
            if not saw_proxy_rule:
                leading_rejects.append(entry)
            else:
                tail_rules.append(entry)
        else:
            saw_proxy_rule = True
            entry.update(action="route", outbound="proxy")
            tail_rules.append(entry)

    config["route"]["rules"].extend(leading_rejects)
    needs_proxy_dns = mode == "global" or default_action != "block" or saw_proxy_rule
    if dns_mode == "doh" and needs_proxy_dns:
        config["route"]["rules"].append({"action": "resolve", "server": "secure", "strategy": "prefer_ipv4"})
    config["route"]["rules"].extend(tail_rules)
    if mode == "rules" and default_action == "block":
        config["route"]["rules"].append({"action": "reject"})
    return config


class WindowsJob:
    """A handle with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    def __init__(self):
        self.handle = None
        if os.name != "nt":
            return
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IOCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IOCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process):
        if self.handle and not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class Host:
    def __init__(self, core=CORE, data=DATA):
        self.core = Path(core)
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True)
        _chmod_private(self.data, 0o700)
        self.process = None
        self.job = None
        self.log_thread = None
        self.config_path = None
        self.port = None
        self.version_cache = None
        self.log_path = self.data / "core.log"
        self.log_lock = threading.Lock()
        self.cleanup_stale_configs()

    def cleanup_stale_configs(self):
        for stale in self.data.glob("config-*.json"):
            if stale != self.config_path:
                _secure_unlink(stale)

    def version(self):
        if not self.core.is_file():
            raise FileNotFoundError("sing-box не найден. Выполните native/install.cmd или native/install.ps1 -DownloadCore, либо поместите ядро в native/bin.")
        if not self.version_cache:
            result = subprocess.run([str(self.core), "version"], capture_output=True, timeout=5, creationflags=CREATE_FLAGS)
            if result.returncode:
                raise RuntimeError("Не удалось запустить sing-box version")
            lines = result.stdout.decode("utf-8", "replace").splitlines()
            if not lines:
                raise RuntimeError("sing-box version вернул пустой ответ")
            self.version_cache = lines[0]
        return self.version_cache

    def write_config(self, config):
        fd, filename = tempfile.mkstemp(prefix="config-", suffix=".json", dir=self.data)
        path = Path(filename)
        _chmod_private(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(config, stream, ensure_ascii=False)
        return path

    def validate_config(self, config):
        self.version()
        path = self.write_config(config)
        try:
            result = subprocess.run([str(self.core), "check", "-c", str(path)], capture_output=True, timeout=15, creationflags=CREATE_FLAGS)
            if result.returncode:
                detail = (result.stderr + result.stdout).decode("utf-8", "replace")[-6000:]
                raise ValueError("sing-box отклонил конфигурацию:\n" + detail)
        finally:
            _secure_unlink(path)

    def drain_logs(self, process):
        # Keep draining even when full, otherwise a full pipe can hang the core.
        stream = None
        try:
            with self.log_lock:
                stream = self.log_path.open("wb")
                _chmod_private(self.log_path, 0o600)
            size = 0
            read_fn = getattr(process.stdout, "read1", process.stdout.read)
            while True:
                chunk = read_fn(4096)
                if not chunk:
                    break
                if size + len(chunk) > MAX_LOG:
                    banner = b"[Earlier log data truncated]\n"
                    with self.log_lock:
                        stream.seek(0)
                        stream.truncate()
                        stream.write(banner)
                    size = len(banner)
                with self.log_lock:
                    stream.write(chunk)
                    stream.flush()
                size += len(chunk)
        except OSError:
            # Continue consuming stdout if writing the log file fails.
            try:
                while process.stdout.read(4096):
                    pass
            except OSError:
                pass
        finally:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _ensure_port_available(self, port_num: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port_num)) == 0:
                raise RuntimeError("Локальный порт занят. Выберите другой в настройках.")
        deadline = time.monotonic() + 1.0
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                if os.name == "nt":
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                try:
                    probe.bind(("127.0.0.1", port_num))
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Локальный порт занят. Выберите другой в настройках.") from None
                    time.sleep(0.05)

    def start(self, outbound, settings):
        try:
            config = build_config(outbound, settings)
            self.validate_config(config)
        except Exception:
            self.stop()
            raise
        self.stop()
        self.cleanup_stale_configs()
        self.port = config["inbounds"][0]["listen_port"]
        # Never mistake an unrelated listener for our newly started process.
        try:
            self._ensure_port_available(self.port)
        except Exception:
            self.port = None
            raise
        self.config_path = self.write_config(config)
        try:
            self.job = WindowsJob()
            self.process = subprocess.Popen(
                [str(self.core), "run", "-c", str(self.config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=CREATE_FLAGS,
            )
            self.job.assign(self.process)
            self.log_thread = threading.Thread(target=self.drain_logs, args=(self.process,), daemon=True)
            self.log_thread.start()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Ядро завершилось при запуске:\n" + self.logs()["text"][-4000:])
                try:
                    # Verify an actual SOCKS5 handshake, not only an open TCP port.
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.3) as conn:
                        conn.sendall(b"\x05\x01\x00")
                        with conn.makefile("rb") as sock_file:
                            if read_exact(sock_file, 2) == b"\x05\x00":
                                time.sleep(0.1)
                                if self.process.poll() is None:
                                    return self.status()
                except (OSError, EOFError):
                    pass
                time.sleep(0.1)
            raise RuntimeError("Ядро не открыло SOCKS5 listener за 8 секунд")
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=4)
            if self.log_thread:
                self.log_thread.join(timeout=2)
            if self.process.stdout:
                try:
                    self.process.stdout.close()
                except OSError:
                    pass
        if self.job:
            self.job.close()
        if self.config_path:
            _secure_unlink(self.config_path)
        self.process = self.job = self.log_thread = self.config_path = None
        self.port = None
        return {"running": False}

    def status(self):
        running = self.process is not None and self.process.poll() is None
        return {
            "running": running,
            "pid": self.process.pid if running else None,
            "port": self.port if running else None,
            "coreVersion": self.version(),
            "corePath": str(self.core),
            "dataPath": str(self.data),
            "note": "Running means local SOCKS listener, not verified remote connectivity.",
        }

    def logs(self):
        with self.log_lock:
            if not self.log_path.exists():
                return {"text": ""}
            with self.log_path.open("rb") as stream:
                stream.seek(max(0, self.log_path.stat().st_size - 60000))
                return {"text": stream.read(60000).decode("utf-8", "replace")}

    def probe(self, outbound, settings, probe_url=None, timeout=8.0):
        self.version()
        raw_url = (probe_url or DEFAULT_PROBE_URL) if probe_url is not None else DEFAULT_PROBE_URL
        scheme, target_host, target_port, path_and_query, use_tls = parse_probe_url(raw_url)
        probe_port = reserve_ephemeral_port()
        probe_settings = {
            "port": probe_port,
            "logLevel": "warn",
            "dnsMode": settings.get("dnsMode", "remote") if isinstance(settings, dict) else "remote",
            "dnsServer": settings.get("dnsServer", "1.1.1.1") if isinstance(settings, dict) else "1.1.1.1",
            "dnsServerName": settings.get("dnsServerName", "cloudflare-dns.com") if isinstance(settings, dict) else "cloudflare-dns.com",
            "dnsPath": settings.get("dnsPath", "/dns-query") if isinstance(settings, dict) else "/dns-query",
            "mode": "global",
            "defaultAction": "proxy",
            "rules": [],
        }
        config = build_config(outbound, probe_settings)
        cfg_path = self.write_config(config)
        proc = None
        job = None
        drain_thread = None
        output_lines = deque(maxlen=40)

        def drain():
            try:
                while proc and proc.stdout:
                    line = proc.stdout.readline(4096)
                    if not line:
                        break
                    text = line.decode("utf-8", "replace").strip()
                    if text:
                        output_lines.append(text)
            except OSError:
                pass

        try:
            job = WindowsJob()
            proc = subprocess.Popen(
                [str(self.core), "run", "-c", str(cfg_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=CREATE_FLAGS,
            )
            job.assign(proc)
            drain_thread = threading.Thread(target=drain, daemon=True)
            drain_thread.start()

            ready_deadline = time.monotonic() + 5.0
            ready = False
            while time.monotonic() < ready_deadline:
                if proc.poll() is not None:
                    if drain_thread:
                        drain_thread.join(timeout=0.5)
                    detail = "\n".join(output_lines)[-1200:]
                    raise RuntimeError("Ядро отклонило конфиг при проверке:\n" + detail)
                try:
                    with socket.create_connection(("127.0.0.1", probe_port), timeout=0.25) as conn:
                        conn.sendall(b"\x05\x01\x00")
                        if recv_exact(conn, 2) == b"\x05\x00":
                            ready = True
                            break
                except (OSError, EOFError):
                    pass
                time.sleep(0.05)
            if not ready:
                raise RuntimeError("Временный SOCKS5-слушатель проверки не запустился за 5 секунд.")

            try:
                latency_ms, status_code = socks5_http_probe(
                    probe_port, target_host, target_port, path_and_query, use_tls, timeout=timeout
                )
            except Exception as err:
                time.sleep(0.08)
                tail = list(output_lines)[-4:]
                detail = " | ".join(tail)[-500:]
                if detail:
                    raise RuntimeError(f"{err} ({detail})") from None
                raise RuntimeError(str(err)) from None

            return {
                "ok": True,
                "latencyMs": latency_ms,
                "status": status_code,
                "url": f"{scheme}://{target_host}{path_and_query}",
                "host": target_host,
            }
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
                if proc.stdout:
                    try:
                        proc.stdout.close()
                    except OSError:
                        pass
            if drain_thread:
                drain_thread.join(timeout=0.5)
            if job:
                job.close()
            _secure_unlink(cfg_path)

    def dispatch(self, message):
        command = message.get("command")
        if command == "start":
            return self.start(message.get("outbound"), message.get("settings", {}))
        if command == "stop":
            return self.stop()
        if command == "status":
            return self.status()
        if command == "logs":
            return self.logs()
        if command == "check":
            self.validate_config(build_config(message.get("outbound"), message.get("settings", {})))
            return {"valid": True, "coreVersion": self.version()}
        if command == "probe":
            return self.probe(
                message.get("outbound"),
                message.get("settings", {}),
                message.get("probeUrl"),
            )
        raise ValueError("Unknown native command")


def reserve_ephemeral_port() -> int:
    for _ in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port_num = s.getsockname()[1]
            if 1024 <= port_num <= 65535:
                return port_num
    raise RuntimeError("Не удалось выделить локальный порт для проверки.")


def parse_probe_url(raw_url: str) -> tuple[str, str, int, str, bool]:
    if not isinstance(raw_url, str) or not raw_url.strip() or len(raw_url) > 512:
        raise ValueError("Некорректный URL для проверки доступности.")
    parsed = urllib.parse.urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL проверки должен использовать http:// или https://.")
    if parsed.username or parsed.password:
        raise ValueError("URL проверки не должен содержать логин или пароль.")
    host = parsed.hostname
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError("В URL проверки отсутствует имя хоста.")
    lower = host.lower().rstrip(".")
    if lower == "localhost" or lower.endswith(".localhost"):
        raise ValueError("URL проверки не должен указывать на localhost.")
    try:
        ip = ipaddress.ip_address(lower)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            raise ValueError("URL проверки не должен указывать на локальный или приватный IP.")
        ascii_host = str(ip)
    except ValueError as err:
        if "URL проверки" in str(err):
            raise
        ascii_host = lower.encode("idna").decode("ascii")
    port_num = parsed.port or (443 if scheme == "https" else 80)
    if not 1 <= port_num <= 65535:
        raise ValueError("Некорректный порт в URL проверки.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, ascii_host, port_num, path, scheme == "https"


def recv_exact(sock, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        data = sock.recv(remaining)
        if not data:
            raise EOFError("Соединение закрыто удалённой стороной.")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def socks5_http_probe(
    socks_port: int,
    target_host: str,
    target_port: int,
    path_and_query: str,
    use_tls: bool,
    timeout: float = 8.0,
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout
    reply_errors = {
        1: "сбой прокси/сервера при подключении",
        2: "соединение запрещено правилами",
        3: "сеть недоступна",
        4: "хост недоступен",
        5: "сервер отклонил соединение",
        6: "истёк TTL",
        7: "команда не поддерживается",
        8: "тип адреса не поддерживается",
    }

    def remaining_timeout() -> float:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("Превышено время ожидания ответа от сервера.")
        return rem

    with socket.create_connection(("127.0.0.1", socks_port), timeout=remaining_timeout()) as raw_sock:
        t0 = time.monotonic()
        raw_sock.settimeout(remaining_timeout())
        raw_sock.sendall(b"\x05\x01\x00")
        if recv_exact(raw_sock, 2) != b"\x05\x00":
            raise RuntimeError("Некорректный ответ локального SOCKS5.")

        try:
            ip_obj = ipaddress.ip_address(target_host)
            if ip_obj.version == 4:
                addr_part = b"\x01" + ip_obj.packed
            else:
                addr_part = b"\x04" + ip_obj.packed
        except ValueError:
            host_bytes = target_host.encode("ascii")
            if len(host_bytes) > 255:
                raise ValueError("Слишком длинное имя хоста проверки.")
            addr_part = b"\x03" + bytes([len(host_bytes)]) + host_bytes

        raw_sock.settimeout(remaining_timeout())
        raw_sock.sendall(b"\x05\x01\x00" + addr_part + struct.pack("!H", target_port))
        ver, rep, _rsv, atyp = recv_exact(raw_sock, 4)
        if ver != 5:
            raise RuntimeError("Некорректная версия ответа SOCKS5.")
        if atyp == 1:
            recv_exact(raw_sock, 6)
        elif atyp == 4:
            recv_exact(raw_sock, 18)
        elif atyp == 3:
            name_len = recv_exact(raw_sock, 1)[0]
            recv_exact(raw_sock, name_len + 2)
        else:
            raise RuntimeError("Неизвестный тип адреса в ответе SOCKS5.")
        if rep != 0:
            raise RuntimeError(reply_errors.get(rep, f"ошибка SOCKS5 (код {rep})"))

        host_header = f"[{target_host}]" if ":" in target_host else target_host
        if (use_tls and target_port != 443) or (not use_tls and target_port != 80):
            host_header = f"{host_header}:{target_port}"
        request = (
            f"GET {path_and_query} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: FoxTunnel-Check/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        if use_tls:
            ctx = ssl.create_default_context()
            raw_sock.settimeout(remaining_timeout())
            with ctx.wrap_socket(raw_sock, server_hostname=target_host) as tls_sock:
                tls_sock.settimeout(remaining_timeout())
                tls_sock.sendall(request)
                status_code = _read_http_status(tls_sock, remaining_timeout)
        else:
            raw_sock.settimeout(remaining_timeout())
            raw_sock.sendall(request)
            status_code = _read_http_status(raw_sock, remaining_timeout)

        latency_ms = max(1, round((time.monotonic() - t0) * 1000))
        if not 200 <= status_code < 400:
            raise RuntimeError(f"Проверочный URL ответил HTTP {status_code}.")
        return latency_ms, status_code


def _read_http_status(sock, remaining_fn) -> int:
    buf = b""
    while b"\r\n" not in buf and len(buf) < 4096:
        sock.settimeout(remaining_fn())
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    first_line = buf.split(b"\r\n", 1)[0].decode("ascii", "replace").strip()
    parts = first_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise RuntimeError("Некорректный HTTP-ответ через туннель.")
    return int(parts[1])


def read_exact(stream, length):
    parts = []
    remaining = length
    while remaining:
        piece = stream.read(remaining)
        if not piece:
            if remaining == length:
                return None
            raise EOFError("Truncated native message")
        parts.append(piece)
        remaining -= len(piece)
    return b"".join(parts)


def read_message(stream):
    header = read_exact(stream, 4)
    if header is None:
        return None
    size = struct.unpack("<I", header)[0]
    if not 0 < size <= MAX_MESSAGE:
        raise ValueError("Native message size out of range")
    body = read_exact(stream, size)
    if body is None:
        raise EOFError("Missing native message body")
    message = json.loads(body.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("Native message must be an object")
    return message


def write_message(stream, message):
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise ValueError("Response too large")
    stream.write(struct.pack("<I", len(body)))
    stream.write(body)
    stream.flush()


def acquire_lock(data):
    data.mkdir(parents=True, exist_ok=True)
    _chmod_private(data, 0o700)
    lock_path = data / "host.lock"
    lock = lock_path.open("a+b")
    _chmod_private(lock_path, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            lock.seek(0, os.SEEK_END)
            if lock.tell() == 0:
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise RuntimeError("FoxTunnel уже используется другим профилем Firefox. Отключите его там.") from None
    return lock


def main():
    if os.name == "nt":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    stdin_stream = sys.stdin.buffer
    stdout_stream = sys.stdout.buffer
    # Prevent any accidental text output from corrupting Native Messaging stdout framing.
    sys.stdout = sys.stderr

    host = None
    lock = None
    setup_error = None
    try:
        try:
            lock = acquire_lock(DATA)
            host = Host()
        except Exception as error:
            setup_error = str(error)
        while True:
            message = read_message(stdin_stream)
            if message is None:
                break
            try:
                if lock is None:
                    lock = acquire_lock(DATA)
                if host is None:
                    host = Host()
                    setup_error = None
                elif setup_error:
                    raise RuntimeError(setup_error)
                result = host.dispatch(message)
                response = {"id": message.get("id"), "ok": True, "result": result}
            except Exception as error:
                response = {"id": message.get("id"), "ok": False, "error": str(error)[:10000]}
            try:
                write_message(stdout_stream, response)
            except ValueError:
                write_message(stdout_stream, {
                    "id": message.get("id"),
                    "ok": False,
                    "error": "Ответ локального помощника превысил лимит 1 МБ.",
                })
    except (BrokenPipeError, EOFError, ValueError, OSError):
        pass
    finally:
        if host:
            host.stop()
        if lock:
            lock.close()


if __name__ == "__main__":
    main()
