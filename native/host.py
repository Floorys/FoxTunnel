"""Firefox native messaging host. Stdlib only; never writes text to stdout.

One foreground sing-box child per native port. No shell execution, no HTTP API,
no TUN device and no changes to the OS proxy/DNS. Windows Job Object kills the
child even if Firefox forcibly kills this host.
"""
from __future__ import annotations

from collections import deque
import base64
import copy
import ctypes
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
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
GEO_MAX_BYTES = 64 * 1024 * 1024
GEO_SAMPLE_LIMIT = 150
DEFAULT_PROBE_URL = "https://cp.cloudflare.com/generate_204"
TYPES = {"vless", "vmess", "hysteria2", "hysteria", "trojan", "shadowsocks", "tuic", "anytls", "socks", "http", "shadowtls", "naive"}
FORBIDDEN_KEYS = {"detour", "outbounds", "inbounds", "endpoints", "providers", "route", "dns", "experimental", "ntp", "log"}
CORE_RULE_KINDS = {"cidr", "geoip", "geosite", "ruleset"}
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


_GEO_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_GEOSITE_BASE_RE = re.compile(r"^[a-z0-9][a-z0-9_!.-]{0,95}$")
_GEOSITE_ATTR_RE = re.compile(r"^!?[a-z0-9][a-z0-9_-]{0,31}$")


def _utc_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_cidr(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("Некорректный CIDR-диапазон в правиле.")
    clean = value.strip()
    if "/" not in clean:
        ip_obj = ipaddress.ip_address(clean.strip("[]"))
        return f"{ip_obj}/{128 if ip_obj.version == 6 else 32}"
    ip_part, prefix_part = clean.split("/", 1)
    ip_obj = ipaddress.ip_address(ip_part.strip("[]"))
    net = ipaddress.ip_network(f"{ip_obj}/{prefix_part}", strict=False)
    return str(net)


def normalize_geo_tag(value: str, kind: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError(f"Некорректный тег для правила {kind}.")
    raw = value.strip().lower()
    if kind == "geoip":
        if raw.startswith("geoip:"):
            raw = raw[6:]
        if not _GEO_TAG_RE.match(raw):
            raise ValueError(f"Некорректный тег GeoIP: «{value}».")
        return raw
    if kind == "geosite":
        if raw.startswith("geosite:"):
            raw = raw[8:]
        parts = raw.split("@", 1)
        if not _GEOSITE_BASE_RE.match(parts[0]):
            raise ValueError(f"Некорректный тег Geosite: «{value}».")
        if len(parts) == 2:
            if not _GEOSITE_ATTR_RE.match(parts[1]):
                raise ValueError(f"Некорректный атрибут Geosite: «{value}».")
            return f"{parts[0]}@{parts[1]}"
        return parts[0]
    for prefix in ("ruleset:", "rule-set:", "rule_set:"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    if not _GEO_TAG_RE.match(raw):
        raise ValueError(f"Некорректный тег Rule-Set: «{value}».")
    return raw


def _read_varint(buf: memoryview, pos: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < end and shift < 70:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("Повреждённые varint-данные в .dat файле.")


def _iter_pb_fields(buf: memoryview):
    pos = 0
    end = len(buf)
    while pos < end:
        tag, pos = _read_varint(buf, pos, end)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 0:
            raise ValueError("Некорректный номер поля protobuf (0) в .dat файле.")
        if wire_type == 0:
            val, pos = _read_varint(buf, pos, end)
            yield field_num, 0, val
        elif wire_type == 1:
            if pos + 8 > end:
                raise ValueError("Обрезанный fixed64 блок в .dat файле.")
            yield field_num, 1, buf[pos : pos + 8]
            pos += 8
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos, end)
            if pos + length > end:
                raise ValueError("Обрезанный length-delimited блок в .dat файле.")
            yield field_num, 2, buf[pos : pos + length]
            pos += length
        elif wire_type == 5:
            if pos + 4 > end:
                raise ValueError("Обрезанный fixed32 блок в .dat файле.")
            yield field_num, 5, buf[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"Неподдерживаемый protobuf wire type ({wire_type}) в .dat файле.")


def _extract_pb_code(entry_buf: memoryview) -> str:
    for field_num, wire_type, val in _iter_pb_fields(entry_buf):
        if field_num == 1 and wire_type == 2:
            return bytes(val).decode("utf-8", "replace").strip().lower()
    return ""


def _parse_geoip_cidrs(entry_buf: memoryview) -> list[str]:
    cidrs = []
    for field_num, wire_type, val in _iter_pb_fields(entry_buf):
        if field_num == 2 and wire_type == 2:
            ip_bytes = b""
            prefix = 0
            for cf, cw, cval in _iter_pb_fields(val):
                if cf == 1 and cw == 2:
                    ip_bytes = bytes(cval)
                elif cf == 2 and cw == 0:
                    prefix = int(cval)
            if len(ip_bytes) not in (4, 16):
                raise ValueError("Некорректная длина IP в записи geoip.dat.")
            ip_obj = ipaddress.ip_address(ip_bytes)
            max_prefix = 128 if ip_obj.version == 6 else 32
            if not 0 <= prefix <= max_prefix:
                raise ValueError("Некорректная маска подсети в geoip.dat.")
            cidrs.append(str(ipaddress.ip_network((ip_obj, prefix), strict=False)))
    return cidrs


def _parse_geosite_domains(entry_buf: memoryview) -> list[tuple[int, str, frozenset[str]]]:
    entries = []
    for field_num, wire_type, val in _iter_pb_fields(entry_buf):
        if field_num == 2 and wire_type == 2:
            dom_type = 0
            dom_val = ""
            attrs = []
            for df, dw, dval in _iter_pb_fields(val):
                if df == 1 and dw == 0:
                    dom_type = int(dval)
                elif df == 2 and dw == 2:
                    dom_val = bytes(dval).decode("utf-8", "replace").strip()
                elif df == 3 and dw == 2:
                    for af, aw, aval in _iter_pb_fields(dval):
                        if af == 1 and aw == 2:
                            key = bytes(aval).decode("utf-8", "replace").strip().lower()
                            if key:
                                attrs.append(key)
            if dom_val:
                entries.append((dom_type, dom_val, frozenset(attrs)))
    return entries


def extract_geoip_tag_cidrs(dat_path: Path, tags: set[str]) -> dict[str, list[str]]:
    needed = {t.lower() for t in tags}
    found: dict[str, list[str]] = {}
    if not needed:
        return found
    raw = dat_path.read_bytes()
    if len(raw) > GEO_MAX_BYTES:
        raise ValueError("Файл geoip.dat превышает допустимый размер 64 МБ.")
    mv = memoryview(raw)
    for field_num, wire_type, val in _iter_pb_fields(mv):
        if field_num == 1 and wire_type == 2:
            code = _extract_pb_code(val)
            if code in needed:
                found.setdefault(code, []).extend(_parse_geoip_cidrs(val))
    return found


def extract_geosite_tag_rules(dat_path: Path, full_tags: set[str]) -> dict[str, dict[str, list[str]]]:
    by_base: dict[str, list[tuple[str, str | None]]] = {}
    for full in full_tags:
        low = full.lower()
        base, _, attr = low.partition("@")
        by_base.setdefault(base, []).append((low, attr or None))
    if not by_base:
        return {}
    raw = dat_path.read_bytes()
    if len(raw) > GEO_MAX_BYTES:
        raise ValueError("Файл geosite.dat превышает допустимый размер 64 МБ.")
    mv = memoryview(raw)
    base_entries: dict[str, list[tuple[int, str, frozenset[str]]]] = {}
    for field_num, wire_type, val in _iter_pb_fields(mv):
        if field_num == 1 and wire_type == 2:
            code = _extract_pb_code(val)
            if code in by_base:
                base_entries.setdefault(code, []).extend(_parse_geosite_domains(val))

    type_map = {
        0: "domain_keyword",
        1: "domain_regex",
        2: "domain_suffix",
        3: "domain",
    }
    output: dict[str, dict[str, list[str]]] = {}
    for base, items in by_base.items():
        if base not in base_entries:
            continue
        parsed = base_entries[base]
        for full_tag, attr in items:
            rule_obj: dict[str, list[str]] = {}
            for dom_type, dom_val, attrs in parsed:
                if attr:
                    if attr.startswith("!"):
                        if attr[1:] in attrs:
                            continue
                    elif attr not in attrs:
                        continue
                key = type_map.get(dom_type)
                if key:
                    rule_obj.setdefault(key, []).append(dom_val)
            output[full_tag] = rule_obj
    return output


def detect_geo_file_format(path: Path) -> str:
    header = path.read_bytes()[:64]
    if header.startswith(b"SRS"):
        return "srs"
    stripped = header.lstrip()
    if stripped.startswith(b"{"):
        return "json"
    ext = path.suffix.lower()
    if ext == ".srs":
        raise ValueError(f"Файл «{path.name}» не является бинарным sing-box rule-set (.srs).")
    if ext == ".json":
        return "json"
    return "dat"


def inspect_geo_file(path: Path, kind_hint: str = "") -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Файл «{path}» не найден.")
    st = path.stat()
    if st.st_size <= 0:
        raise ValueError(f"Файл «{path.name}» пуст.")
    if st.st_size > GEO_MAX_BYTES:
        raise ValueError(f"Файл «{path.name}» больше лимита 64 МБ.")

    fmt = detect_geo_file_format(path)
    tags: list[str] = []
    if fmt == "json":
        try:
            obj = json.loads(path.read_text("utf-8"))
        except Exception as err:
            raise ValueError(f"Некорректный JSON в rule-set «{path.name}»: {err}") from None
        if not isinstance(obj, dict) or not isinstance(obj.get("rules"), list) or "version" not in obj:
            raise ValueError(f"Файл «{path.name}» не соответствует формату sing-box rule-set JSON.")
    elif fmt == "dat":
        if kind_hint == "ruleset":
            raise ValueError(f"Дополнительный Rule-Set поддерживает только .srs или .json, получено .dat («{path.name}»).")
        raw = path.read_bytes()
        mv = memoryview(raw)
        seen: set[str] = set()
        for field_num, wire_type, val in _iter_pb_fields(mv):
            if field_num == 1 and wire_type == 2:
                code = _extract_pb_code(val)
                if code and code not in seen:
                    seen.add(code)
                    tags.append(code)
        if not tags:
            raise ValueError(f"Файл «{path.name}» не содержит категорий GeoIP/Geosite (.dat).")
        tags.sort()

    return {
        "path": str(path),
        "fileName": path.name,
        "format": fmt,
        "size": st.st_size,
        "updatedAt": _utc_iso(st.st_mtime),
        "tagsCount": len(tags),
        "sampleTags": tags[:GEO_SAMPLE_LIMIT],
    }


def json_ruleset_has_ip(path: Path) -> bool:
    try:
        obj = json.loads(path.read_text("utf-8"))
    except Exception:
        return True
    if not isinstance(obj, dict) or not isinstance(obj.get("rules"), list):
        return True
    ip_keys = {"ip_cidr", "source_ip_cidr", "ip_is_private"}
    for item in obj["rules"]:
        if isinstance(item, dict) and any(k in item for k in ip_keys):
            return True
    return False


def build_config(outbound, settings, prepared_rule_sets=None):
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

    rules = settings.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 2000:
        raise ValueError("Invalid routing rules")
    has_core_rules = any(isinstance(r, dict) and r.get("enabled") is not False and r.get("kind") in CORE_RULE_KINDS for r in rules)

    outbounds = [outbound]
    if has_core_rules:
        outbounds.append({"type": "direct", "tag": "direct"})

    config = {
        "log": {"level": level, "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "bootstrap"}], "final": "bootstrap"},
        "inbounds": [{"type": "socks", "tag": "firefox", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": outbounds,
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

    mapping = {"domain": "domain", "suffix": "domain_suffix", "keyword": "domain_keyword"}
    valid_kinds = set(mapping) | CORE_RULE_KINDS

    if not has_core_rules:
        # Only domain rules (no direct leak inside sing-box because Firefox handles direct itself).
        leading_rejects = []
        tail_rules = []
        saw_proxy_rule = False
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("kind") not in valid_kinds or rule.get("action") not in {"proxy", "direct", "block"}:
                raise ValueError("Invalid routing rule")
            value = rule.get("value")
            if not isinstance(value, str) or not value or len(value) > 253:
                raise ValueError("Invalid routing rule value")
            if any(c.isspace() or ord(c) < 32 for c in value):
                raise ValueError("Invalid characters in routing rule value")
            if rule["kind"] in {"domain", "suffix"} and any(c in "/?#@*\\[]" for c in value):
                raise ValueError("Invalid domain characters in domain rule")
            if rule.get("enabled") is False:
                continue
            if rule["action"] == "direct":
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

    prep = prepared_rule_sets or {}
    rule_sets = prep.get("rule_sets") or []
    if rule_sets:
        config["route"]["rule_set"] = rule_sets
    geoip_tags = prep.get("geoip_tags") or {}
    geosite_tags = prep.get("geosite_tags") or {}
    custom_tags = prep.get("custom_tags") or {}
    ruleset_has_ip = prep.get("ruleset_has_ip") or {}

    ordered_entries: list[tuple[dict, bool]] = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("kind") not in valid_kinds or rule.get("action") not in {"proxy", "direct", "block"}:
            raise ValueError("Invalid routing rule")
        value = rule.get("value")
        if not isinstance(value, str) or not value or len(value) > 253:
            raise ValueError("Invalid routing rule value")
        if any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError("Invalid characters in routing rule value")
        kind = rule["kind"]
        if kind in {"domain", "suffix"} and any(c in "/?#@*\\[]" for c in value):
            raise ValueError("Invalid domain characters in domain rule")
        if rule.get("enabled") is False:
            continue

        is_ip_rule = False
        if kind in mapping:
            entry = {mapping[kind]: [value]}
        elif kind == "cidr":
            entry = {"ip_cidr": [normalize_cidr(value)]}
            is_ip_rule = True
        elif kind == "geoip":
            tag = normalize_geo_tag(value, "geoip")
            rs_tag = geoip_tags.get(tag)
            if not rs_tag:
                raise ValueError(f"Для правила geoip:{tag} не подготовлена база GeoIP.")
            entry = {"rule_set": [rs_tag]}
            is_ip_rule = True
        elif kind == "geosite":
            tag = normalize_geo_tag(value, "geosite")
            rs_tag = geosite_tags.get(tag)
            if not rs_tag:
                raise ValueError(f"Для правила geosite:{tag} не подготовлена база Geosite.")
            entry = {"rule_set": [rs_tag]}
        else:
            tag = normalize_geo_tag(value, "ruleset")
            rs_tag = custom_tags.get(tag)
            if not rs_tag:
                raise ValueError(f"Rule-Set «{tag}» не подготовлен или отсутствует.")
            entry = {"rule_set": [rs_tag]}
            is_ip_rule = bool(ruleset_has_ip.get(tag, True))

        if rule["action"] == "block":
            entry["action"] = "reject"
        elif rule["action"] == "direct":
            entry.update(action="route", outbound="direct")
        else:
            entry.update(action="route", outbound="proxy")
        ordered_entries.append((entry, is_ip_rule))

    has_ip_rule = any(is_ip for _, is_ip in ordered_entries)
    has_non_reject = any(entry.get("action") != "reject" for entry, _ in ordered_entries)
    needs_outbound = mode == "global" or default_action != "block" or has_non_reject

    if dns_mode == "doh" and (needs_outbound or has_ip_rule):
        insert_at = len(ordered_entries)
        for idx, (entry, is_ip) in enumerate(ordered_entries):
            if entry.get("action") != "reject" or is_ip:
                insert_at = idx
                break
        route_rules = [e for e, _ in ordered_entries[:insert_at]]
        route_rules.append({"action": "resolve", "server": "secure", "strategy": "prefer_ipv4"})
        route_rules.extend(e for e, _ in ordered_entries[insert_at:])
    elif dns_mode == "remote" and has_ip_rule:
        first_ip_idx = next(idx for idx, (_, is_ip) in enumerate(ordered_entries) if is_ip)
        route_rules = [e for e, _ in ordered_entries[:first_ip_idx]]
        route_rules.append({"action": "resolve", "server": "bootstrap", "strategy": "prefer_ipv4"})
        route_rules.extend(e for e, _ in ordered_entries[first_ip_idx:])
    else:
        route_rules = [e for e, _ in ordered_entries]

    if mode == "rules" and default_action == "block":
        route_rules.append({"action": "reject"})
        config["route"]["final"] = "proxy"
    elif mode == "global" or default_action == "proxy":
        config["route"]["final"] = "proxy"
    else:
        config["route"]["final"] = "direct"

    config["route"]["rules"] = route_rules
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
        self.geo_dir = self.data / "geo"
        self.geo_compiled = self.geo_dir / "compiled"
        self.geo_dir.mkdir(parents=True, exist_ok=True)
        self.geo_compiled.mkdir(parents=True, exist_ok=True)
        _chmod_private(self.geo_dir, 0o700)
        _chmod_private(self.geo_compiled, 0o700)
        self.uploads: dict[str, dict] = {}
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
        for stale in self.geo_dir.glob("*.tmp"):
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

    def _resolve_local_geo_path(self, raw_path: str, kind_hint: str = "") -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError("Путь к локальному файлу Geo-базы не указан.")
        clean = raw_path.strip().strip('"').strip("'")
        if any(ord(c) < 32 or c in '\r\n<>|?*' for c in clean):
            raise ValueError("Некорректные символы в пути к файлу Geo-базы.")
        if clean.startswith("\\\\") or clean.startswith("//"):
            raise ValueError("Сетевые UNC-пути не допускаются. Укажите локальный файл на диске.")
        path = Path(clean).expanduser()
        if path.suffix.lower() not in {".dat", ".srs", ".json"}:
            raise ValueError("Файл Geo-базы должен иметь расширение .dat, .srs или .json.")
        if kind_hint == "ruleset" and path.suffix.lower() not in {".srs", ".json"}:
            raise ValueError("Для дополнительного Rule-Set поддерживаются только .srs и .json.")
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise FileNotFoundError(f"Файл Geo-базы не найден: {path}") from None
        if not resolved.is_file():
            raise FileNotFoundError(f"Указанный путь не является файлом: {resolved}")
        if resolved.stat().st_size > GEO_MAX_BYTES:
            raise ValueError(f"Файл «{resolved.name}» превышает лимит 64 МБ.")
        return resolved

    def _compile_or_cache_dat_tag(self, kind: str, tag: str, src_path: Path, rule_obj: dict, compile_srs: bool) -> dict:
        if not rule_obj:
            raise ValueError(f"Тег {kind}:«{tag}» пуст в базе «{src_path.name}».")
        st = src_path.stat()
        mode_flag = "srs" if compile_srs else "json"
        digest = hashlib.sha256(
            f"{kind}|{tag}|{src_path}|{st.st_mtime_ns}|{st.st_size}|{mode_flag}".encode("utf-8")
        ).hexdigest()[:20]
        safe_slug = re.sub(r"[^a-z0-9_-]+", "_", tag).strip("_")[:36] or "tag"
        tag_hash = hashlib.sha1(tag.encode("utf-8")).hexdigest()[:6]
        rs_tag = f"{kind}-{safe_slug}-{tag_hash}"
        ext = ".srs" if compile_srs else ".json"
        out_path = self.geo_compiled / f"{kind}-{safe_slug}-{digest}{ext}"
        if not out_path.is_file():
            payload = {"version": 2, "rules": [rule_obj]}
            if compile_srs:
                self.version()
                fd_in, tmp_in_name = tempfile.mkstemp(prefix="geo-src-", suffix=".json", dir=self.geo_compiled)
                tmp_in = Path(tmp_in_name)
                tmp_out = self.geo_compiled / f"tmp-{uuid.uuid4().hex}-{kind}.srs"
                try:
                    _chmod_private(tmp_in, 0o600)
                    with os.fdopen(fd_in, "w", encoding="utf-8") as stream:
                        json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"))
                    res = subprocess.run(
                        [str(self.core), "rule-set", "compile", "--output", str(tmp_out), str(tmp_in)],
                        capture_output=True,
                        timeout=30,
                        creationflags=CREATE_FLAGS,
                    )
                    if res.returncode or not tmp_out.is_file():
                        detail = (res.stderr + res.stdout).decode("utf-8", "replace")[-1200:]
                        raise ValueError(f"Не удалось скомпилировать {kind}:{tag} в .srs:\n{detail}")
                    os.replace(tmp_out, out_path)
                    _chmod_private(out_path, 0o600)
                finally:
                    _secure_unlink(tmp_in)
                    _secure_unlink(tmp_out)
            else:
                tmp_out = self.geo_compiled / f"{kind}-{safe_slug}-{digest}.{uuid.uuid4().hex}.json.tmp"
                try:
                    tmp_out.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
                    os.replace(tmp_out, out_path)
                    _chmod_private(out_path, 0o600)
                finally:
                    _secure_unlink(tmp_out)
            self._prune_compiled_cache()
        return {"type": "local", "tag": rs_tag, "format": "binary" if compile_srs else "source", "path": str(out_path)}

    def _prune_compiled_cache(self, limit: int = 128) -> None:
        try:
            files = sorted(
                (p for p in self.geo_compiled.iterdir() if p.is_file()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in files[limit:]:
                _secure_unlink(old)
        except OSError:
            pass

    def prepare_geo_rule_sets(self, settings: dict, compile_srs: bool | None = None) -> dict:
        if not isinstance(settings, dict):
            return {}
        rules = settings.get("rules") or []
        needed_geoip: set[str] = set()
        needed_geosite: set[str] = set()
        needed_ruleset: set[str] = set()
        for r in rules:
            if not isinstance(r, dict) or r.get("enabled") is False:
                continue
            k = r.get("kind")
            if k == "geoip":
                needed_geoip.add(normalize_geo_tag(r.get("value", ""), "geoip"))
            elif k == "geosite":
                needed_geosite.add(normalize_geo_tag(r.get("value", ""), "geosite"))
            elif k == "ruleset":
                needed_ruleset.add(normalize_geo_tag(r.get("value", ""), "ruleset"))

        if not (needed_geoip or needed_geosite or needed_ruleset):
            return {"rule_sets": [], "geoip_tags": {}, "geosite_tags": {}, "custom_tags": {}, "ruleset_has_ip": {}}

        if compile_srs is None:
            compile_srs = self.core.is_file()

        geo = settings.get("geo") if isinstance(settings.get("geo"), dict) else {}
        rule_sets: list[dict] = []
        geoip_tags: dict[str, str] = {}
        geosite_tags: dict[str, str] = {}
        custom_tags: dict[str, str] = {}
        ruleset_has_ip: dict[str, bool] = {}

        def resolve_geo_db_path(kind_key: str, label: str) -> Path:
            src = geo.get(kind_key) if isinstance(geo.get(kind_key), dict) else {}
            st_type = src.get("sourceType", "none")
            if st_type == "none":
                raise ValueError(f"Для правил {kind_key}:... не настроен источник {label} в разделе «Базы GeoIP и Geosite».")
            raw_path = src.get("path") or ""
            if st_type == "remote":
                if not raw_path:
                    raise ValueError(f"База {label} ещё не загружена. Нажмите «Обновить {label}» в настройках маршрутизации.")
                try:
                    return self._resolve_local_geo_path(raw_path, kind_hint=kind_key)
                except FileNotFoundError:
                    raise FileNotFoundError(f"Кэш базы {label} не найден на диске. Нажмите «Обновить {label}».") from None
            return self._resolve_local_geo_path(raw_path, kind_hint=kind_key)

        if needed_geoip:
            geoip_path = resolve_geo_db_path("geoip", "GeoIP")
            fmt = detect_geo_file_format(geoip_path)
            if fmt in {"srs", "json"}:
                rs_def = {"type": "local", "tag": "geoip-custom", "format": "binary" if fmt == "srs" else "source", "path": str(geoip_path)}
                rule_sets.append(rs_def)
                for tag in sorted(needed_geoip):
                    geoip_tags[tag] = "geoip-custom"
            else:
                extracted = extract_geoip_tag_cidrs(geoip_path, needed_geoip)
                for tag in sorted(needed_geoip):
                    cidrs = extracted.get(tag)
                    if not cidrs:
                        raise ValueError(f"Категория GeoIP «{tag}» не найдена в файле «{geoip_path.name}».")
                    rs_def = self._compile_or_cache_dat_tag("geoip", tag, geoip_path, {"ip_cidr": cidrs}, compile_srs)
                    rule_sets.append(rs_def)
                    geoip_tags[tag] = rs_def["tag"]

        if needed_geosite:
            geosite_path = resolve_geo_db_path("geosite", "Geosite")
            fmt = detect_geo_file_format(geosite_path)
            if fmt in {"srs", "json"}:
                rs_def = {"type": "local", "tag": "geosite-custom", "format": "binary" if fmt == "srs" else "source", "path": str(geosite_path)}
                rule_sets.append(rs_def)
                for tag in sorted(needed_geosite):
                    geosite_tags[tag] = "geosite-custom"
            else:
                extracted = extract_geosite_tag_rules(geosite_path, needed_geosite)
                for tag in sorted(needed_geosite):
                    rule_obj = extracted.get(tag)
                    if rule_obj is None:
                        base_name = tag.split("@", 1)[0]
                        raise ValueError(f"Категория Geosite «{base_name}» не найдена в файле «{geosite_path.name}».")
                    if not rule_obj:
                        raise ValueError(f"В категории Geosite «{tag}» нет записей для компиляции.")
                    rs_def = self._compile_or_cache_dat_tag("geosite", tag, geosite_path, rule_obj, compile_srs)
                    rule_sets.append(rs_def)
                    geosite_tags[tag] = rs_def["tag"]

        if needed_ruleset:
            entries = geo.get("ruleSets") if isinstance(geo.get("ruleSets"), list) else []
            by_tag = {}
            for item in entries:
                if isinstance(item, dict) and isinstance(item.get("tag"), str):
                    try:
                        by_tag[normalize_geo_tag(item["tag"], "ruleset")] = item
                    except ValueError:
                        pass
            for tag in sorted(needed_ruleset):
                entry = by_tag.get(tag)
                if not entry or entry.get("enabled") is False:
                    raise ValueError(f"Rule-Set «{tag}» не найден или отключён в разделе «Дополнительные Rule-Sets».")
                raw_path = entry.get("path") or ""
                if entry.get("sourceType") == "remote":
                    if not raw_path:
                        raise ValueError(f"Rule-Set «{tag}» ещё не скачан. Нажмите «Обновить» напротив него в настройках маршрутизации.")
                    try:
                        rs_path = self._resolve_local_geo_path(raw_path, kind_hint="ruleset")
                    except FileNotFoundError:
                        raise FileNotFoundError(f"Кэш Rule-Set «{tag}» не найден на диске. Нажмите «Обновить».") from None
                else:
                    rs_path = self._resolve_local_geo_path(raw_path, kind_hint="ruleset")
                fmt = detect_geo_file_format(rs_path)
                if fmt == "dat":
                    raise ValueError(f"Rule-Set «{tag}» должен быть .srs или .json файлом.")
                rs_tag = f"rs-{tag}"
                rule_sets.append({
                    "type": "local",
                    "tag": rs_tag,
                    "format": "binary" if fmt == "srs" else "source",
                    "path": str(rs_path),
                })
                custom_tags[tag] = rs_tag
                ruleset_has_ip[tag] = True if fmt == "srs" else json_ruleset_has_ip(rs_path)

        return {
            "rule_sets": rule_sets,
            "geoip_tags": geoip_tags,
            "geosite_tags": geosite_tags,
            "custom_tags": custom_tags,
            "ruleset_has_ip": ruleset_has_ip,
        }

    def build_runtime_config(self, outbound, settings, compile_srs: bool | None = None):
        prepared = self.prepare_geo_rule_sets(settings, compile_srs=compile_srs)
        return build_config(outbound, settings, prepared_rule_sets=prepared)

    def start(self, outbound, settings):
        try:
            config = self.build_runtime_config(outbound, settings, compile_srs=True)
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

    def _active_socks_port(self, geo: dict) -> int | None:
        if geo.get("updateViaProxy") is True and self.process is not None and self.process.poll() is None and self.port:
            return self.port
        return None

    def _cleanup_old_target_files(self, prefix: str, keep_path: Path | None = None) -> None:
        for ext in (".dat", ".srs", ".json"):
            candidate = self.geo_dir / f"{prefix}{ext}"
            if candidate != keep_path and candidate.is_file():
                _secure_unlink(candidate)

    def _download_single_geo_target(
        self,
        url: str,
        dest_prefix: str,
        kind_hint: str,
        socks_port: int | None,
    ) -> dict:
        _, _, _, _, _ = _validate_remote_url(url, {"https"}, f"URL базы {kind_hint}")
        fd, tmp_name = tempfile.mkstemp(prefix=f"dl-{dest_prefix}-", suffix=".tmp", dir=self.geo_dir)
        os.close(fd)
        tmp_path = Path(tmp_name)
        _chmod_private(tmp_path, 0o600)
        try:
            https_download_to_file(url, tmp_path, socks_port=socks_port, max_bytes=GEO_MAX_BYTES, timeout=45.0)
            info = inspect_geo_file(tmp_path, kind_hint=kind_hint)
            ext = "." + info["format"]
            final_path = self.geo_dir / f"{dest_prefix}{ext}"
            os.replace(tmp_path, final_path)
            _chmod_private(final_path, 0o600)
            self._cleanup_old_target_files(dest_prefix, keep_path=final_path)
            info["path"] = str(final_path)
            info["fileName"] = final_path.name
            info["updatedAt"] = _utc_iso()
            return info
        finally:
            _secure_unlink(tmp_path)

    def geo_status(self, geo: dict | None = None) -> dict:
        g = geo if isinstance(geo, dict) else {}

        def check_entry(src, kind_hint):
            if not isinstance(src, dict):
                return {"exists": False, "size": 0, "format": "", "updatedAt": ""}
            raw_path = src.get("path") or ""
            if not raw_path:
                return {"exists": False, "size": 0, "format": src.get("format", ""), "updatedAt": src.get("updatedAt", "")}
            try:
                p = self._resolve_local_geo_path(raw_path, kind_hint=kind_hint)
                st = p.stat()
                return {
                    "exists": True,
                    "path": str(p),
                    "fileName": p.name,
                    "size": st.st_size,
                    "updatedAt": src.get("updatedAt") or _utc_iso(st.st_mtime),
                    "format": src.get("format") or detect_geo_file_format(p),
                }
            except Exception as err:
                return {"exists": False, "error": str(err), "path": raw_path}

        rs_status = {}
        for item in (g.get("ruleSets") if isinstance(g.get("ruleSets"), list) else []):
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                rs_status[item["id"]] = check_entry(item, "ruleset")

        return {
            "geoDir": str(self.geo_dir),
            "geoip": check_entry(g.get("geoip"), "geoip"),
            "geosite": check_entry(g.get("geosite"), "geosite"),
            "ruleSets": rs_status,
        }

    def geo_inspect(self, raw_path: str, target: str = "") -> dict:
        resolved = self._resolve_local_geo_path(raw_path, kind_hint=target)
        return inspect_geo_file(resolved, kind_hint=target)

    def geo_update(self, message: dict) -> dict:
        geo = message.get("geo") if isinstance(message.get("geo"), dict) else {}
        targets = message.get("targets")
        if not isinstance(targets, list) or not targets:
            single = message.get("target")
            targets = [single] if isinstance(single, str) and single else ["geoip", "geosite", "ruleset"]
        rule_set_ids = set(message.get("ruleSetIds") or [])
        socks_port = self._active_socks_port(geo)

        jobs: list[tuple[str, str, str, str, str | None]] = []
        for kind_key, label in (("geoip", "GeoIP"), ("geosite", "Geosite")):
            if kind_key in targets:
                src = geo.get(kind_key) if isinstance(geo.get(kind_key), dict) else {}
                if src.get("sourceType") == "remote" and src.get("url"):
                    jobs.append((kind_key, label, src["url"], f"remote-{kind_key}", None))
                elif len(targets) == 1:
                    raise ValueError(f"Источник {label} не настроен как удалённый URL.")

        if "ruleset" in targets:
            entries = geo.get("ruleSets") if isinstance(geo.get("ruleSets"), list) else []
            for item in entries:
                if not isinstance(item, dict):
                    continue
                rs_id = str(item.get("id") or "")
                if rule_set_ids and rs_id not in rule_set_ids:
                    continue
                if item.get("sourceType") != "remote" or not item.get("url"):
                    if rule_set_ids and rs_id in rule_set_ids:
                        raise ValueError(f"Rule-Set «{item.get('tag', rs_id)}» не настроен как удалённый URL.")
                    continue
                if not rule_set_ids and item.get("enabled") is False:
                    continue
                safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", rs_id)[:40] or "rs"
                jobs.append(("ruleset", f"Rule-Set {item.get('tag', safe_id)}", item["url"], f"remote-rs-{safe_id}", rs_id))

        if not jobs:
            raise ValueError("Нет настроенных удалённых URL (GeoIP / Geosite / Rule-Set) для скачивания.")

        updated_geoip = None
        updated_geosite = None
        updated_rulesets: dict[str, dict] = {}
        errors: dict[str, str] = {}
        first_error: Exception | None = None

        for kind_key, label, url, prefix, rs_id in jobs:
            try:
                info = self._download_single_geo_target(url, prefix, kind_key, socks_port)
                if kind_key == "geoip":
                    updated_geoip = info
                elif kind_key == "geosite":
                    updated_geosite = info
                elif rs_id is not None:
                    updated_rulesets[rs_id] = info
            except Exception as err:
                if first_error is None:
                    first_error = err
                key = rs_id if rs_id is not None else kind_key
                errors[key] = f"{label}: {err}"

        updated_count = int(updated_geoip is not None) + int(updated_geosite is not None) + len(updated_rulesets)
        if updated_count == 0:
            if len(jobs) == 1 and first_error is not None:
                raise first_error
            raise RuntimeError("\n".join(errors.values()))

        return {
            "geoip": updated_geoip,
            "geosite": updated_geosite,
            "ruleSets": updated_rulesets,
            "updatedCount": updated_count,
            "errors": errors,
            "viaProxy": socks_port is not None,
        }

    def _evict_stale_uploads(self) -> None:
        now = time.monotonic()
        stale_ids = [uid for uid, sess in self.uploads.items() if now - sess["created"] > 600]
        for uid in stale_ids:
            sess = self.uploads.pop(uid)
            try:
                sess["stream"].close()
            except OSError:
                pass
            _secure_unlink(sess["tmp_path"])

    def geo_upload_begin(self, message: dict) -> dict:
        self._evict_stale_uploads()
        if len(self.uploads) >= 6:
            raise RuntimeError("Слишком много одновременных загрузок файлов.")
        target = message.get("target")
        if target not in {"geoip", "geosite", "ruleset"}:
            raise ValueError("Неизвестная цель загрузки Geo-файла.")
        raw_name = Path(str(message.get("fileName") or "geo.dat")).name
        ext = Path(raw_name).suffix.lower()
        if ext not in {".dat", ".srs", ".json"}:
            raise ValueError("Разрешены только файлы .dat, .srs или .json.")
        if target == "ruleset" and ext not in {".srs", ".json"}:
            raise ValueError("Rule-Set поддерживает только .srs или .json файлы.")
        total_size = message.get("totalSize", 0)
        if isinstance(total_size, bool) or not isinstance(total_size, int) or not 0 < total_size <= GEO_MAX_BYTES:
            raise ValueError("Размер загружаемого файла должен быть от 1 байта до 64 МБ.")
        rs_id = str(message.get("ruleSetId") or "")
        safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", rs_id)[:40] or "rs"
        dest_prefix = f"local-{target}" if target != "ruleset" else f"local-rs-{safe_id}"

        uid = uuid.uuid4().hex
        fd, tmp_name = tempfile.mkstemp(prefix=f"up-{dest_prefix}-", suffix=".tmp", dir=self.geo_dir)
        tmp_path = Path(tmp_name)
        _chmod_private(tmp_path, 0o600)
        stream = os.fdopen(fd, "wb")
        self.uploads[uid] = {
            "target": target,
            "dest_prefix": dest_prefix,
            "orig_name": raw_name[:120],
            "total_size": total_size,
            "received": 0,
            "tmp_path": tmp_path,
            "stream": stream,
            "created": time.monotonic(),
        }
        return {"uploadId": uid}

    def geo_upload_chunk(self, message: dict) -> dict:
        uid = message.get("uploadId")
        sess = self.uploads.get(uid) if isinstance(uid, str) else None
        if not sess:
            raise ValueError("Сессия загрузки не найдена или истекла.")
        data_b64 = message.get("data")
        if not isinstance(data_b64, str) or not data_b64:
            raise ValueError("Пустой фрагмент файла.")
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise ValueError("Некорректные base64-данные при загрузке файла.") from None
        if len(raw) > 512 * 1024:
            raise ValueError("Фрагмент файла слишком большой.")
        if sess["received"] + len(raw) > sess["total_size"]:
            self.geo_upload_abort(uid)
            raise ValueError("Передано больше байт, чем заявленный размер файла.")
        sess["stream"].write(raw)
        sess["received"] += len(raw)
        return {"received": sess["received"]}

    def geo_upload_abort(self, uid: str) -> None:
        sess = self.uploads.pop(uid, None)
        if sess:
            try:
                sess["stream"].close()
            except OSError:
                pass
            _secure_unlink(sess["tmp_path"])

    def geo_upload_finish(self, message: dict) -> dict:
        uid = message.get("uploadId")
        sess = self.uploads.pop(uid, None) if isinstance(uid, str) else None
        if not sess:
            raise ValueError("Сессия загрузки не найдена.")
        tmp_path = sess["tmp_path"]
        try:
            sess["stream"].flush()
            sess["stream"].close()
            if sess["received"] != sess["total_size"]:
                raise ValueError("Файл загружен не полностью.")
            info = inspect_geo_file(tmp_path, kind_hint=sess["target"])
            ext = "." + info["format"]
            final_path = self.geo_dir / f"{sess['dest_prefix']}{ext}"
            os.replace(tmp_path, final_path)
            _chmod_private(final_path, 0o600)
            self._cleanup_old_target_files(sess["dest_prefix"], keep_path=final_path)
            info["path"] = str(final_path)
            info["fileName"] = sess["orig_name"] or final_path.name
            info["updatedAt"] = _utc_iso()
            return info
        finally:
            _secure_unlink(tmp_path)

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
            config = self.build_runtime_config(message.get("outbound"), message.get("settings", {}), compile_srs=True)
            self.validate_config(config)
            return {"valid": True, "coreVersion": self.version()}
        if command == "probe":
            return self.probe(
                message.get("outbound"),
                message.get("settings", {}),
                message.get("probeUrl"),
            )
        if command == "geo_status":
            return self.geo_status(message.get("geo", {}))
        if command == "geo_inspect":
            return self.geo_inspect(message.get("path", ""), message.get("target", ""))
        if command == "geo_update":
            return self.geo_update(message)
        if command == "geo_upload_begin":
            return self.geo_upload_begin(message)
        if command == "geo_upload_chunk":
            return self.geo_upload_chunk(message)
        if command == "geo_upload_finish":
            return self.geo_upload_finish(message)
        raise ValueError("Unknown native command")


def reserve_ephemeral_port() -> int:
    for _ in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port_num = s.getsockname()[1]
            if 1024 <= port_num <= 65535:
                return port_num
    raise RuntimeError("Не удалось выделить локальный порт для проверки.")


def _validate_remote_url(raw_url: str, allowed_schemes: set[str], label: str) -> tuple[str, str, int, str, bool]:
    if not isinstance(raw_url, str) or not raw_url.strip() or len(raw_url) > 2048:
        raise ValueError(f"Некорректный {label}.")
    parsed = urllib.parse.urlsplit(raw_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        schemes_str = " или ".join(f"{s}://" for s in sorted(allowed_schemes))
        raise ValueError(f"{label} должен использовать {schemes_str}.")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} не должен содержать логин или пароль.")
    host = parsed.hostname
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError(f"В {label} отсутствует имя хоста.")
    lower = host.lower().rstrip(".")
    if lower == "localhost" or lower.endswith(".localhost"):
        raise ValueError(f"{label} не должен указывать на localhost.")
    ip = None
    try:
        ip = ipaddress.ip_address(lower)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            raise ValueError(f"{label} не должен указывать на локальный или приватный IP.")
        ascii_host = str(ip)
    else:
        try:
            ascii_host = lower.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"Некорректное доменное имя в {label}.") from None
    port_num = parsed.port or (443 if scheme == "https" else 80)
    if not 1 <= port_num <= 65535:
        raise ValueError(f"Некорректный порт в {label}.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, ascii_host, port_num, path, scheme == "https"


def parse_probe_url(raw_url: str) -> tuple[str, str, int, str, bool]:
    return _validate_remote_url(raw_url, {"http", "https"}, "URL проверки")


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


def socks5_connect(socks_port: int, target_host: str, target_port: int, remaining_fn) -> socket.socket:
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
    raw_sock = socket.create_connection(("127.0.0.1", socks_port), timeout=remaining_fn())
    try:
        raw_sock.settimeout(remaining_fn())
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
                raise ValueError("Слишком длинное имя хоста.")
            addr_part = b"\x03" + bytes([len(host_bytes)]) + host_bytes

        raw_sock.settimeout(remaining_fn())
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
        return raw_sock
    except Exception:
        raw_sock.close()
        raise


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int = 443, socks_port: int | None = None, timeout: float = 45.0):
        ctx = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=ctx)
        self._tls_context = ctx
        self.socks_port = socks_port

    def connect(self):
        if self.socks_port is None:
            super().connect()
            return
        raw = socks5_connect(self.socks_port, self.host, self.port, lambda: self.timeout or 45.0)
        try:
            self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def https_download_to_file(
    url: str,
    dest_path: Path,
    socks_port: int | None = None,
    max_bytes: int = GEO_MAX_BYTES,
    timeout: float = 45.0,
) -> int:
    current = url
    deadline = time.monotonic() + timeout
    for _hop in range(6):
        _, host, port_num, path_and_query, _ = _validate_remote_url(current, {"https"}, "URL скачивания Geo-базы")
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("Превышено время ожидания скачивания Geo-базы.")
        conn = _Socks5HTTPSConnection(host, port=port_num, socks_port=socks_port, timeout=rem)
        try:
            host_header = f"[{host}]" if ":" in host else host
            if port_num != 443:
                host_header = f"{host_header}:{port_num}"
            conn.request(
                "GET",
                path_and_query,
                headers={
                    "Host": host_header,
                    "User-Agent": "FoxTunnel/0.1",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise RuntimeError(f"Сервер вернул редирект HTTP {resp.status} без заголовка Location.")
                current = urllib.parse.urljoin(current, loc)
                continue
            if resp.status != 200:
                raise RuntimeError(f"Сервер ответил HTTP {resp.status}.")
            cl_hdr = resp.getheader("Content-Length")
            if cl_hdr and cl_hdr.isdigit() and int(cl_hdr) > max_bytes:
                raise ValueError("Размер удалённого файла превышает лимит 64 МБ.")
            total = 0
            with dest_path.open("wb") as out:
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Превышено время ожидания загрузки файла.")
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Удалённый файл превышает лимит 64 МБ.")
                    out.write(chunk)
            if total == 0:
                raise ValueError("Удалённый сервер вернул пустой файл.")
            return total
        finally:
            conn.close()
    raise RuntimeError("Слишком много HTTP-редиректов при скачивании Geo-базы.")


def socks5_http_probe(
    socks_port: int,
    target_host: str,
    target_port: int,
    path_and_query: str,
    use_tls: bool,
    timeout: float = 8.0,
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout

    def remaining_timeout() -> float:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("Превышено время ожидания ответа от сервера.")
        return rem

    t0 = time.monotonic()
    with socks5_connect(socks_port, target_host, target_port, remaining_timeout) as raw_sock:
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
