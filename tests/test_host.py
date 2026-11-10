from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "native"))

import host  # noqa: E402


def sample_vless_tls():
    return {
        "type": "vless",
        "server": "vless.example.invalid",
        "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": True, "server_name": "vless.example.invalid", "alpn": ["h2", "http/1.1"]},
    }


def sample_vless_reality():
    return {
        "type": "vless",
        "server": "192.0.2.11",
        "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": "www.example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {
                "enabled": True,
                "public_key": "dGVzdC1yZWFsaXR5LXB1YmxpYy1rZXktMzItYnl0ZXM",
                "short_id": "0123abcd",
            },
        },
    }


def sample_vmess_ws():
    return {
        "type": "vmess",
        "server": "vmess.example.invalid",
        "server_port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "security": "auto",
        "alter_id": 0,
        "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "vmess.example.invalid"}},
        "tls": {"enabled": True, "server_name": "vmess.example.invalid"},
    }


def sample_hysteria2():
    return {
        "type": "hysteria2",
        "server": "hy2.example.invalid",
        "server_port": 443,
        "password": "test-placeholder-password",
        "up_mbps": 50,
        "down_mbps": 100,
        "obfs": {"type": "salamander", "password": "test-obfs-placeholder"},
        "tls": {"enabled": True, "server_name": "hy2.example.invalid", "alpn": ["h3"]},
    }


def sample_trojan():
    return {
        "type": "trojan",
        "server": "trojan.example.invalid",
        "server_port": 443,
        "password": "test-placeholder-password",
        "tls": {"enabled": True, "server_name": "trojan.example.invalid", "alpn": ["h2", "http/1.1"]},
    }


def sample_shadowsocks():
    return {
        "type": "shadowsocks",
        "server": "192.0.2.12",
        "server_port": 8388,
        "method": "aes-128-gcm",
        "password": "test-placeholder-password",
    }


class HostConfigTests(unittest.TestCase):
    def test_build_config_remote_dns(self):
        cfg = host.build_config(sample_vless_tls(), {"port": 2080, "dnsMode": "remote", "mode": "rules"})
        self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(cfg["inbounds"][0]["listen_port"], 2080)
        self.assertEqual([o["tag"] for o in cfg["outbounds"]], ["proxy"])
        self.assertEqual(cfg["outbounds"][0]["domain_resolver"], "bootstrap")
        self.assertEqual(cfg["dns"]["servers"], [{"type": "local", "tag": "bootstrap"}])
        self.assertEqual(cfg["route"]["final"], "proxy")
        self.assertEqual(cfg["route"]["default_domain_resolver"], "bootstrap")
        self.assertEqual(cfg["route"]["rules"], [])

    def test_build_config_doh_and_rule_ordering(self):
        settings = {
            "port": 2081,
            "dnsMode": "doh",
            "dnsServer": "1.1.1.1",
            "dnsServerName": "cloudflare-dns.com",
            "dnsPath": "/dns-query",
            "mode": "rules",
            "defaultAction": "direct",
            "rules": [
                {"kind": "suffix", "value": "ads.invalid", "action": "block", "enabled": True},
                {"kind": "domain", "value": "local.invalid", "action": "direct", "enabled": True},
                {"kind": "domain", "value": "ok.ads.invalid", "action": "proxy", "enabled": True},
                {"kind": "keyword", "value": "tracker", "action": "block", "enabled": True},
                {"kind": "domain", "value": "disabled.invalid", "action": "block", "enabled": False},
            ],
        }
        cfg = host.build_config(sample_vless_reality(), settings)
        self.assertEqual(len(cfg["dns"]["servers"]), 2)
        secure = cfg["dns"]["servers"][1]
        self.assertEqual(secure["type"], "https")
        self.assertEqual(secure["detour"], "proxy")
        self.assertEqual(secure["tls"], {"enabled": True, "server_name": "cloudflare-dns.com"})
        self.assertEqual(
            cfg["route"]["rules"],
            [
                {"domain_suffix": ["ads.invalid"], "action": "reject"},
                {"action": "resolve", "server": "secure", "strategy": "prefer_ipv4"},
                {"domain": ["ok.ads.invalid"], "action": "route", "outbound": "proxy"},
                {"domain_keyword": ["tracker"], "action": "reject"},
            ],
        )

    def test_build_config_default_block_vs_global(self):
        rules_block = host.build_config(
            sample_trojan(),
            {"mode": "rules", "defaultAction": "block", "dnsMode": "doh", "rules": []},
        )
        self.assertEqual(rules_block["route"]["rules"], [{"action": "reject"}])

        global_cfg = host.build_config(
            sample_trojan(),
            {"mode": "global", "defaultAction": "block", "dnsMode": "remote", "rules": []},
        )
        self.assertEqual(global_cfg["route"]["rules"], [])
        self.assertEqual(global_cfg["route"]["final"], "proxy")

    def test_rejects_dangerous_fields(self):
        dangerous = [
            {"certificate_path": "/etc/passwd"},
            {"tls": {"enabled": True, "certificate_path": "secret.pem"}},
            {"tls": {"enabled": True, "ech": {"key_path": "ech.key"}}},
            {"detour": "direct"},
            {"outbounds": []},
            {"inbounds": []},
            {"endpoints": []},
            {"providers": []},
            {"route": {}},
            {"dns": {}},
        ]
        for extra in dangerous:
            bad = {**sample_trojan(), **extra}
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    host.build_config(bad, {})

    def test_port_limits(self):
        for bad_port in (0, -1, 65536, True, "443"):
            bad = {**sample_trojan(), "server_port": bad_port}
            with self.assertRaises(ValueError):
                host.build_config(bad, {})

        for bad_local in (0, 80, 1023, 65536, False, "2080"):
            with self.assertRaises(ValueError):
                host.build_config(sample_trojan(), {"port": bad_local})

        self.assertEqual(host.build_config(sample_trojan(), {"port": 1024})["inbounds"][0]["listen_port"], 1024)
        self.assertEqual(host.build_config(sample_trojan(), {"port": 65535})["inbounds"][0]["listen_port"], 65535)

    def test_domain_rules_validation(self):
        bad_rules = [
            {"kind": "regex", "value": ".*", "action": "proxy"},
            {"kind": "domain", "value": "a.com", "action": "allow"},
            {"kind": "domain", "value": "", "action": "proxy"},
            {"kind": "domain", "value": "a" * 254, "action": "proxy"},
            {"kind": "domain", "value": "bad domain.com", "action": "proxy"},
            {"kind": "suffix", "value": "*.example.com", "action": "proxy"},
            {"kind": "domain", "value": "example.com/path", "action": "proxy"},
            {"kind": "keyword", "value": "bad\nword", "action": "block"},
        ]
        for rule in bad_rules:
            with self.subTest(rule=rule):
                with self.assertRaises(ValueError):
                    host.build_config(sample_trojan(), {"rules": [rule]})

        with self.assertRaises(ValueError):
            too_many = [{"kind": "domain", "value": "a.invalid", "action": "proxy"}] * 2001
            host.build_config(sample_trojan(), {"rules": too_many})


class NativeMessagingTests(unittest.TestCase):
    def test_framing_roundtrip_and_limits(self):
        buf = io.BytesIO()
        payload = {"id": 42, "command": "start", "note": "Кириллица и пробелы"}
        host.write_message(buf, payload)
        buf.seek(0)
        self.assertEqual(host.read_message(buf), payload)
        self.assertIsNone(host.read_message(buf))

    def test_framing_rejects_oversized_and_truncated(self):
        too_big = struct.pack("<I", host.MAX_MESSAGE + 1) + b"{}"
        with self.assertRaises(ValueError):
            host.read_message(io.BytesIO(too_big))

        zero_len = struct.pack("<I", 0)
        with self.assertRaises(ValueError):
            host.read_message(io.BytesIO(zero_len))

        truncated = struct.pack("<I", 10) + b"{\"a\":1"
        with self.assertRaises(EOFError):
            host.read_message(io.BytesIO(truncated))

        not_obj = struct.pack("<I", 2) + b"[]"
        with self.assertRaises(ValueError):
            host.read_message(io.BytesIO(not_obj))

        with self.assertRaises(ValueError):
            host.write_message(io.BytesIO(), {"big": "x" * (host.MAX_MESSAGE + 10)})

    def test_host_subprocess_stdout_only_framed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "LOCALAPPDATA": tmp}
            req_buf = io.BytesIO()
            host.write_message(req_buf, {"id": 7, "command": "logs"})
            proc = subprocess.run(
                [sys.executable, "-u", str(ROOT / "native" / "host.py")],
                input=req_buf.getvalue(),
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
            out = io.BytesIO(proc.stdout)
            resp = host.read_message(out)
            self.assertIsNotNone(resp)
            self.assertEqual(resp["id"], 7)
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["result"], {"text": ""})
            self.assertEqual(out.read(), b"")


class HostLifecycleTests(unittest.TestCase):
    def test_single_instance_lock_and_stale_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            stale = data / "config-stale.json"
            stale.write_text('{"secret":"value"}', encoding="utf-8")

            lock1 = host.acquire_lock(data)
            try:
                with self.assertRaises(RuntimeError):
                    host.acquire_lock(data)
                h = host.Host(core=ROOT / "native" / "bin" / "sing-box.exe", data=data)
                self.assertFalse(stale.exists())
                h.stop()
            finally:
                lock1.close()

            lock2 = host.acquire_lock(data)
            lock2.close()


class ProbeTests(unittest.TestCase):
    def test_parse_probe_url_validation(self):
        scheme, ascii_host, port_num, path, use_tls = host.parse_probe_url("https://cp.cloudflare.com/generate_204")
        self.assertEqual((scheme, ascii_host, port_num, path, use_tls), ("https", "cp.cloudflare.com", 443, "/generate_204", True))

        scheme2, ascii_host2, port2, path2, use_tls2 = host.parse_probe_url("http://пример.рф:8080/check?x=1")
        self.assertEqual((scheme2, ascii_host2, port2, path2, use_tls2), ("http", "xn--e1afmkfd.xn--p1ai", 8080, "/check?x=1", False))

        for bad in (
            "",
            "ftp://example.com/",
            "https://user:pass@example.com/",
            "https://localhost/test",
            "http://127.0.0.1:8080/",
            "http://192.168.1.1/",
            "http://[::1]/",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    host.parse_probe_url(bad)

    def test_socks5_http_probe_roundtrip_and_failure(self):
        def run_mock_socks(reply_code: int):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port_num = srv.getsockname()[1]

            def serve():
                with srv:
                    conn, _ = srv.accept()
                    with conn:
                        greeting = host.recv_exact(conn, 3)
                        if greeting == b"\x05\x01\x00":
                            conn.sendall(b"\x05\x00")
                        hdr = host.recv_exact(conn, 4)
                        atyp = hdr[3]
                        if atyp == 3:
                            n = host.recv_exact(conn, 1)[0]
                            host.recv_exact(conn, n + 2)
                        conn.sendall(bytes([5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0]))
                        if reply_code == 0:
                            conn.recv(1024)
                            conn.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")

            t = threading.Thread(target=serve, daemon=True)
            t.start()
            return port_num, t

        ok_port, t1 = run_mock_socks(0)
        latency, status_code = host.socks5_http_probe(ok_port, "example.invalid", 80, "/generate_204", use_tls=False, timeout=3.0)
        t1.join(timeout=2)
        self.assertGreaterEqual(latency, 1)
        self.assertEqual(status_code, 204)

        fail_port, t2 = run_mock_socks(5)
        with self.assertRaises(RuntimeError):
            host.socks5_http_probe(fail_port, "example.invalid", 80, "/generate_204", use_tls=False, timeout=3.0)
        t2.join(timeout=2)


class SingBoxBinaryCheckTests(unittest.TestCase):
    @unittest.skipUnless(host.CORE.is_file(), "sing-box binary not present in native/bin")
    def test_static_test_configs_with_sing_box_check(self):
        config_dir = ROOT / "tests" / "configs"
        files = sorted(config_dir.glob("*.json"))
        self.assertGreaterEqual(len(files), 6)
        for cfg_file in files:
            with self.subTest(config=cfg_file.name):
                res = subprocess.run(
                    [str(host.CORE), "check", "-c", str(cfg_file)],
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(
                    res.returncode,
                    0,
                    f"{cfg_file.name} failed:\n{(res.stderr + res.stdout).decode('utf-8', 'replace')}",
                )

    @unittest.skipUnless(host.CORE.is_file(), "sing-box binary not present in native/bin")
    def test_generated_configs_with_sing_box_check(self):
        samples = [
            ("vless-tls", sample_vless_tls(), {"dnsMode": "remote"}),
            ("vless-reality", sample_vless_reality(), {"dnsMode": "doh", "rules": [{"kind": "suffix", "value": "example.invalid", "action": "proxy"}]}),
            ("vmess-ws", sample_vmess_ws(), {"dnsMode": "remote"}),
            ("hysteria2", sample_hysteria2(), {"dnsMode": "remote"}),
            ("trojan", sample_trojan(), {"dnsMode": "doh", "mode": "rules", "defaultAction": "block"}),
            ("shadowsocks", sample_shadowsocks(), {"dnsMode": "remote"}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            h = host.Host(core=host.CORE, data=Path(tmp))
            for name, outbound, settings in samples:
                with self.subTest(profile=name):
                    cfg = host.build_config(outbound, settings)
                    h.validate_config(cfg)


if __name__ == "__main__":
    unittest.main()

