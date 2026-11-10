from __future__ import annotations

import base64
import io
import ipaddress
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

    @unittest.skipUnless(host.CORE.is_file(), "sing-box binary not present in native/bin")
    def test_geo_dat_and_ruleset_with_sing_box_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            geo_dir = Path(tmp) / "files"
            geo_dir.mkdir()
            geoip_dat = geo_dir / "geoip.dat"
            geosite_dat = geo_dir / "geosite.dat"
            custom_json = geo_dir / "custom.json"
            geoip_dat.write_bytes(build_sample_geoip_dat())
            geosite_dat.write_bytes(build_sample_geosite_dat())
            custom_json.write_text(json.dumps({"version": 2, "rules": [{"domain_suffix": ["custom.invalid"]}]}), encoding="utf-8")

            h = host.Host(core=host.CORE, data=Path(tmp) / "data")
            settings = {
                "dnsMode": "doh",
                "mode": "rules",
                "defaultAction": "direct",
                "geo": {
                    "geoip": {"sourceType": "local", "path": str(geoip_dat)},
                    "geosite": {"sourceType": "local", "path": str(geosite_dat)},
                    "ruleSets": [{"id": "rs1", "tag": "custom-rs", "enabled": True, "sourceType": "local", "format": "source", "path": str(custom_json)}],
                },
                "rules": [
                    {"kind": "geosite", "value": "ads", "action": "block", "enabled": True},
                    {"kind": "geosite", "value": "youtube@!cn", "action": "proxy", "enabled": True},
                    {"kind": "geoip", "value": "ru", "action": "direct", "enabled": True},
                    {"kind": "cidr", "value": "198.51.100.0/24", "action": "proxy", "enabled": True},
                    {"kind": "ruleset", "value": "custom-rs", "action": "proxy", "enabled": True},
                ],
            }
            cfg = h.build_runtime_config(sample_vless_tls(), settings, compile_srs=True)
            h.validate_config(cfg)


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _pb_field_bytes(num: int, data: bytes) -> bytes:
    return _pb_varint((num << 3) | 2) + _pb_varint(len(data)) + data


def _pb_field_varint(num: int, val: int) -> bytes:
    return _pb_varint((num << 3) | 0) + _pb_varint(val)


def build_sample_geoip_dat() -> bytes:
    def cidr_msg(ip_str: str, prefix: int) -> bytes:
        msg = _pb_field_bytes(1, ipaddress.ip_address(ip_str).packed)
        if prefix:
            msg += _pb_field_varint(2, prefix)
        return msg

    ru_entry = _pb_field_bytes(1, b"RU") + _pb_field_bytes(2, cidr_msg("77.88.55.0", 24)) + _pb_field_bytes(2, cidr_msg("2a02:6b8::", 32))
    cf_entry = _pb_field_bytes(1, b"CLOUDFLARE") + _pb_field_bytes(2, cidr_msg("1.1.1.0", 24))
    return _pb_field_bytes(1, ru_entry) + _pb_field_bytes(1, cf_entry)


def build_sample_geosite_dat() -> bytes:
    def dom_msg(kind: int, val: str, attrs=()) -> bytes:
        m = b""
        if kind:
            m += _pb_field_varint(1, kind)
        m += _pb_field_bytes(2, val.encode("utf-8"))
        for a in attrs:
            m += _pb_field_bytes(3, _pb_field_bytes(1, a.encode("utf-8")))
        return m

    yt_entry = (
        _pb_field_bytes(1, b"youtube")
        + _pb_field_bytes(2, dom_msg(2, "youtube.com"))
        + _pb_field_bytes(2, dom_msg(3, "m.youtube.com"))
        + _pb_field_bytes(2, dom_msg(2, "youtube.cn", attrs=("cn",)))
        + _pb_field_bytes(2, dom_msg(0, "ytimg"))
    )
    ads_entry = _pb_field_bytes(1, b"ads") + _pb_field_bytes(2, dom_msg(1, r"^ad\..*\.invalid$"))
    return _pb_field_bytes(1, yt_entry) + _pb_field_bytes(1, ads_entry)


class GeoRoutingTests(unittest.TestCase):
    def test_dat_inspection_and_extraction_including_attributes(self):
        with tempfile.TemporaryDirectory() as tmp:
            geoip_dat = Path(tmp) / "geoip.dat"
            geosite_dat = Path(tmp) / "geosite.dat"
            geoip_dat.write_bytes(build_sample_geoip_dat())
            geosite_dat.write_bytes(build_sample_geosite_dat())

            gi_info = host.inspect_geo_file(geoip_dat, "geoip")
            self.assertEqual(gi_info["format"], "dat")
            self.assertEqual(gi_info["tagsCount"], 2)
            self.assertEqual(gi_info["sampleTags"], ["cloudflare", "ru"])

            cidrs = host.extract_geoip_tag_cidrs(geoip_dat, {"ru"})
            self.assertEqual(cidrs["ru"], ["77.88.55.0/24", "2a02:6b8::/32"])

            gs = host.extract_geosite_tag_rules(geosite_dat, {"youtube", "youtube@cn", "youtube@!cn", "ads"})
            self.assertEqual(gs["youtube"]["domain_suffix"], ["youtube.com", "youtube.cn"])
            self.assertEqual(gs["youtube"]["domain"], ["m.youtube.com"])
            self.assertEqual(gs["youtube"]["domain_keyword"], ["ytimg"])
            self.assertEqual(gs["youtube@cn"], {"domain_suffix": ["youtube.cn"]})
            self.assertNotIn("youtube.cn", gs["youtube@!cn"].get("domain_suffix", []))
            self.assertIn("youtube.com", gs["youtube@!cn"]["domain_suffix"])
            self.assertEqual(gs["ads"]["domain_regex"], [r"^ad\..*\.invalid$"])

    def test_prepare_geo_and_preserve_rule_order_with_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = Path(tmp) / "files"
            files.mkdir()
            geoip_dat = files / "geoip.dat"
            geosite_dat = files / "geosite.dat"
            rs_json = files / "extra.json"
            geoip_dat.write_bytes(build_sample_geoip_dat())
            geosite_dat.write_bytes(build_sample_geosite_dat())
            rs_json.write_text(json.dumps({"version": 2, "rules": [{"ip_cidr": ["203.0.113.0/24"]}]}), encoding="utf-8")

            h = host.Host(core=Path(tmp) / "missing-core", data=Path(tmp) / "data")
            settings = {
                "dnsMode": "remote",
                "mode": "rules",
                "defaultAction": "direct",
                "geo": {
                    "geoip": {"sourceType": "local", "path": str(geoip_dat)},
                    "geosite": {"sourceType": "local", "path": str(geosite_dat)},
                    "ruleSets": [{"id": "r1", "tag": "extra", "enabled": True, "sourceType": "local", "format": "source", "path": str(rs_json)}],
                },
                "rules": [
                    {"kind": "geosite", "value": "youtube@!cn", "action": "proxy", "enabled": True},
                    {"kind": "geoip", "value": "ru", "action": "direct", "enabled": True},
                    {"kind": "cidr", "value": "198.51.100.5", "action": "block", "enabled": True},
                    {"kind": "ruleset", "value": "extra", "action": "proxy", "enabled": True},
                ],
            }
            cfg = h.build_runtime_config(sample_vless_tls(), settings, compile_srs=False)
            self.assertEqual([o["tag"] for o in cfg["outbounds"]], ["proxy", "direct"])
            self.assertEqual(cfg["route"]["final"], "direct")
            self.assertGreaterEqual(len(cfg["route"]["rule_set"]), 3)
            # geosite rule must stay BEFORE resolve(bootstrap), while geoip/cidr/ruleset stay AFTER resolve.
            rule_actions = [r.get("action") for r in cfg["route"]["rules"]]
            self.assertEqual(rule_actions, ["route", "resolve", "route", "reject", "route"])
            self.assertEqual(cfg["route"]["rules"][1], {"action": "resolve", "server": "bootstrap", "strategy": "prefer_ipv4"})
            self.assertEqual(cfg["route"]["rules"][3], {"ip_cidr": ["198.51.100.5/32"], "action": "reject"})

    def test_geo_errors_and_chunked_upload_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = host.Host(core=Path(tmp) / "missing-core", data=Path(tmp) / "data")
            dat = build_sample_geoip_dat()
            begin = h.geo_upload_begin({"target": "geoip", "fileName": "my-geoip.dat", "totalSize": len(dat)})
            uid = begin["uploadId"]
            mid = len(dat) // 2
            h.geo_upload_chunk({"uploadId": uid, "data": base64.b64encode(dat[:mid]).decode("ascii")})
            h.geo_upload_chunk({"uploadId": uid, "data": base64.b64encode(dat[mid:]).decode("ascii")})
            info = h.geo_upload_finish({"uploadId": uid})
            self.assertEqual(info["format"], "dat")
            self.assertEqual(info["tagsCount"], 2)
            self.assertTrue(Path(info["path"]).is_file())

            # Un-downloaded remote GeoIP raises clear error when referenced by enabled rule.
            with self.assertRaises(ValueError):
                h.prepare_geo_rule_sets({
                    "geo": {"geoip": {"sourceType": "remote", "url": "https://example.invalid/geoip.dat", "path": ""}},
                    "rules": [{"kind": "geoip", "value": "ru", "action": "direct", "enabled": True}],
                }, compile_srs=False)

            # Missing tag raises clear error.
            with self.assertRaises(ValueError):
                h.prepare_geo_rule_sets({
                    "geo": {"geoip": {"sourceType": "local", "path": info["path"]}},
                    "rules": [{"kind": "geoip", "value": "nonexistent-country", "action": "direct", "enabled": True}],
                }, compile_srs=False)

            # Reject local/http download URLs.
            with self.assertRaises(ValueError):
                h.geo_update({"targets": ["geoip"], "geo": {"geoip": {"sourceType": "remote", "url": "https://127.0.0.1/geoip.dat"}}})
            with self.assertRaises(ValueError):
                h.geo_update({"targets": ["geoip"], "geo": {"geoip": {"sourceType": "remote", "url": "http://example.invalid/geoip.dat"}}})


if __name__ == "__main__":
    unittest.main()

