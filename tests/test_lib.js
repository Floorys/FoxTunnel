"use strict";
const assert = require("node:assert/strict");
const FoxTunnel = require("../extension/lib.js");

function test(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (err) {
    console.error(`FAIL ${name}: ${err.stack || err.message}`);
    process.exitCode = 1;
  }
}

test("parseLink: VLESS TLS", () => {
  const p = FoxTunnel.parseLink(
    "vless://00000000-0000-4000-8000-000000000001@vless.example.invalid:443?type=tcp&security=tls&sni=cdn.example.invalid&alpn=h2,http/1.1&fp=firefox#My%20VLESS"
  );
  assert.equal(p.name, "My VLESS");
  assert.equal(p.outbound.type, "vless");
  assert.equal(p.outbound.server, "vless.example.invalid");
  assert.equal(p.outbound.server_port, 443);
  assert.equal(p.outbound.tls.server_name, "cdn.example.invalid");
  assert.deepEqual(p.outbound.tls.alpn, ["h2", "http/1.1"]);
  assert.deepEqual(p.outbound.tls.utls, { enabled: true, fingerprint: "firefox" });
});

test("parseLink: VLESS Reality with spx and IPv6", () => {
  const p = FoxTunnel.parseLink(
    "vless://00000000-0000-4000-8000-000000000001@[2001:db8::1]:443?security=reality&flow=xtls-rprx-vision&pbk=dGVzdC1yZWFsaXR5LXB1YmxpYy1rZXktMzItYnl0ZXM&sid=01ab&sni=www.example.com&spx=%2F#IPv6%20Reality"
  );
  assert.equal(p.name, "IPv6 Reality");
  assert.equal(p.outbound.server, "2001:db8::1");
  assert.equal(p.outbound.flow, "xtls-rprx-vision");
  assert.equal(p.outbound.tls.reality.enabled, true);
  assert.equal(p.outbound.tls.reality.short_id, "01ab");
  assert.equal(p.outbound.tls.utls.fingerprint, "chrome");
});

test("parseLink: VMess base64 JSON without padding and with insecure", () => {
  const json = JSON.stringify({
    v: "2", ps: "Мой VMess", add: "пример.рф", port: "443",
    id: "00000000-0000-4000-8000-000000000001", aid: "0", scy: "auto",
    net: "ws", type: "none", host: "ws.example.invalid", path: "/ws", tls: "tls", sni: "ws.example.invalid"
  });
  const b64 = Buffer.from(json, "utf8").toString("base64").replace(/=+$/, "");
  const p = FoxTunnel.parseLink("vmess://" + b64);
  assert.equal(p.name, "Мой VMess");
  assert.equal(p.outbound.server, "xn--e1afmkfd.xn--p1ai");
  assert.equal(p.outbound.transport.type, "ws");
  assert.equal(p.outbound.transport.headers.Host, "ws.example.invalid");
});

test("parseLink: Hysteria2 / hy2, Trojan, TUIC, AnyTLS", () => {
  const hy2 = FoxTunnel.parseLink(
    "hy2://pass%3A1@hy2.example.invalid:8443?obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=100&sni=hy2.example.invalid#Hy2%2050%"
  );
  assert.equal(hy2.name, "Hy2 50%");
  assert.equal(hy2.outbound.type, "hysteria2");
  assert.equal(hy2.outbound.password, "pass:1");
  assert.equal(hy2.outbound.obfs.type, "salamander");
  assert.equal(hy2.outbound.up_mbps, 50);

  const trojan = FoxTunnel.parseLink(
    "trojan://user:secret@trojan.example.invalid?type=grpc&serviceName=svc&mode=gun#Trojan"
  );
  assert.equal(trojan.outbound.password, "user:secret");
  assert.equal(trojan.outbound.server_port, 443);
  assert.equal(trojan.outbound.transport.type, "grpc");
  assert.equal(trojan.outbound.transport.service_name, "svc");

  const tuic = FoxTunnel.parseLink(
    "tuic://00000000-0000-4000-8000-000000000001:secret@tuic.example.invalid:443?congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1&disable_sni=1#TUIC"
  );
  assert.equal(tuic.outbound.type, "tuic");
  assert.equal(tuic.outbound.tls.insecure, true);
  assert.equal(tuic.outbound.tls.disable_sni, true);

  const anytls = FoxTunnel.parseLink("anytls://secret@any.example.invalid:443?sni=any.example.invalid#Any");
  assert.equal(anytls.outbound.type, "anytls");
  assert.equal(anytls.outbound.tls.enabled, true);
});

test("parseLink: Shadowsocks SIP002, legacy with slashes, HTTP :80 and SOCKS", () => {
  const sip = FoxTunnel.parseLink(
    "ss://" + Buffer.from("aes-128-gcm:pass+1/2=", "utf8").toString("base64url") + "@ss.example.invalid:8388/?uot=1#SS"
  );
  assert.equal(sip.outbound.method, "aes-128-gcm");
  assert.equal(sip.outbound.password, "pass+1/2=");
  assert.equal(sip.outbound.udp_over_tcp, true);

  const legacyPayload = Buffer.from("chacha20-ietf-poly1305:pw?/+@192.0.2.5:8388", "utf8").toString("base64");
  const legacy = FoxTunnel.parseLink(`ss://${legacyPayload}#Legacy`);
  assert.equal(legacy.outbound.server, "192.0.2.5");
  assert.equal(legacy.outbound.password, "pw?/+");

  const http80 = FoxTunnel.parseLink("http://user:pass@proxy.example.invalid:80#HTTP80");
  assert.equal(http80.outbound.type, "http");
  assert.equal(http80.outbound.server_port, 80);

  const socks = FoxTunnel.parseLink("socks5://user:pass@192.0.2.9:1080#S5");
  assert.equal(socks.outbound.type, "socks");
  assert.equal(socks.outbound.version, "5");
});

test("parseLink: rejects Xray-only and unsupported params explicitly", () => {
  assert.throws(() => FoxTunnel.parseLink("vless://00000000-0000-4000-8000-000000000001@a.invalid:443?type=xhttp"));
  assert.throws(() => FoxTunnel.parseLink("vless://00000000-0000-4000-8000-000000000001@a.invalid:443?type=kcp"));
  assert.throws(() => FoxTunnel.parseLink("vless://00000000-0000-4000-8000-000000000001@a.invalid:443?headerType=http"));
  assert.throws(() => FoxTunnel.parseLink("vless://00000000-0000-4000-8000-000000000001@a.invalid:443?flow=xtls-rprx-vision-udp443"));
  assert.throws(() => FoxTunnel.parseLink("hy2://pw@a.invalid:443?mport=1000-2000"));
  assert.throws(() => FoxTunnel.parseLink("hy2://pw@a.invalid:443?pinSHA256=abc"));
  assert.throws(() => FoxTunnel.parseLink("ss://YWVzLTEyOC1nY206cHc=@a.invalid:8388/?plugin=v2ray-plugin"));
  assert.throws(() => FoxTunnel.parseLink("trojan://pw@a.invalid:443?security=none"));
  assert.throws(() => FoxTunnel.parseLink("trojan://pw@a.invalid:443?unknownParam=1"));
});

test("parseSubscription: atomic failure with real line number", () => {
  const text = "# comment\n\ntrojan://pw@a.invalid:443\nvless://bad@a.invalid:443?type=xhttp\n";
  assert.throws(
    () => FoxTunnel.parseSubscription(text),
    err => /Строка 4:/.test(err.message)
  );
});

test("actionFor, isLocal and validateSettings", () => {
  const s = {
    ...FoxTunnel.defaults(),
    mode: "rules",
    defaultAction: "direct",
    bypassLocal: false,
    rules: [
      { id: "1", enabled: true, kind: "domain", value: "sub.example.invalid", action: "direct" },
      { id: "2", enabled: true, kind: "suffix", value: "example.invalid", action: "proxy" },
      { id: "3", enabled: true, kind: "keyword", value: "ads", action: "block" }
    ]
  };
  assert.equal(FoxTunnel.actionFor("http://127.0.0.1:8080/x", s), "direct");
  assert.equal(FoxTunnel.actionFor("http://[::1]:8080/x", s), "direct");
  assert.equal(FoxTunnel.actionFor("http://[::ffff:127.0.0.1]/", { ...s, bypassLocal: true }), "direct");
  assert.equal(FoxTunnel.actionFor("http://192.168.1.1/", { ...s, bypassLocal: true }), "direct");
  assert.equal(FoxTunnel.actionFor("https://sub.example.invalid/", s), "direct");
  assert.equal(FoxTunnel.actionFor("https://app.example.invalid/", s), "proxy");
  assert.equal(FoxTunnel.actionFor("https://ads.other.invalid/", s), "block");
  assert.equal(FoxTunnel.actionFor("https://other.invalid/", { ...s, mode: "global" }), "proxy");

  assert.throws(() => FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), dnsMode: "doh", dnsServer: "abc" }));
  assert.throws(() => FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), dnsMode: "doh", dnsServer: "999.1.1.1" }));
  const validDoh = FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), dnsMode: "doh", dnsServer: "[2606:4700:4700::1111]" });
  assert.equal(validDoh.dnsServer, "2606:4700:4700::1111");

  const validTheme = FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), theme: "dark", probeUrl: "https://www.gstatic.com/generate_204" });
  assert.equal(validTheme.theme, "dark");
  assert.equal(validTheme.probeUrl, "https://www.gstatic.com/generate_204");
  assert.throws(() => FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), theme: "neon" }));
  assert.throws(() => FoxTunnel.validateSettings({ ...FoxTunnel.defaults(), probeUrl: "http://127.0.0.1:8080/" }));
});

test("subscriptions: URL validation, headers, masking, merge and settings", () => {
  assert.equal(FoxTunnel.validateSubscriptionUrl("https://sub.example.invalid/token/123"), "https://sub.example.invalid/token/123");
  assert.throws(() => FoxTunnel.validateSubscriptionUrl("http://sub.example.invalid/token"));
  assert.throws(() => FoxTunnel.validateSubscriptionUrl("https://user:pass@sub.example.invalid/token"));
  assert.throws(() => FoxTunnel.validateSubscriptionUrl("https://127.0.0.1/token"));
  assert.equal(FoxTunnel.maskSubscriptionUrl("https://sub.example.invalid/secret-token?x=1"), "https://sub.example.invalid/•••");

  const titleB64 = Buffer.from("Мой провайдер", "utf8").toString("base64");
  const meta = FoxTunnel.parseSubscriptionHeaders({
    "Profile-Title": `base64:${titleB64}`,
    "Subscription-Userinfo": "upload=100; download=200; total=1000; expire=1893456000"
  }, "sub.example.invalid");
  assert.equal(meta.title, "Мой провайдер");
  assert.deepEqual(meta.info, { upload: 100, download: 200, total: 1000, expire: 1893456000 });

  const subId = "sub-1";
  const manual = { id: "m1", name: "Manual", outbound: { type: "socks", server: "192.0.2.1", server_port: 1080, version: "5" }, subscriptionId: "" };
  const oldS1 = { id: "s1", name: "Node 1", outbound: { type: "trojan", server: "192.0.2.2", server_port: 443, password: "p1" }, subscriptionId: subId };
  const oldS2 = { id: "s2", name: "Node 2", outbound: { type: "trojan", server: "192.0.2.3", server_port: 443, password: "p2" }, subscriptionId: subId };

  const parsedNew = [
    { id: "tmp1", name: "Node 1 renamed", outbound: { type: "trojan", server: "192.0.2.2", server_port: 443, password: "p1" } },
    { id: "tmp2", name: "Node 3", outbound: { type: "trojan", server: "192.0.2.4", server_port: 443, password: "p3" } }
  ];
  const merged = FoxTunnel.mergeSubscriptionProfiles([manual, oldS1, oldS2], subId, parsedNew, "s1");
  assert.equal(merged.count, 2);
  assert.equal(merged.selectedId, "s1");
  assert.deepEqual(merged.profiles.map(p => p.id), ["m1", "s1", "tmp2"]);

  const mergedRemovedSelected = FoxTunnel.mergeSubscriptionProfiles([manual, oldS1, oldS2], subId, parsedNew, "s2");
  assert.equal(mergedRemovedSelected.selectedId, "s1");

  const swapped = FoxTunnel.mergeSubscriptionProfiles(
    [oldS1, oldS2],
    subId,
    [
      { id: "n1", name: "Node 2", outbound: { type: "trojan", server: "192.0.2.9", server_port: 443, password: "p9" } },
      { id: "n2", name: "Node 1", outbound: oldS2.outbound }
    ],
    "s2"
  );
  assert.equal(new Set(swapped.profiles.map(p => p.id)).size, 2);
  assert.equal(swapped.selectedId, "s2");

  const valid = FoxTunnel.validateSettings({
    ...FoxTunnel.defaults(),
    subscriptionAutoUpdate: true,
    subscriptions: [{ id: subId, name: "Provider", url: "https://sub.example.invalid/abc", updatedAt: "2026-11-10T10:00:00Z", info: meta.info }],
    profiles: merged.profiles,
    selectedId: merged.selectedId
  });
  assert.equal(valid.subscriptions.length, 1);
  assert.equal(valid.profiles[1].subscriptionId, subId);
});

test("geo routing: cidr, geoip, geosite, ruleset normalization, policy order, and geo sources", () => {
  const rCidr = FoxTunnel.normalizeRule({ kind: "cidr", action: "direct", value: "198.51.100.5" });
  assert.equal(rCidr.value, "198.51.100.5/32");
  const rCidr6 = FoxTunnel.normalizeRule({ kind: "cidr", action: "proxy", value: "[2001:0db8:0000:0000::]/32" });
  assert.equal(rCidr6.value, "2001:db8::/32");
  assert.throws(() => FoxTunnel.normalizeRule({ kind: "cidr", action: "direct", value: "1.2.3.4/99" }));

  const rGeoip = FoxTunnel.normalizeRule({ kind: "geoip", action: "direct", value: "GEOIP:RU" });
  assert.equal(rGeoip.value, "ru");
  const rGeosite = FoxTunnel.normalizeRule({ kind: "geosite", action: "proxy", value: "geosite:YouTube@!CN" });
  assert.equal(rGeosite.value, "youtube@!cn");
  const rSet = FoxTunnel.normalizeRule({ kind: "ruleset", action: "block", value: "ruleset:Ads_List" });
  assert.equal(rSet.value, "ads_list");
  assert.throws(() => FoxTunnel.normalizeRule({ kind: "geosite", action: "proxy", value: "bad/tag" }));

  const s = FoxTunnel.validateSettings({
    ...FoxTunnel.defaults(),
    mode: "rules",
    defaultAction: "direct",
    geo: {
      geoip: { sourceType: "remote", url: "https://example.invalid/geoip.dat", path: "", format: "dat" },
      geosite: { sourceType: "local", path: "C:\\Geo\\geosite.dat" },
      ruleSets: [{ id: "rs1", tag: "custom-ads", enabled: true, sourceType: "remote", format: "binary", url: "https://example.invalid/ads.srs" }],
      updateViaProxy: true
    },
    rules: [
      { kind: "domain", action: "direct", value: "direct-first.invalid" },
      { kind: "geosite", action: "proxy", value: "youtube" },
      { kind: "suffix", action: "block", value: "later.invalid" }
    ]
  });
  assert.equal(FoxTunnel.hasCoreOnlyRules(s), true);
  assert.equal(FoxTunnel.routePolicy("https://direct-first.invalid/", s), "direct");
  assert.equal(FoxTunnel.routePolicy("https://www.youtube.com/", s), "core");
  assert.equal(FoxTunnel.routePolicy("https://later.invalid/", s), "core");
  assert.equal(FoxTunnel.actionFor("https://later.invalid/", s), "proxy");

  const disabledCore = { ...s, rules: s.rules.map(r => (r.kind === "geosite" ? { ...r, enabled: false } : r)) };
  assert.equal(FoxTunnel.hasCoreOnlyRules(disabledCore), false);
  assert.equal(FoxTunnel.routePolicy("https://later.invalid/", disabledCore), "block");

  assert.throws(() => FoxTunnel.validateGeoSettings({ geoip: { sourceType: "remote", url: "http://example.invalid/geoip.dat" } }));
  assert.throws(() => FoxTunnel.validateGeoSettings({ geoip: { sourceType: "remote", url: "https://127.0.0.1/geoip.dat" } }));
  assert.throws(() => FoxTunnel.validateGeoSettings({ geoip: { sourceType: "local", path: "C:\\Geo\\bad.exe" } }));
  assert.throws(() => FoxTunnel.validateGeoSettings({
    ruleSets: [
      { id: "1", tag: "dup", sourceType: "remote", url: "https://example.invalid/a.srs" },
      { id: "2", tag: "dup", sourceType: "remote", url: "https://example.invalid/b.srs" }
    ]
  }));

  // Legacy backups without geo field remain valid.
  const legacy = FoxTunnel.validateSettings({ version: 1, profiles: [], rules: [] });
  assert.equal(legacy.geo.geoip.sourceType, "none");
  assert.deepEqual(legacy.geo.ruleSets, []);
});


