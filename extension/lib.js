/* Shared, pure functions: no browser APIs, no network. */
/* global globalThis */
"use strict";
(function (root) {
  const TYPES = ["vless", "vmess", "hysteria2", "hysteria", "trojan", "shadowsocks", "tuic", "anytls", "socks", "http", "shadowtls", "naive"];
  const FORBIDDEN_KEYS = new Set(["detour", "outbounds", "inbounds", "endpoints", "providers", "route", "dns", "experimental", "ntp", "log"]);
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  const defaults = () => ({
    version: 1, profiles: [], selectedId: "", subscriptions: [], subscriptionAutoUpdate: false,
    mode: "rules", defaultAction: "direct",
    rules: [], port: 2080, killSwitch: true, bypassLocal: true,
    protectWebRTC: true, autoConnect: false, logLevel: "warn", dnsMode: "remote",
    dnsServer: "1.1.1.1", dnsServerName: "cloudflare-dns.com", dnsPath: "/dns-query",
    theme: "system", probeUrl: "https://cp.cloudflare.com/generate_204"
  });

  function decode64(text) {
    const value = String(text || "").replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    if (!value || !/^[A-Za-z0-9+/]*=*$/.test(value)) throw new Error("Некорректные данные base64.");
    const padded = value + "=".repeat((4 - value.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function decodePercent(text) {
    try { return decodeURIComponent(text); }
    catch { throw new Error("Некорректное percent-кодирование (%XX) в ссылке."); }
  }

  function decodeFragment(text) {
    if (!text) return "";
    try { return decodeURIComponent(text); }
    catch {
      return text.replace(/(?:%[0-9a-fA-F]{2})+/g, m => {
        try { return decodeURIComponent(m); } catch { return m; }
      });
    }
  }

  function unbracket(host) { return String(host || "").replace(/^\[|\]$/g, ""); }

  function isValidIpv4(host) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (!m) return false;
    return m.slice(1).every(octet => {
      const n = Number(octet);
      return n >= 0 && n <= 255 && String(n) === octet;
    });
  }

  function parseIpv6(host) {
    const raw = unbracket(String(host || "").trim());
    if (!raw.includes(":") || /[\s/?#@[\]]/.test(raw)) return "";
    try {
      const u = new URL(`http://[${raw}]/`);
      return unbracket(u.hostname);
    } catch { return ""; }
  }

  function isValidIp(host) {
    const raw = String(host || "").trim();
    return isValidIpv4(raw) || Boolean(parseIpv6(raw));
  }

  function normalizeHost(rawHost) {
    const clean = unbracket(String(rawHost || "").trim());
    if (!clean || /[\s/?#@\\[\]]/.test(clean)) throw new Error("Укажите адрес сервера без схемы, пути и пробелов.");
    if (isValidIpv4(clean)) return clean;
    const ipv6 = parseIpv6(clean);
    if (ipv6) return ipv6;
    let u;
    try { u = new URL(`http://${clean}`); } catch { throw new Error("Некорректный адрес сервера."); }
    if (u.port || u.hostname !== u.host) throw new Error("Адрес сервера не должен содержать порт или учётные данные.");
    return u.hostname.replace(/\.$/, "");
  }

  function port(value) {
    if (typeof value === "boolean" || value === "" || value === null || value === undefined) {
      throw new Error("Порт должен быть числом от 1 до 65535.");
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error("Порт должен быть числом от 1 до 65535.");
    return n;
  }

  function positiveInt(raw, label) {
    if (!/^\d+$/.test(String(raw || "").trim())) throw new Error(`${label} должно быть целым неотрицательным числом.`);
    const n = Number(raw);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${label} вне допустимого диапазона.`);
    return n;
  }

  function validateOutbound(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) || !TYPES.includes(value.type)) {
      throw new Error("Неизвестный тип outbound sing-box.");
    }
    if (typeof value.server !== "string" || !value.server.trim() || /[\s/\\[\]\x00-\x1f]/.test(value.server)) {
      throw new Error("Укажите адрес сервера без схемы, пути и квадратных скобок.");
    }
    value.server_port = port(value.server_port);
    const walk = obj => {
      if (!obj || typeof obj !== "object") return;
      for (const [key, child] of Object.entries(obj)) {
        if (key.endsWith("_path") || FORBIDDEN_KEYS.has(key)) {
          throw new Error(`Поле ${key} запрещено в профиле. Используйте встроенные значения, не пути к файлам и не маршрутизацию.`);
        }
        walk(child);
      }
    };
    walk(value);
    if (["vless", "vmess", "tuic"].includes(value.type) && !UUID_RE.test(value.uuid || "")) {
      throw new Error("Нужен корректный UUID.");
    }
    if (value.type === "shadowsocks") {
      if (typeof value.method !== "string" || !value.method.trim()) throw new Error("Shadowsocks: укажите method.");
      if (typeof value.password !== "string" || !value.password) throw new Error("Shadowsocks: укажите password.");
    }
    if (["trojan", "anytls", "hysteria2"].includes(value.type)) {
      if (typeof value.password !== "string" || !value.password) throw new Error(`${value.type}: укажите password.`);
    }
    if (value.type === "vmess" && value.alter_id !== undefined) {
      if (typeof value.alter_id !== "number" || !Number.isInteger(value.alter_id) || value.alter_id < 0) {
        throw new Error("VMess: alter_id должен быть целым числом >= 0.");
      }
    }
    if (value.tls !== undefined && (typeof value.tls !== "object" || value.tls === null || Array.isArray(value.tls))) {
      throw new Error("Поле tls должно быть объектом.");
    }
    if (value.transport !== undefined && (typeof value.transport !== "object" || value.transport === null || Array.isArray(value.transport))) {
      throw new Error("Поле transport должно быть объектом.");
    }
    return value;
  }

  function ensureSupportedParams(params, allowed, protocolLabel) {
    for (const [key, val] of params.entries()) {
      if (!allowed.has(key) && val !== "") {
        throw new Error(`${protocolLabel}: параметр «${key}» не поддерживается импортом; при необходимости настройте профиль через JSON outbound.`);
      }
    }
  }

  function transport(params) {
    const type = (params.get("type") || params.get("net") || "tcp").toLowerCase();
    const headerType = params.get("headerType");
    if (type === "tcp" || type === "none") {
      if (headerType && headerType !== "none") {
        throw new Error(`TCP headerType=${headerType} не поддерживается sing-box. Используйте JSON outbound или другой транспорт.`);
      }
      return undefined;
    }
    if (type === "ws") {
      const result = { type: "ws", path: params.get("path") || "/" };
      if (params.get("host")) result.headers = { Host: params.get("host") };
      if (params.has("ed") && params.get("ed") !== "") result.max_early_data = positiveInt(params.get("ed"), "ws ed");
      if (params.has("eh") && params.get("eh") !== "") result.early_data_header_name = params.get("eh");
      return result;
    }
    if (type === "grpc") {
      const mode = params.get("mode");
      if (mode && mode !== "gun") {
        throw new Error(`gRPC mode=${mode} не поддерживается импортом; используйте стандартный gRPC или JSON outbound.`);
      }
      return { type: "grpc", service_name: params.get("serviceName") || "" };
    }
    if (type === "http" || type === "h2") {
      return { type: "http", host: (params.get("host") || "").split(",").map(s => s.trim()).filter(Boolean), path: params.get("path") || "/" };
    }
    if (type === "httpupgrade") {
      const result = { type: "httpupgrade", path: params.get("path") || "/" };
      if (params.get("host")) result.host = params.get("host");
      return result;
    }
    throw new Error(`Транспорт ${type} не поддерживается этим импортом/sing-box. XHTTP, KCP и Xray-only транспорты автоматически не конвертируются; используйте JSON outbound.`);
  }

  function tls(params, required = false, protocolLabel = "Протокол") {
    const rawSecurity = params.get("security");
    const security = (rawSecurity || (params.get("tls") === "tls" ? "tls" : "none")).toLowerCase();
    if (required && rawSecurity && rawSecurity.toLowerCase() === "none") {
      throw new Error(`${protocolLabel} требует TLS; параметр security=none недопустим.`);
    }
    if (!required && security === "none") return undefined;
    if (!["none", "tls", "reality"].includes(security)) throw new Error(`Неизвестный TLS режим: ${security}`);
    const result = { enabled: true };
    const sni = params.get("sni") || params.get("peer") || params.get("serverName");
    if (sni) result.server_name = sni;
    if (params.has("alpn") && params.get("alpn") !== "") {
      result.alpn = params.get("alpn").split(",").map(s => s.trim()).filter(Boolean);
    }
    const insecureVal = params.get("allowInsecure") || params.get("insecure") || params.get("allow_insecure");
    if (["1", "true"].includes(String(insecureVal || "").toLowerCase())) result.insecure = true;
    const disableSniVal = params.get("disable_sni");
    if (["1", "true"].includes(String(disableSniVal || "").toLowerCase())) result.disable_sni = true;
    if (params.get("fp")) result.utls = { enabled: true, fingerprint: params.get("fp") };
    if (security === "reality") {
      if (!params.get("pbk")) throw new Error("В Reality-ссылке отсутствует pbk (public key).");
      if (params.has("pqv") || params.has("mldsa65Verify")) throw new Error("Xray Reality pqv/mldsa65Verify не поддерживается sing-box.");
      result.reality = { enabled: true, public_key: params.get("pbk"), short_id: params.get("sid") || "" };
      result.utls ||= { enabled: true, fingerprint: "chrome" };
    }
    return result;
  }

  function parseShadowsocks(text) {
    const body = text.slice(5);
    const hashIdx = body.indexOf("#");
    const beforeHash = hashIdx >= 0 ? body.slice(0, hashIdx) : body;
    const name = hashIdx >= 0 ? decodeFragment(body.slice(hashIdx + 1)) : "";
    const queryIdx = beforeHash.indexOf("?");
    const main = queryIdx >= 0 ? beforeHash.slice(0, queryIdx) : beforeHash;
    const params = new URLSearchParams(queryIdx >= 0 ? beforeHash.slice(queryIdx + 1) : "");
    if (params.get("plugin")) {
      throw new Error("Shadowsocks plugin не поддерживается импортом. При необходимости настройте профиль через JSON outbound.");
    }
    ensureSupportedParams(params, new Set(["plugin", "uot"]), "Shadowsocks");

    let server, serverPort, credentials;
    const atIdx = main.lastIndexOf("@");
    if (atIdx >= 0) {
      const userinfo = decodePercent(main.slice(0, atIdx));
      const endpointRaw = main.slice(atIdx + 1).replace(/\/+$/, "");
      let endpoint;
      try { endpoint = new URL(`socks://${endpointRaw}`); } catch { throw new Error("Некорректный адрес сервера Shadowsocks."); }
      server = endpoint.hostname;
      serverPort = endpoint.port;
      credentials = userinfo.includes(":") ? userinfo : decode64(userinfo);
    } else {
      const full = decode64(main.replace(/\/+$/, ""));
      const split = full.lastIndexOf("@");
      if (split < 1) throw new Error("Некорректная Shadowsocks-ссылка.");
      credentials = full.slice(0, split);
      let endpoint;
      try { endpoint = new URL(`socks://${full.slice(split + 1)}`); } catch { throw new Error("Некорректный адрес сервера Shadowsocks."); }
      server = endpoint.hostname;
      serverPort = endpoint.port;
    }

    const split = credentials.indexOf(":");
    if (split < 1) throw new Error("Shadowsocks: отсутствуют метод или пароль.");
    const outbound = {
      type: "shadowsocks",
      server: normalizeHost(decodePercent(server)),
      server_port: port(serverPort),
      method: credentials.slice(0, split),
      password: credentials.slice(split + 1)
    };
    const uot = String(params.get("uot") || "").toLowerCase();
    if (["1", "true"].includes(uot)) outbound.udp_over_tcp = true;
    else if (uot && !["0", "false"].includes(uot)) throw new Error(`Shadowsocks: неподдерживаемое значение uot=${uot}.`);
    return { outbound, name };
  }

  function parseVmess(text) {
    const body = text.slice(8);
    const hashIdx = body.indexOf("#");
    const encoded = hashIdx >= 0 ? body.slice(0, hashIdx) : body;
    const fragName = hashIdx >= 0 ? decodeFragment(body.slice(hashIdx + 1)) : "";
    let v;
    try { v = JSON.parse(decode64(encoded)); } catch { throw new Error("VMess: ожидается vmess://base64(JSON). URI-вариант не поддержан."); }
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("VMess: некорректный JSON внутри ссылки.");
    const net = String(v.net || "tcp").toLowerCase();
    const camType = String(v.type || "").toLowerCase();
    if (camType && camType !== "none" && !(net === "grpc" && camType === "gun")) {
      throw new Error(`VMess camouflage type=${v.type} не поддерживается импортом; используйте JSON outbound.`);
    }
    const aid = v.aid === undefined || v.aid === "" ? 0 : positiveInt(v.aid, "VMess aid");
    const allowInsecure = v.allowInsecure ?? v.insecure ?? v.skipCertVerify ?? v["skip-cert-verify"];
    const p = new URLSearchParams({
      type: net,
      path: v.path || (net === "grpc" ? "" : "/"),
      host: v.host || "",
      serviceName: v.path || "",
      security: v.tls || "none",
      sni: v.sni || v.host || "",
      alpn: Array.isArray(v.alpn) ? v.alpn.join(",") : (v.alpn || ""),
      fp: v.fp || "",
      allowInsecure: allowInsecure === true || allowInsecure === 1 || allowInsecure === "1" || allowInsecure === "true" ? "1" : ""
    });
    const outbound = {
      type: "vmess",
      server: normalizeHost(v.add),
      server_port: port(v.port),
      uuid: String(v.id || ""),
      security: v.scy || "auto",
      alter_id: aid
    };
    const tr = transport(p);
    if (tr) outbound.transport = tr;
    const tl = tls(p, false, "VMess");
    if (tl) outbound.tls = tl;
    return { outbound, name: String(v.ps || fragName || "") };
  }

  function parseLink(text) {
    text = String(text || "").trim();
    if (!text) throw new Error("Пустая ссылка.");
    let outbound, name;
    if (text.startsWith("vmess://")) {
      ({ outbound, name } = parseVmess(text));
    } else if (text.startsWith("ss://")) {
      ({ outbound, name } = parseShadowsocks(text));
    } else {
      let u;
      try { u = new URL(text); } catch { throw new Error("Некорректный формат URI ссылки."); }
      const p = u.searchParams;
      const protocol = u.protocol.slice(0, -1).toLowerCase();
      const type = protocol === "hy2" ? "hysteria2" : (protocol === "socks5" || protocol === "socks5h") ? "socks" : protocol;
      if (!["vless", "hysteria2", "trojan", "tuic", "socks", "http", "https", "anytls"].includes(type)) {
        throw new Error(`Импорт ${protocol}:// не поддержан. Можно добавить JSON outbound.`);
      }
      if (p.has("mport") || p.has("ports")) throw new Error("Port hopping не поддерживается в URI-импорте: добавьте server_ports через JSON outbound.");
      if (p.has("pinSHA256")) throw new Error("Hysteria2 pinSHA256 не импортируется из ссылки; настройте TLS/сертификат через JSON outbound.");

      const defaultPort = type === "http" ? 80 : type === "socks" ? 1080 : ["trojan", "hysteria2", "tuic", "anytls", "https"].includes(type) ? 443 : 0;
      const serverHost = normalizeHost(decodePercent(u.hostname));
      outbound = {
        type: type === "https" ? "http" : type,
        server: serverHost,
        server_port: port(u.port || defaultPort)
      };
      const user = decodePercent(u.username), pass = decodePercent(u.password);

      if (type === "vless") {
        ensureSupportedParams(p, new Set(["type", "net", "security", "encryption", "flow", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp", "pbk", "sid", "spx", "path", "host", "ed", "eh", "serviceName", "mode", "headerType", "packetEncoding"]), "VLESS");
        if (p.get("encryption") && p.get("encryption") !== "none") throw new Error("VLESS encryption из Xray не поддерживается sing-box.");
        const flow = p.get("flow") || "";
        if (flow && flow !== "xtls-rprx-vision") {
          throw new Error(`VLESS flow=${flow} (Xray-only) не поддерживается sing-box; используйте xtls-rprx-vision или JSON outbound.`);
        }
        outbound.uuid = user;
        if (flow) outbound.flow = flow;
        const pe = p.get("packetEncoding");
        if (pe) {
          if (!["xudp", "packetaddr"].includes(pe)) throw new Error(`VLESS packetEncoding=${pe} не поддерживается sing-box.`);
          outbound.packet_encoding = pe;
        }
        const tr = transport(p);
        if (tr) outbound.transport = tr;
        const tl = tls(p, false, "VLESS");
        if (tl) outbound.tls = tl;
      } else if (type === "trojan") {
        ensureSupportedParams(p, new Set(["type", "net", "security", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp", "pbk", "sid", "spx", "path", "host", "ed", "eh", "serviceName", "mode", "headerType"]), "Trojan");
        outbound.password = pass ? `${user}:${pass}` : user;
        outbound.tls = tls(p, true, "Trojan");
        const tr = transport(p);
        if (tr) outbound.transport = tr;
      } else if (type === "anytls") {
        ensureSupportedParams(p, new Set(["security", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp"]), "AnyTLS");
        outbound.password = pass ? `${user}:${pass}` : user;
        outbound.tls = tls(p, true, "AnyTLS");
      } else if (type === "hysteria2") {
        ensureSupportedParams(p, new Set(["security", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp", "obfs", "obfs-password", "upmbps", "downmbps"]), "Hysteria2");
        outbound.password = pass ? `${user}:${pass}` : user;
        outbound.tls = tls(p, true, "Hysteria2");
        if (p.get("obfs")) {
          if (p.get("obfs") !== "salamander" || !p.get("obfs-password")) throw new Error("Hysteria2: поддерживается только obfs=salamander с obfs-password.");
          outbound.obfs = { type: "salamander", password: p.get("obfs-password") };
        }
        for (const [param, field] of [["upmbps", "up_mbps"], ["downmbps", "down_mbps"]]) {
          if (p.has(param) && p.get(param) !== "") {
            const val = positiveInt(p.get(param), param);
            if (val < 1) throw new Error(`${param} должен быть больше 0.`);
            outbound[field] = val;
          }
        }
      } else if (type === "tuic") {
        ensureSupportedParams(p, new Set(["security", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp", "congestion_control", "udp_relay_mode", "disable_sni", "zero_rtt_handshake"]), "TUIC");
        outbound.uuid = user;
        outbound.password = pass;
        outbound.tls = tls(p, true, "TUIC");
        if (p.get("congestion_control")) outbound.congestion_control = p.get("congestion_control");
        if (p.get("udp_relay_mode")) outbound.udp_relay_mode = p.get("udp_relay_mode");
        if (["1", "true"].includes(String(p.get("zero_rtt_handshake") || "").toLowerCase())) outbound.zero_rtt_handshake = true;
      } else {
        ensureSupportedParams(p, type === "https" ? new Set(["security", "sni", "peer", "serverName", "alpn", "allowInsecure", "insecure", "allow_insecure", "fp"]) : new Set(), type.toUpperCase());
        if (user) outbound.username = user;
        if (pass) outbound.password = pass;
        if (type === "https") outbound.tls = tls(p, true, "HTTPS");
        if (type === "socks") outbound.version = "5";
      }
      name = decodeFragment(u.hash.slice(1));
    }
    outbound = JSON.parse(JSON.stringify(outbound));
    validateOutbound(outbound);
    return { id: crypto.randomUUID(), name: (name || "").trim().slice(0, 160) || `${outbound.type} · ${outbound.server}`, outbound };
  }

  function parseSubscription(text) {
    const clean = String(text || "").trim().replace(/^\uFEFF/, "");
    if (!clean) throw new Error("Пустой текст подписки.");
    if (clean.length > 2 * 1024 * 1024) throw new Error("Подписка превышает допустимый размер (2 МБ).");
    let decoded = clean;
    if (!clean.includes("://")) {
      try { decoded = decode64(clean); } catch { throw new Error("Ожидаются ссылки, по одной на строку, или base64-подписка. YAML не поддержан."); }
    }
    const entries = decoded.split(/\r?\n/)
      .map((line, index) => ({ line: line.trim(), num: index + 1 }))
      .filter(item => item.line && !item.line.startsWith("#"));
    if (!entries.length || entries.length > 500) throw new Error("Подписка должна содержать от 1 до 500 профилей.");
    // Atomic import: unsupported lines must not silently disappear.
    return entries.map(item => {
      try { return parseLink(item.line); }
      catch (e) { throw new Error(`Строка ${item.num}: ${e.message}`); }
    });
  }

  function normalizeDomain(input) {
    const raw = String(input || "").trim().toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/\.$/, "");
    if (!raw || /[\s/?#@\\[\]]/.test(raw)) throw new Error("Введите домен без протокола, порта и пути.");
    let u;
    try { u = new URL(`http://${raw}`); } catch { throw new Error("Некорректный домен в правиле."); }
    if (u.port || u.hostname !== u.host) throw new Error("В доменном правиле не нужен порт.");
    return u.hostname.replace(/\.$/, "");
  }

  function normalizeRule(rule) {
    if (!rule || typeof rule !== "object") throw new Error("Некорректное правило.");
    if (!["domain", "suffix", "keyword"].includes(rule.kind)) throw new Error("Неизвестный тип доменного правила.");
    if (!["proxy", "direct", "block"].includes(rule.action)) throw new Error("Неизвестное действие правила.");
    let value;
    if (rule.kind === "keyword") {
      value = String(rule.value || "").trim().toLowerCase();
      if (/[\s/?#@\\\x00-\x1f]/.test(value)) throw new Error("Подстрока домена не должна содержать пробелы или спецсимволы URL.");
    } else {
      value = normalizeDomain(String(rule.value || ""));
    }
    if (!value || value.length > 253) throw new Error("Пустое или слишком длинное правило.");
    return { id: rule.id || crypto.randomUUID(), enabled: rule.enabled !== false, kind: rule.kind, value, action: rule.action };
  }

  function ipv4MappedHexToTuple(host) {
    const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
    if (!m) return null;
    const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
    return [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255];
  }

  function isLocalIpv4Tuple(a, b) {
    return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
  }

  function isLoopbackHost(host) {
    const h = unbracket(String(host || "")).toLowerCase();
    if (h === "localhost" || h.endsWith(".localhost") || h === "::1") return true;
    const mapped = ipv4MappedHexToTuple(h);
    if (mapped) return mapped[0] === 127;
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
    return Boolean(m && Number(m[1]) === 127);
  }

  function isLocal(host) {
    host = unbracket(host).toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || (!host.includes(".") && !host.includes(":"))) return true;
    if (host === "::1" || host === "::" || /^(fc|fd)[0-9a-f]{2}:|^fe[89ab][0-9a-f]:/i.test(host)) return true;
    const mapped = ipv4MappedHexToTuple(host);
    if (mapped) return isLocalIpv4Tuple(mapped[0], mapped[1]);
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
    if (!m) return false;
    return isLocalIpv4Tuple(Number(m[1]), Number(m[2]));
  }

  function actionFor(url, settings) {
    let u;
    try { u = new URL(url); } catch { return "direct"; }
    if (!["http:", "https:", "ws:", "wss:", "ftp:"].includes(u.protocol)) return "direct";
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    // Always keep the native loopback listener accessible; LAN bypass is optional.
    if (isLoopbackHost(host)) return "direct";
    if (settings.bypassLocal && isLocal(host)) return "direct";
    for (const r of settings.rules) {
      if (!r.enabled) continue;
      if ((r.kind === "domain" && host === r.value) || (r.kind === "suffix" && (host === r.value || host.endsWith(`.${r.value}`))) || (r.kind === "keyword" && host.includes(r.value))) return r.action;
    }
    return settings.mode === "global" ? "proxy" : settings.defaultAction;
  }

  function validateProbeUrl(rawUrl) {
    let u;
    try { u = new URL(String(rawUrl || "").trim()); } catch { throw new Error("Некорректный URL для проверки доступности."); }
    if (!["http:", "https:"].includes(u.protocol)) throw new Error("URL проверки должен использовать http:// или https://.");
    if (u.username || u.password) throw new Error("URL проверки не должен содержать логин или пароль.");
    if (!u.hostname || isLocal(u.hostname)) throw new Error("URL проверки не должен указывать на локальный адрес.");
    if (u.href.length > 512) throw new Error("URL проверки слишком длинный.");
    return u.href;
  }

  function validateSubscriptionUrl(rawUrl) {
    let u;
    try { u = new URL(String(rawUrl || "").trim()); } catch { throw new Error("Некорректный URL подписки."); }
    if (u.protocol !== "https:" || u.username || u.password) {
      throw new Error("Нужен HTTPS URL подписки без встроенных логина/пароля.");
    }
    if (!u.hostname || isLocal(u.hostname)) {
      throw new Error("URL подписки должен указывать на внешний HTTPS-сервер.");
    }
    if (u.href.length > 1024) throw new Error("URL подписки слишком длинный (максимум 1024 символа).");
    return u.href;
  }

  function maskSubscriptionUrl(rawUrl) {
    try {
      const u = new URL(rawUrl);
      const hasSecretPath = (u.pathname && u.pathname !== "/") || u.search;
      return `${u.protocol}//${u.host}${hasSecretPath ? "/•••" : ""}`;
    } catch {
      return "https://•••";
    }
  }

  function parseSubscriptionHeaders(headers, fallbackName = "") {
    const readHeader = name => {
      if (!headers) return "";
      if (typeof headers.get === "function") return headers.get(name) || "";
      const target = name.toLowerCase();
      for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === target) return String(v || "");
      }
      return "";
    };
    let title = String(fallbackName || "").trim();
    const rawTitle = readHeader("profile-title").trim();
    if (rawTitle) {
      try {
        if (/^base64:/i.test(rawTitle)) title = decode64(rawTitle.slice(7)).trim();
        else title = decodeFragment(rawTitle).trim();
      } catch {}
    }
    let info = null;
    const rawInfo = readHeader("subscription-userinfo").trim();
    if (rawInfo) {
      const parsed = {};
      for (const part of rawInfo.split(";")) {
        const eq = part.indexOf("=");
        if (eq < 1) continue;
        const key = part.slice(0, eq).trim().toLowerCase();
        const num = Number(part.slice(eq + 1).trim());
        if (["upload", "download", "total", "expire"].includes(key) && Number.isFinite(num) && num >= 0) {
          parsed[key] = Math.trunc(num);
        }
      }
      if (Object.keys(parsed).length) info = parsed;
    }
    return { title: title.slice(0, 160), info };
  }

  function mergeSubscriptionProfiles(existingProfiles, subscriptionId, parsedProfiles, existingSelectedId = "") {
    const oldSubProfiles = existingProfiles.filter(p => p.subscriptionId === subscriptionId);
    const others = existingProfiles.filter(p => p.subscriptionId !== subscriptionId);
    const otherIds = new Set(others.map(p => p.id));
    const byOutbound = new Map();
    const byName = new Map();
    for (const old of oldSubProfiles) {
      const obKey = JSON.stringify(old.outbound);
      if (!byOutbound.has(obKey)) byOutbound.set(obKey, []);
      byOutbound.get(obKey).push(old.id);
      if (!byName.has(old.name)) byName.set(old.name, []);
      byName.get(old.name).push(old.id);
    }

    const seenOutbounds = new Set();
    const deduped = [];
    for (const item of parsedProfiles) {
      const obKey = JSON.stringify(item.outbound);
      if (seenOutbounds.has(obKey)) continue;
      seenOutbounds.add(obKey);
      deduped.push({
        rawId: item.id,
        obKey,
        name: String(item.name || "").trim().slice(0, 160) || `${item.outbound.type} · ${item.outbound.server}`,
        outbound: structuredClone(item.outbound)
      });
    }

    const usedIds = new Set(otherIds);
    const takeUnused = queue => {
      while (queue && queue.length) {
        const candidate = queue.shift();
        if (!usedIds.has(candidate)) {
          usedIds.add(candidate);
          return candidate;
        }
      }
      return "";
    };

    const assignedIds = new Array(deduped.length).fill("");
    for (let i = 0; i < deduped.length; i++) {
      assignedIds[i] = takeUnused(byOutbound.get(deduped[i].obKey));
    }
    for (let i = 0; i < deduped.length; i++) {
      if (!assignedIds[i]) assignedIds[i] = takeUnused(byName.get(deduped[i].name));
    }

    const mergedSub = deduped.map((item, i) => {
      let id = assignedIds[i];
      if (!id) {
        id = item.rawId && !usedIds.has(item.rawId) ? item.rawId : crypto.randomUUID();
        usedIds.add(id);
      }
      return { id, name: item.name, outbound: item.outbound, subscriptionId };
    });

    const insertAt = existingProfiles.findIndex(p => p.subscriptionId === subscriptionId);
    const nextProfiles = insertAt < 0
      ? [...others, ...mergedSub]
      : [...others.slice(0, Math.min(insertAt, others.length)), ...mergedSub, ...others.slice(Math.min(insertAt, others.length))];

    const newIds = new Set(nextProfiles.map(p => p.id));
    let nextSelectedId = existingSelectedId;
    if (!nextSelectedId || !newIds.has(nextSelectedId)) {
      nextSelectedId = mergedSub[0]?.id || nextProfiles[0]?.id || "";
    }
    return { profiles: nextProfiles, selectedId: nextSelectedId, count: mergedSub.length };
  }

  function normalizeSubInfo(info) {
    if (!info || typeof info !== "object" || Array.isArray(info)) return null;
    const out = {};
    for (const key of ["upload", "download", "total", "expire"]) {
      if (info[key] !== undefined && info[key] !== null) {
        const n = Number(info[key]);
        if (Number.isFinite(n) && n >= 0) out[key] = Math.trunc(n);
      }
    }
    return Object.keys(out).length ? out : null;
  }

  function validateSettings(value) {
    if (!value || typeof value !== "object" || value.version !== 1) throw new Error("Неизвестная версия настроек.");
    const result = { ...defaults(), ...value };
    if (!["rules", "global"].includes(result.mode) || !["direct", "proxy", "block"].includes(result.defaultAction)) throw new Error("Некорректный режим маршрутизации.");
    result.port = port(result.port);
    if (result.port < 1024) throw new Error("Локальный порт должен быть не ниже 1024.");
    if (!Array.isArray(result.subscriptions) || result.subscriptions.length > 50) throw new Error("Слишком много подписок или неверный формат.");
    const subIds = new Set();
    result.subscriptions = result.subscriptions.map(s => {
      if (!s || typeof s.id !== "string" || !s.id || subIds.has(s.id) || typeof s.name !== "string" || !s.name.trim()) {
        throw new Error("Имена и ID подписок должны быть заполнены; ID уникальны.");
      }
      subIds.add(s.id);
      return {
        id: s.id,
        name: s.name.trim().slice(0, 160),
        url: validateSubscriptionUrl(s.url),
        updatedAt: typeof s.updatedAt === "string" ? s.updatedAt.slice(0, 64) : "",
        info: normalizeSubInfo(s.info)
      };
    });
    if (typeof result.subscriptionAutoUpdate !== "boolean") throw new Error("Некорректное поле subscriptionAutoUpdate.");
    if (!Array.isArray(result.profiles) || result.profiles.length > 500 || !Array.isArray(result.rules) || result.rules.length > 2000) throw new Error("Слишком много профилей/правил или неверный формат.");
    const ids = new Set();
    result.profiles = result.profiles.map(p => {
      if (!p || typeof p.id !== "string" || !p.id || ids.has(p.id) || typeof p.name !== "string" || !p.name.trim()) throw new Error("Имена и ID профилей должны быть заполнены; ID уникальны.");
      ids.add(p.id);
      const subId = typeof p.subscriptionId === "string" && subIds.has(p.subscriptionId) ? p.subscriptionId : "";
      return {
        id: p.id,
        name: p.name.trim().slice(0, 160),
        outbound: validateOutbound(structuredClone(p.outbound)),
        subscriptionId: subId
      };
    });
    if (result.selectedId && !ids.has(result.selectedId)) throw new Error("Выбранный профиль не найден.");
    result.rules = result.rules.map(normalizeRule);
    for (const key of ["killSwitch", "bypassLocal", "protectWebRTC", "autoConnect"]) if (typeof result[key] !== "boolean") throw new Error(`Некорректное поле ${key}.`);
    if (!["trace", "debug", "info", "warn", "error"].includes(result.logLevel)) throw new Error("Неизвестный уровень журнала.");
    if (!["remote", "doh"].includes(result.dnsMode)) throw new Error("Неизвестный DNS режим.");
    if (result.dnsMode === "doh") {
      const cleanIp = unbracket(String(result.dnsServer || "").trim());
      if (!isValidIp(cleanIp)) throw new Error("Для DoH нужен корректный IPv4 или IPv6 адрес DNS-сервера, например 1.1.1.1.");
      result.dnsServer = parseIpv6(cleanIp) || cleanIp;
      result.dnsServerName = normalizeDomain(result.dnsServerName);
      if (typeof result.dnsPath !== "string" || !result.dnsPath.startsWith("/") || /[\s\r\n]/.test(result.dnsPath) || result.dnsPath.length > 512) {
        throw new Error("Некорректный путь DoH.");
      }
    }
    if (!["system", "light", "dark"].includes(result.theme)) throw new Error("Неизвестная тема оформления.");
    result.probeUrl = validateProbeUrl(result.probeUrl);
    // Drop unknown top-level keys from imported backups.
    return Object.fromEntries(Object.keys(defaults()).map(k => [k, result[k]]));
  }

  root.FoxTunnel = {
    TYPES, defaults, decode64, parseLink, parseSubscription, validateOutbound,
    validateSettings, validateProbeUrl, validateSubscriptionUrl, maskSubscriptionUrl,
    parseSubscriptionHeaders, mergeSubscriptionProfiles,
    normalizeRule, normalizeDomain, actionFor, isLocal, isValidIp
  };
  if (typeof module !== "undefined") module.exports = root.FoxTunnel;
})(globalThis);
