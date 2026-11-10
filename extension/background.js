/* global browser, FoxTunnel */
"use strict";
let settings = FoxTunnel.defaults();
let wanted = false, running = false, busy = false, nativePort = null;
let lastError = "", coreStatus = {}, nextId = 0;
const pending = new Map(), events = [];
let resolveReady;
let isReady = false;
const ready = new Promise(resolve => { resolveReady = () => { isReady = true; resolve(); }; });
let operations = Promise.resolve();

function record(message) {
  events.push({ time: new Date().toISOString(), message });
  if (events.length > 120) events.shift();
}
function snapshot() {
  return { settings, wanted, running, busy, lastError, nativeConnected: !!nativePort, coreStatus, events };
}
function announce() {
  browser.browserAction.setBadgeText({ text: busy ? "…" : running ? "ON" : wanted ? "!" : "" }).catch(() => {});
  browser.browserAction.setBadgeBackgroundColor({ color: running ? "#246d55" : "#a43b32" }).catch(() => {});
  browser.runtime.sendMessage({ type: "stateChanged", state: snapshot() }).catch(() => {});
}
function teardownPort(port, errorMsg) {
  if (nativePort !== port) return;
  nativePort = null;
  running = false;
  coreStatus = {};
  for (const request of pending.values()) {
    clearTimeout(request.timer);
    request.reject(new Error(errorMsg));
  }
  pending.clear();
}
function connectNative() {
  if (nativePort) return nativePort;
  const port = browser.runtime.connectNative("io.foxtunnel.host");
  nativePort = port;
  port.onMessage.addListener(message => {
    const request = pending.get(message.id);
    if (!request) return;
    clearTimeout(request.timer);
    pending.delete(message.id);
    if (message.ok) request.resolve(message.result);
    else request.reject(new Error(message.error || "Ошибка локального помощника."));
  });
  port.onDisconnect.addListener(() => {
    if (nativePort !== port) return;
    const error = port.error?.message || "Соединение с локальным помощником закрыто. Проверьте установку native host.";
    teardownPort(port, error);
    if (wanted) { lastError = error; record(error); }
    announce();
  });
  return port;
}
function native(command, payload = {}, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    try {
      const port = connectNative();
      const timer = setTimeout(() => {
        pending.delete(id);
        const msg = "Локальный помощник не ответил вовремя.";
        // Disconnecting from JS does not fire onDisconnect; clear nativePort explicitly.
        if (nativePort === port) {
          try { port.disconnect(); } catch {}
          teardownPort(port, msg);
        }
        reject(new Error(msg));
      }, timeout);
      pending.set(id, { resolve, reject, timer });
      port.postMessage({ id, command, ...payload });
    } catch (error) {
      const request = pending.get(id);
      if (request) { clearTimeout(request.timer); pending.delete(id); }
      reject(error);
    }
  });
}
function coreConfigSettings(s) {
  return {
    port: s.port,
    logLevel: s.logLevel,
    dnsMode: s.dnsMode,
    dnsServer: s.dnsServer,
    dnsServerName: s.dnsServerName,
    dnsPath: s.dnsPath,
    rules: s.rules,
    mode: s.mode,
    defaultAction: s.defaultAction,
    geo: s.geo
  };
}
function payload() {
  const profile = settings.profiles.find(p => p.id === settings.selectedId);
  if (!profile) throw new Error("Сначала добавьте и выберите профиль в настройках.");
  return {
    outbound: profile.outbound,
    settings: coreConfigSettings(settings)
  };
}
async function privacy(active) {
  const network = browser.privacy.network;
  // clear() restores the browser/user's prior setting instead of guessing it.
  if (active && settings.protectWebRTC) {
    await network.webRTCIPHandlingPolicy.set({ value: "disable_non_proxied_udp" });
  } else await network.webRTCIPHandlingPolicy.clear({});
  if (active) await network.networkPredictionEnabled.set({ value: false });
  else await network.networkPredictionEnabled.clear({});
}
async function start() {
  let data;
  try {
    data = payload();
  } catch (e) {
    if (nativePort && running) await native("stop", {}, 5000).catch(() => {});
    running = false;
    coreStatus = {};
    lastError = e.message;
    announce();
    throw e;
  }
  wanted = true; running = false; busy = true; lastError = "";
  await browser.storage.local.set({ wanted });
  announce();
  try {
    await privacy(true);
    coreStatus = await native("start", data);
    running = coreStatus.running === true;
    if (!running) throw new Error("Ядро не запущено.");
    record("Ядро запущено. Доступность удалённого VPN-сервера не проверяется автоматически.");
  } catch (e) {
    lastError = e.message;
    running = false;
    record(lastError);
    throw e;
  } finally {
    busy = false;
    announce();
  }
}
async function stop() {
  // Keep fail-closed routing until the requested stop has completed.
  busy = true;
  announce();
  try {
    if (nativePort) {
      try {
        await native("stop", {}, 10000);
      } catch {
        const port = nativePort;
        if (port) {
          try { port.disconnect(); } catch {}
          teardownPort(port, "Остановка подключения");
        }
      }
    }
  } finally {
    wanted = false; running = false; busy = false; coreStatus = {}; lastError = "";
    await browser.storage.local.set({ wanted });
    await privacy(false).catch(e => { lastError = e.message; });
    record("Отключено вручную: браузер использует обычное соединение.");
    announce();
  }
}
function coreSignature(s) {
  const active = s.profiles.find(p => p.id === s.selectedId);
  return JSON.stringify({
    outbound: active ? active.outbound : null,
    ...coreConfigSettings(s)
  });
}
async function save(value) {
  const previousSig = coreSignature(settings);
  const previousWebRTC = settings.protectWebRTC;
  settings = FoxTunnel.validateSettings(value);
  await browser.storage.local.set({ settings });
  if (wanted) {
    if (!running || coreSignature(settings) !== previousSig) {
      await start();
    } else {
      if (settings.protectWebRTC !== previousWebRTC) await privacy(true);
      announce();
    }
  } else {
    announce();
  }
  return snapshot();
}
function safeSubHost(rawUrl) {
  try { return new URL(rawUrl).hostname; } catch { return "подписка"; }
}
async function fetchSubscriptionPayload(rawUrl) {
  const url = FoxTunnel.validateSubscriptionUrl(rawUrl);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    let response;
    try {
      response = await fetch(url, {
        signal: controller.signal,
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer"
      });
    } catch (err) {
      if (err?.name === "AbortError") throw new Error("Таймаут загрузки подписки (20 секунд).");
      throw new Error(`Не удалось загрузить подписку (${safeSubHost(url)}): сетевая ошибка или запрещённый редирект.`);
    }
    if (!response.ok) throw new Error(`Сервер подписки ответил HTTP ${response.status}`);
    if (!response.body) throw new Error("Сервер подписки вернул пустой ответ.");
    const reader = response.body.getReader();
    let total = 0;
    const chunks = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 1048576) {
        await reader.cancel();
        throw new Error("Подписка больше 1 МБ.");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder().decode(bytes);
    const profiles = FoxTunnel.parseSubscription(text);
    const meta = FoxTunnel.parseSubscriptionHeaders(response.headers, safeSubHost(url));
    return { url, profiles, title: meta.title, info: meta.info };
  } finally {
    clearTimeout(timer);
  }
}

async function applySubscriptionRefresh(subId) {
  const index = settings.subscriptions.findIndex(s => s.id === subId);
  if (index < 0) throw new Error("Подписка не найдена.");
  const target = settings.subscriptions[index];
  const fetched = await fetchSubscriptionPayload(target.url);
  const nextSubs = structuredClone(settings.subscriptions);
  const host = safeSubHost(target.url);
  const nextName = (target.name === host && fetched.title) ? fetched.title : target.name;
  nextSubs[index] = {
    ...target,
    name: nextName,
    updatedAt: new Date().toISOString(),
    info: fetched.info
  };
  const merged = FoxTunnel.mergeSubscriptionProfiles(settings.profiles, target.id, fetched.profiles, settings.selectedId);
  await save({
    ...settings,
    subscriptions: nextSubs,
    profiles: merged.profiles,
    selectedId: merged.selectedId
  });
  record(`Подписка «${nextName}» обновлена (${merged.count} серв.).`);
  return { count: merged.count, name: nextName, state: snapshot() };
}

async function refreshAllSubs(onlyStale = false) {
  const ids = settings.subscriptions
    .filter(s => {
      if (!onlyStale) return true;
      const ts = Date.parse(s.updatedAt || "");
      return !Number.isFinite(ts) || (Date.now() - ts) >= 24 * 60 * 60 * 1000;
    })
    .map(s => s.id);
  let updated = 0;
  const errors = [];
  for (const id of ids) {
    const sub = settings.subscriptions.find(s => s.id === id);
    if (!sub) continue;
    try {
      await applySubscriptionRefresh(id);
      updated++;
    } catch (e) {
      const msg = `${sub.name}: ${e.message}`;
      errors.push(msg);
      record(`Ошибка обновления подписки «${sub.name}»: ${e.message}`);
    }
  }
  announce();
  return { updated, total: ids.length, errors, state: snapshot() };
}

function enqueue(fn) {
  const result = operations.then(fn, fn);
  operations = result.catch(() => {});
  return result;
}

function decideProxy(details) {
  if (!wanted) return { type: "direct" };
  const action = FoxTunnel.routePolicy(details.url, settings);
  if (action === "direct") return { type: "direct" };
  if (action === "block" || (!running && settings.killSwitch)) {
    // No DIRECT fallback. The core also enforces the saved block/geo rules.
    return { type: "socks", host: "127.0.0.1", port: settings.port, proxyDNS: true };
  }
  if (!running) return { type: "direct" };
  return { type: "socks", host: "127.0.0.1", port: settings.port, proxyDNS: true };
}
function decideBeforeRequest(details) {
  if (!wanted) return {};
  const action = FoxTunnel.routePolicy(details.url, settings);
  return { cancel: action === "block" || ((action === "proxy" || action === "core") && !running && settings.killSwitch) };
}

// Registered before loading storage to avoid a direct-connect startup window.
browser.proxy.onRequest.addListener(details => {
  if (!isReady) return ready.then(() => decideProxy(details));
  return decideProxy(details);
}, { urls: ["<all_urls>"] });

browser.webRequest.onBeforeRequest.addListener(details => {
  if (!isReady) return ready.then(() => decideBeforeRequest(details));
  return decideBeforeRequest(details);
}, { urls: ["<all_urls>"] }, ["blocking"]);

browser.proxy.onError.addListener(error => {
  lastError = error.message;
  record(`Firefox proxy: ${error.message}`);
  announce();
});

function mergeGeoMeta(src, info, overrides = {}) {
  return {
    ...src,
    ...overrides,
    path: info.path,
    fileName: info.fileName || src.fileName || "",
    format: info.format || src.format || "",
    updatedAt: info.updatedAt || new Date().toISOString(),
    size: info.size || 0,
    tagsCount: Number.isInteger(info.tagsCount) ? info.tagsCount : (src.tagsCount || 0),
    sampleTags: Array.isArray(info.sampleTags) ? info.sampleTags : (src.sampleTags || [])
  };
}

browser.runtime.onMessage.addListener(message => {
  if (!message || message.type === "stateChanged") return undefined;
  return ready.then(() => {
    if (message.type === "getState") return { ok: true, result: snapshot() };
    if (message.type === "routePreview") {
      const targetSettings = message.settings ? FoxTunnel.validateSettings({ ...settings, ...message.settings }) : settings;
      return { ok: true, result: FoxTunnel.routePolicy(message.url, targetSettings) };
    }
    return enqueue(async () => {
      try {
        let result;
        if (message.type === "connect") { await start(); result = snapshot(); }
        else if (message.type === "disconnect") { await stop(); result = snapshot(); }
        else if (message.type === "saveSettings") result = await save(message.settings);
        else if (message.type === "diagnostics") {
          coreStatus = await native("status");
          const proxyControl = await browser.proxy.settings.get({});
          const webRtcPolicy = await browser.privacy.network.webRTCIPHandlingPolicy.get({});
          result = {
            ...coreStatus,
            wanted,
            mode: settings.mode,
            defaultAction: settings.defaultAction,
            activeProxyRules: settings.rules.filter(r => r.enabled && r.action === "proxy").length,
            killSwitch: settings.killSwitch,
            dnsMode: settings.dnsMode,
            proxyControl: proxyControl.levelOfControl,
            proxyType: proxyControl.value?.proxyType,
            webRtcPolicy: webRtcPolicy.value,
            webRtcControl: webRtcPolicy.levelOfControl
          };
          announce();
        } else if (message.type === "logs") result = await native("logs");
        else if (message.type === "checkProfile") {
          result = await native("check", {
            outbound: message.outbound,
            settings: coreConfigSettings(settings)
          });
        } else if (message.type === "probeProfile") {
          result = await native("probe", {
            outbound: message.outbound,
            probeUrl: message.probeUrl || settings.probeUrl,
            settings: {
              dnsMode: settings.dnsMode,
              dnsServer: settings.dnsServer,
              dnsServerName: settings.dnsServerName,
              dnsPath: settings.dnsPath
            }
          }, 20000);
        } else if (message.type === "addSubscription") {
          const fetched = await fetchSubscriptionPayload(message.url);
          const customName = String(message.name || "").trim().slice(0, 160);
          if (message.save === false) {
            let added = 0;
            const nextProfiles = structuredClone(settings.profiles);
            const existing = new Set(nextProfiles.map(p => JSON.stringify(p.outbound)));
            for (const p of fetched.profiles) {
              const key = JSON.stringify(p.outbound);
              if (!existing.has(key)) {
                nextProfiles.push({ ...p, subscriptionId: "" });
                existing.add(key);
                added++;
              }
            }
            const nextSelected = settings.selectedId || nextProfiles[0]?.id || "";
            await save({ ...settings, profiles: nextProfiles, selectedId: nextSelected });
            result = { added, count: fetched.profiles.length, saved: false, state: snapshot() };
          } else {
            const existingSub = settings.subscriptions.find(s => s.url === fetched.url);
            const subId = existingSub ? existingSub.id : crypto.randomUUID();
            const subName = customName || (existingSub && existingSub.name) || fetched.title || safeSubHost(fetched.url);
            const nextSub = {
              id: subId,
              name: subName,
              url: fetched.url,
              updatedAt: new Date().toISOString(),
              info: fetched.info
            };
            const nextSubs = existingSub
              ? settings.subscriptions.map(s => (s.id === subId ? nextSub : s))
              : [...settings.subscriptions, nextSub];
            const merged = FoxTunnel.mergeSubscriptionProfiles(settings.profiles, subId, fetched.profiles, settings.selectedId);
            await save({
              ...settings,
              subscriptions: nextSubs,
              profiles: merged.profiles,
              selectedId: merged.selectedId
            });
            record(`Подписка «${subName}» ${existingSub ? "обновлена" : "сохранена"} (${merged.count} серв.).`);
            result = { count: merged.count, name: subName, saved: true, updatedExisting: Boolean(existingSub), state: snapshot() };
          }
        } else if (message.type === "refreshSubscription") {
          result = await applySubscriptionRefresh(message.id);
        } else if (message.type === "refreshAllSubscriptions") {
          result = await refreshAllSubs(false);
        } else if (message.type === "renameSubscription") {
          const cleanName = String(message.name || "").trim().slice(0, 160);
          if (!cleanName) throw new Error("Укажите название подписки.");
          const exists = settings.subscriptions.some(s => s.id === message.id);
          if (!exists) throw new Error("Подписка не найдена.");
          const nextSubs = settings.subscriptions.map(s => (s.id === message.id ? { ...s, name: cleanName } : s));
          result = await save({ ...settings, subscriptions: nextSubs });
        } else if (message.type === "deleteSubscription") {
          const keep = Boolean(message.keepProfiles);
          const activeProfile = settings.profiles.find(p => p.id === settings.selectedId);
          if (!keep && wanted && activeProfile?.subscriptionId === message.id) {
            throw new Error("Нельзя удалить подписку с активным сервером, пока VPN включён. Сначала отключите подключение или выберите другой профиль.");
          }
          const nextSubs = settings.subscriptions.filter(s => s.id !== message.id);
          const nextProfiles = keep
            ? settings.profiles.map(p => (p.subscriptionId === message.id ? { ...p, subscriptionId: "" } : p))
            : settings.profiles.filter(p => p.subscriptionId !== message.id);
          const nextSelected = nextProfiles.some(p => p.id === settings.selectedId)
            ? settings.selectedId
            : (nextProfiles[0]?.id || "");
          result = await save({
            ...settings,
            subscriptions: nextSubs,
            profiles: nextProfiles,
            selectedId: nextSelected
          });
        } else if (message.type === "geoStatus") {
          result = await native("geo_status", { geo: message.geo || settings.geo }, 10000);
        } else if (message.type === "geoInspect") {
          result = await native("geo_inspect", { path: message.path, target: message.target || "" }, 15000);
        } else if (message.type === "geoUpdate") {
          const validatedGeo = FoxTunnel.validateGeoSettings(message.geo || settings.geo);
          const res = await native("geo_update", {
            targets: message.targets,
            ruleSetIds: message.ruleSetIds || [],
            geo: validatedGeo
          }, 65000);
          const nextGeo = structuredClone(settings.geo);
          nextGeo.updateViaProxy = validatedGeo.updateViaProxy;
          if (res.geoip) nextGeo.geoip = mergeGeoMeta(validatedGeo.geoip, res.geoip);
          if (res.geosite) nextGeo.geosite = mergeGeoMeta(validatedGeo.geosite, res.geosite);
          if (res.ruleSets && typeof res.ruleSets === "object") {
            const byId = new Map(nextGeo.ruleSets.map(r => [r.id, r]));
            for (const rs of validatedGeo.ruleSets) {
              if (res.ruleSets[rs.id]) {
                byId.set(rs.id, mergeGeoMeta(rs, res.ruleSets[rs.id], { format: res.ruleSets[rs.id].format === "json" ? "source" : "binary" }));
              }
            }
            nextGeo.ruleSets = Array.from(byId.values());
          }
          await save({ ...settings, geo: nextGeo });
          result = { ...res, geo: settings.geo, state: snapshot() };
        } else if (message.type === "geoUploadBegin") {
          result = await native("geo_upload_begin", {
            target: message.target,
            fileName: message.fileName,
            totalSize: message.totalSize,
            ruleSetId: message.ruleSetId || ""
          }, 15000);
        } else if (message.type === "geoUploadChunk") {
          result = await native("geo_upload_chunk", {
            uploadId: message.uploadId,
            data: message.data
          }, 15000);
        } else if (message.type === "geoUploadFinish") {
          const info = await native("geo_upload_finish", { uploadId: message.uploadId }, 30000);
          if (message.autoSave && (message.target === "geoip" || message.target === "geosite")) {
            const nextGeo = structuredClone(settings.geo);
            nextGeo[message.target] = mergeGeoMeta(nextGeo[message.target], info, { sourceType: "local" });
            await save({ ...settings, geo: nextGeo });
          }
          result = { info, geo: settings.geo, state: snapshot() };
        } else throw new Error("Неизвестная команда расширения.");
        return { ok: true, result };
      } catch (e) {
        if (![
          "checkProfile", "probeProfile", "addSubscription", "refreshSubscription",
          "refreshAllSubscriptions", "renameSubscription", "deleteSubscription",
          "geoStatus", "geoInspect", "geoUpdate", "geoUploadBegin", "geoUploadChunk", "geoUploadFinish"
        ].includes(message.type)) {
          lastError = e.message;
          announce();
        }
        return { ok: false, error: e.message };
      }
    });
  });
});

async function boot() {
  try {
    const saved = await browser.storage.local.get(["settings", "wanted"]);
    settings = FoxTunnel.validateSettings(saved.settings || FoxTunnel.defaults());
    wanted = saved.wanted === true || (settings.autoConnect && Boolean(settings.selectedId));
  } catch (e) {
    // Corrupted settings must not silently turn a previously enabled VPN off.
    wanted = true;
    settings.mode = "global";
    lastError = `Не удалось загрузить настройки: ${e.message}`;
    record(lastError);
  } finally {
    resolveReady();
    announce();
  }
  if (wanted && !lastError) enqueue(start).catch(() => {});
  else await privacy(wanted).catch(e => { lastError = e.message; announce(); });
  if (settings.subscriptionAutoUpdate && settings.subscriptions.length) {
    setTimeout(() => {
      if (settings.subscriptionAutoUpdate && settings.subscriptions.length) {
        enqueue(() => refreshAllSubs(true)).catch(() => {});
      }
    }, 5000);
  }
}

setInterval(() => {
  if (settings.subscriptionAutoUpdate && settings.subscriptions.length && !busy) {
    enqueue(() => refreshAllSubs(true)).catch(() => {});
  }
}, 60 * 60 * 1000);

setInterval(() => {
  if (!nativePort || busy || !wanted || !running) return;
  enqueue(async () => {
    if (!nativePort || busy || !wanted || !running) return;
    try {
      coreStatus = await native("status", {}, 5000);
      const stillRunning = coreStatus.running === true;
      if (!stillRunning) {
        running = false;
        lastError = "Ядро остановилось. Защищаемые запросы блокируются, если включён kill switch. Нажмите «Подключить» или отключите VPN.";
        record(lastError);
      }
      announce();
    } catch (e) {
      if (running) {
        running = false;
        lastError = e.message;
        record(lastError);
        announce();
      }
    }
  });
}, 5000);

boot();
