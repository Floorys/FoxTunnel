/* global browser, FoxTunnel */
"use strict";
const $ = id => document.getElementById(id);
let savedSettings = FoxTunnel.defaults();
let routingRules = [];
let routingGeo = FoxTunnel.defaults().geo;
let geoDiskStatus = null;
let currentState = null;
let editId = "";
let dirtyRouting = false;
let dirtySecurity = false;
let dirtyEditor = false;
let probeAllAborted = false;
let probeAllRunning = false;
const probeResults = new Map();

const labels = {
  proxy: "VPN", direct: "Напрямую", block: "Блокировать",
  core: "Решает ядро (GeoIP / Geosite / CIDR / Rule-Set)",
  domain: "Точно", suffix: "Домен + поддомены", keyword: "Подстрока",
  cidr: "IP / CIDR", geoip: "GeoIP", geosite: "Geosite", ruleset: "Rule-Set"
};
const ruleKindHints = {
  suffix: { label: "Домен или поддомены", placeholder: "example.com" },
  domain: { label: "Точный домен", placeholder: "api.example.com" },
  keyword: { label: "Подстрока в домене", placeholder: "yandex" },
  cidr: { label: "IP или CIDR подсеть", placeholder: "192.168.0.0/16 или 1.1.1.1" },
  geosite: { label: "Категория Geosite (можно с @атрибутом)", placeholder: "youtube, category-ads-all, google@!cn" },
  geoip: { label: "Код страны или тег GeoIP", placeholder: "ru, private, cloudflare" },
  ruleset: { label: "Тег дополнительного Rule-Set", placeholder: "ru-blocked" }
};
const GEO_PRESETS = {
  geoip: {
    loyal: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    runet: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"
  },
  geosite: {
    loyal: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    runet: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"
  }
};
const themeLabels = { system: "Тема: Авто", light: "Тема: Светлая", dark: "Тема: Тёмная" };
const themeOrder = ["system", "dark", "light"];
const routingFields = ["mode", "defaultAction", "bypassLocal"];
const securityFields = [
  "killSwitch", "protectWebRTC", "autoConnect", "port", "logLevel",
  "theme", "probeUrl", "dnsMode", "dnsServer", "dnsServerName", "dnsPath"
];

function formatBytes(n) {
  if (!n || n < 0) return "";
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
  return `${(n / (1024 * 1024)).toFixed(2)} МБ`;
}
function formatIsoShort(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("ru-RU");
}
function bytesToBase64(bytes) {
  let out = "";
  const step = 8192;
  for (let i = 0; i < bytes.length; i += step) {
    out += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(out);
}
async function uploadGeoFile(file, target, ruleSetId = "") {
  if (!file) throw new Error("Файл не выбран.");
  if (file.size <= 0 || file.size > 64 * 1024 * 1024) throw new Error("Размер файла должен быть от 1 байта до 64 МБ.");
  const begin = await send("geoUploadBegin", { target, fileName: file.name, totalSize: file.size, ruleSetId });
  const chunkSize = 256 * 1024;
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const buf = await file.slice(offset, Math.min(file.size, offset + chunkSize)).arrayBuffer();
    await send("geoUploadChunk", { uploadId: begin.uploadId, data: bytesToBase64(new Uint8Array(buf)) });
  }
  const finished = await send("geoUploadFinish", { uploadId: begin.uploadId, target, ruleSetId, autoSave: false });
  return finished.info;
}
async function send(type, extra = {}) {
  const reply = await browser.runtime.sendMessage({ type, ...extra });
  if (!reply.ok) throw new Error(reply.error);
  return reply.result;
}
function toast(text, error = false) {
  $("toast").hidden = false;
  $("toast").textContent = text;
  $("toast").className = `toast${error ? " error" : ""}`;
}
function handle(id, fn) {
  $(id).addEventListener("click", async () => {
    $(id).disabled = true;
    try { await fn(); }
    catch (e) { toast(e.message, true); }
    finally { $(id).disabled = false; }
  });
}
function updateThemeUi(mode) {
  const applied = window.applyFoxTunnelTheme?.(mode) || mode || "system";
  $("themeToggle").textContent = themeLabels[applied] || themeLabels.system;
}
function updateDirtyIndicators() {
  const msg = dirtyRouting ? "Есть несохранённые изменения маршрутизации или Geo-баз." : "Изменения правил и Geo-баз применяются после сохранения.";
  const cls = dirtyRouting ? "fine dirty-note" : "fine";
  $("routingStatus").textContent = msg;
  $("routingStatus").className = cls;
  if ($("geoSaveNote")) {
    $("geoSaveNote").textContent = msg;
    $("geoSaveNote").className = cls;
  }
  const s = $("securityStatus");
  s.textContent = dirtySecurity
    ? "Есть несохранённые изменения сети и защиты."
    : "Изменения ядра перезапустят активный процесс; смена темы применяется без разрыва.";
  s.className = dirtySecurity ? "fine dirty-note" : "fine";
}
function status(state) {
  currentState = state;
  const label = state.busy
    ? "Запускается…"
    : state.running
      ? `Работает · SOCKS5 127.0.0.1:${state.settings.port}`
      : state.wanted
        ? "Ошибка (kill switch)"
        : "Отключено";
  $("connectionStatus").textContent = label;
  $("events").textContent = state.events.map(e => `${e.time}  ${e.message}`).join("\n") || "Нет событий.";
  const showBanner = Boolean(state.wanted && !state.running && !state.busy);
  $("killSwitchBanner").hidden = !showBanner;
  if (showBanner) {
    $("killSwitchError").textContent = state.lastError || "Ядро не запущено. Защищаемые запросы заблокированы.";
  }
  if (!dirtySecurity) updateThemeUi(state.settings.theme);
}
function button(text, action, className = "", disabled = false) {
  const b = document.createElement("button");
  b.textContent = text;
  b.className = className;
  b.disabled = disabled;
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await action(); }
    catch (e) { toast(e.message, true); }
    finally { b.disabled = disabled; }
  });
  return b;
}
function empty(text) {
  const e = document.createElement("div");
  e.className = "empty";
  e.textContent = text;
  return e;
}
async function runSingleProbe(profile) {
  const sig = JSON.stringify(profile.outbound);
  probeResults.set(profile.id, { state: "wait", sig, text: "Проверка…" });
  renderProfiles();
  try {
    const res = await send("probeProfile", { outbound: profile.outbound });
    probeResults.set(profile.id, {
      state: "ok",
      sig,
      text: `Доступен · ${res.latencyMs} мс (HTTP ${res.status}, ${res.host})`
    });
  } catch (e) {
    probeResults.set(profile.id, {
      state: "err",
      sig,
      text: `Недоступен: ${e.message}`
    });
  }
  renderProfiles();
}
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "";
  const gb = bytes / (1024 ** 3);
  if (gb >= 1) return `${gb.toFixed(gb >= 100 ? 0 : 1)} ГБ`;
  const mb = bytes / (1024 ** 2);
  return `${mb.toFixed(0)} МБ`;
}
function formatSubInfo(info) {
  if (!info) return "";
  const parts = [];
  const used = (info.upload || 0) + (info.download || 0);
  if (info.total > 0) parts.push(`${formatBytes(used)} / ${formatBytes(info.total)}`);
  else if (used > 0) parts.push(`использовано ${formatBytes(used)}`);
  if (info.expire > 0) {
    const dt = new Date(info.expire * 1000);
    if (!Number.isNaN(dt.getTime())) parts.push(`до ${dt.toLocaleDateString("ru-RU")}`);
  }
  return parts.join(" · ");
}
function renderSubscriptions() {
  const list = $("subscriptions");
  list.replaceChildren();
  const subs = savedSettings.subscriptions || [];
  $("refreshAllSubs").disabled = !subs.length;
  $("subscriptionAutoUpdate").checked = Boolean(savedSettings.subscriptionAutoUpdate);
  if (!subs.length) {
    list.append(empty("Сохранённых подписок пока нет. Загрузите URL ниже с галочкой «Сохранить подписку», чтобы обновлять серверы в один клик."));
    return;
  }
  for (const s of subs) {
    const item = document.createElement("div");
    item.className = "list-item";
    const info = document.createElement("div");
    info.className = "info";
    const name = document.createElement("strong");
    name.textContent = s.name;
    const count = savedSettings.profiles.filter(p => p.subscriptionId === s.id).length;
    const updated = s.updatedAt ? new Date(s.updatedAt).toLocaleString("ru-RU") : "не обновлялась";
    const meta = [FoxTunnel.maskSubscriptionUrl(s.url), `серверов: ${count}`, updated];
    const traffic = formatSubInfo(s.info);
    if (traffic) meta.push(traffic);
    const sub = document.createElement("small");
    sub.textContent = meta.join(" · ");
    info.append(name, sub);
    item.append(info);
    item.append(button("Обновить", async () => {
      const res = await send("refreshSubscription", { id: s.id });
      savedSettings = structuredClone(res.state.settings);
      status(res.state);
      fillAll(false);
      toast(`Подписка «${res.name}» обновлена (${res.count} серв.).`);
    }));
    item.append(button("Переименовать", async () => {
      const nextName = prompt("Новое название подписки:", s.name);
      if (nextName === null) return;
      const state = await send("renameSubscription", { id: s.id, name: nextName });
      savedSettings = structuredClone(state.settings);
      status(state);
      fillAll(false);
      toast("Название подписки обновлено.");
    }));
    item.append(button("Удалить", async () => {
      if (!confirm(`Удалить подписку «${s.name}» и все её серверы (${count})?`)) return;
      const state = await send("deleteSubscription", { id: s.id, keepProfiles: false });
      savedSettings = structuredClone(state.settings);
      status(state);
      fillAll(false);
      toast("Подписка удалена.");
    }, "danger"));
    list.append(item);
  }
}
function renderProfiles() {
  const list = $("profiles");
  list.replaceChildren();
  $("probeAll").disabled = probeAllRunning || !savedSettings.profiles.length;
  if (!savedSettings.profiles.length) {
    list.append(empty("Пока нет серверов. Добавьте ссылку ниже, затем установите локальный помощник."));
  }
  const subNames = new Map((savedSettings.subscriptions || []).map(s => [s.id, s.name]));
  for (const p of savedSettings.profiles) {
    const item = document.createElement("div");
    item.className = `list-item${p.id === savedSettings.selectedId ? " selected" : ""}`;
    const info = document.createElement("div");
    info.className = "info";
    const name = document.createElement("strong");
    name.textContent = p.name;
    const sub = document.createElement("small");
    const subLabel = p.subscriptionId && subNames.has(p.subscriptionId) ? `Подписка: ${subNames.get(p.subscriptionId)} · ` : "";
    sub.textContent = `${subLabel}${p.outbound.type} · ${p.outbound.server}:${p.outbound.server_port}${p.outbound.tls?.insecure ? " · TLS без проверки сертификата!" : ""}`;
    info.append(name, sub);

    const probe = probeResults.get(p.id);
    if (probe && probe.sig === JSON.stringify(p.outbound)) {
      const badge = document.createElement("span");
      badge.className = `probe-status ${probe.state}`;
      badge.textContent = probe.text;
      info.append(badge);
    }

    item.append(info);
    item.append(button(
      p.id === savedSettings.selectedId ? "Выбран" : "Выбрать",
      async () => {
        if (p.id === savedSettings.selectedId) return;
        await saveMerged({ selectedId: p.id }, "Профиль выбран.");
      },
      "",
      p.id === savedSettings.selectedId
    ));
    item.append(button(
      "Проверить",
      () => runSingleProbe(p),
      "",
      probeAllRunning || probe?.state === "wait"
    ));
    item.append(button("Изменить", () => {
      if (dirtyEditor && !confirm("В редакторе профиля есть несохранённые изменения. Заменить их?")) return;
      editId = p.id;
      $("profileName").value = p.name;
      $("outbound").value = JSON.stringify(p.outbound, null, 2);
      $("editorTitle").textContent = "Редактирование профиля";
      $("editorProbeLine").textContent = "";
      $("editorProbeLine").className = "probe-line";
      dirtyEditor = false;
      $("profileName").focus();
    }));
    item.append(button("Удалить", async () => {
      if (currentState?.wanted && p.id === savedSettings.selectedId) {
        throw new Error("Нельзя удалить активный профиль, пока подключение включено. Сначала отключите VPN или выберите другой профиль.");
      }
      if (!confirm(`Удалить профиль «${p.name}»?`)) return;
      probeResults.delete(p.id);
      const nextProfiles = savedSettings.profiles.filter(v => v.id !== p.id);
      const nextSelected = savedSettings.selectedId === p.id ? (nextProfiles[0]?.id || "") : savedSettings.selectedId;
      if (editId === p.id) resetEditor(true);
      await saveMerged({ profiles: nextProfiles, selectedId: nextSelected }, "Профиль удалён.");
    }, "danger"));
    list.append(item);
  }
}
function geoSourceIssue(r) {
  if (r.kind === "geoip" || r.kind === "geosite") {
    const src = routingGeo[r.kind];
    if (!src || src.sourceType === "none") return `настройте ${labels[r.kind]}`;
    if (src.sourceType === "remote" && !src.path) return `скачайте ${labels[r.kind]}`;
    const disk = geoDiskStatus?.[r.kind];
    if (disk && src.path && disk.exists === false) return "файл не найден на диске";
  } else if (r.kind === "ruleset") {
    const rs = (routingGeo.ruleSets || []).find(item => item.tag === r.value && item.enabled !== false);
    if (!rs) return `добавьте Rule-Set «${r.value}»`;
    if (rs.sourceType === "remote" && !rs.path) return "скачайте Rule-Set";
    const disk = geoDiskStatus?.ruleSets?.[rs.id];
    if (disk && rs.path && disk.exists === false) return "файл Rule-Set не найден";
  }
  return "";
}

function renderRules() {
  const list = $("rules");
  list.replaceChildren();
  if (!routingRules.length) {
    list.append(empty("Нет правил. В режиме «По правилам» без правил весь трафик идёт напрямую: добавьте правило с действием «VPN» и сохраните, либо выберите режим «Весь веб-трафик»."));
  }
  routingRules.forEach((r, i) => {
    const item = document.createElement("div");
    item.className = "list-item";
    const enabled = document.createElement("input");
    enabled.type = "checkbox";
    enabled.checked = r.enabled;
    enabled.setAttribute("aria-label", `Включить правило ${r.value}`);
    enabled.addEventListener("change", () => {
      r.enabled = enabled.checked;
      dirtyRouting = true;
      updateDirtyIndicators();
    });
    const info = document.createElement("div");
    info.className = "info";
    const name = document.createElement("strong");
    name.textContent = `${i + 1}. ${r.value}`;
    const sub = document.createElement("small");
    const issue = r.enabled ? geoSourceIssue(r) : "";
    sub.textContent = `${labels[r.kind] || r.kind} → ${labels[r.action]}${issue ? ` · ⚠ ${issue}` : ""}`;
    info.append(name, sub);
    item.append(enabled, info);
    const move = direction => {
      const target = i + direction;
      if (target < 0 || target >= routingRules.length) return;
      [routingRules[i], routingRules[target]] = [routingRules[target], routingRules[i]];
      dirtyRouting = true;
      updateDirtyIndicators();
      renderRules();
    };
    item.append(
      button("↑", () => move(-1), "", i === 0),
      button("↓", () => move(1), "", i === routingRules.length - 1),
      button("Удалить", () => {
        routingRules.splice(i, 1);
        dirtyRouting = true;
        updateDirtyIndicators();
        renderRules();
      }, "danger")
    );
    list.append(item);
  });
}

function renderGeoMeta(kind) {
  const src = routingGeo[kind] || FoxTunnel.DEFAULT_GEO_SOURCE();
  const el = $(`${kind}Meta`);
  const disk = geoDiskStatus?.[kind];
  if (src.sourceType === "none") {
    el.textContent = "Источник не выбран.";
    el.className = "geo-meta";
    return;
  }
  if (src.sourceType === "remote" && !src.path) {
    el.textContent = src.url
      ? "Удалённая база ещё не скачана. Нажмите «Обновить» справа, чтобы загрузить файл."
      : "Укажите HTTPS-ссылку (или выберите пресет) и нажмите «Обновить».";
    el.className = "geo-meta warn";
    return;
  }
  if (src.sourceType === "local" && !src.path) {
    el.textContent = "Укажите путь к файлу .dat/.srs/.json или выберите файл с диска.";
    el.className = "geo-meta warn";
    return;
  }
  if (disk && src.path && disk.exists === false) {
    el.textContent = `Файл отсутствует на диске: ${disk.error || src.path}`;
    el.className = "geo-meta warn";
    return;
  }
  const parts = [];
  if (src.fileName || src.path) parts.push(src.fileName || src.path.split(/[\\/]/).pop());
  if (src.format) parts.push(`.${src.format}`);
  if (src.tagsCount > 0) parts.push(`${src.tagsCount} категорий`);
  if (src.size > 0) parts.push(formatBytes(src.size));
  if (src.updatedAt) parts.push(`обновлено ${formatIsoShort(src.updatedAt)}`);
  el.textContent = parts.length ? parts.join(" · ") : src.path;
  el.className = "geo-meta ok";
}

function syncGeoBoxes(kind) {
  const type = $(`${kind}SourceType`).value;
  $(`${kind}RemoteBox`).hidden = type !== "remote";
  $(`${kind}LocalBox`).hidden = type !== "local";
}

function renderRuleSets() {
  const list = $("ruleSetsList");
  list.replaceChildren();
  const items = routingGeo.ruleSets || [];
  if (!items.length) {
    list.append(empty("Нет дополнительных Rule-Set списков. Добавьте .srs или .json ниже при необходимости."));
    return;
  }
  items.forEach((rs, idx) => {
    const item = document.createElement("div");
    item.className = "list-item";
    const enabled = document.createElement("input");
    enabled.type = "checkbox";
    enabled.checked = rs.enabled !== false;
    enabled.setAttribute("aria-label", `Включить Rule-Set ${rs.tag}`);
    enabled.addEventListener("change", () => {
      rs.enabled = enabled.checked;
      dirtyRouting = true;
      updateDirtyIndicators();
      renderRules();
    });
    const info = document.createElement("div");
    info.className = "info";
    const name = document.createElement("strong");
    name.textContent = `ruleset:${rs.tag} (${rs.format === "source" ? ".json" : ".srs"})`;
    const sub = document.createElement("small");
    const disk = geoDiskStatus?.ruleSets?.[rs.id];
    const parts = [rs.sourceType === "remote" ? rs.url : (rs.fileName || rs.path)];
    if (rs.sourceType === "remote" && !rs.path) parts.push("не скачан");
    else if (disk && rs.path && disk.exists === false) parts.push("файл отсутствует");
    else {
      if (rs.size > 0) parts.push(formatBytes(rs.size));
      if (rs.updatedAt) parts.push(`обновлено ${formatIsoShort(rs.updatedAt)}`);
    }
    sub.textContent = parts.filter(Boolean).join(" · ");
    info.append(name, sub);
    item.append(enabled, info);
    if (rs.sourceType === "remote") {
      item.append(button("Обновить", async () => {
        await runGeoUpdate(["ruleset"], [rs.id]);
      }));
    } else {
      item.append(button("Проверить", async () => {
        const res = await send("geoInspect", { path: rs.path, target: "ruleset" });
        rs.size = res.size;
        rs.updatedAt = res.updatedAt;
        rs.format = res.format === "json" ? "source" : "binary";
        rs.fileName = res.fileName;
        renderRuleSets();
        toast(`Rule-Set «${rs.tag}» корректен (${formatBytes(res.size)}).`);
      }));
    }
    item.append(button("Удалить", () => {
      routingGeo.ruleSets.splice(idx, 1);
      dirtyRouting = true;
      updateDirtyIndicators();
      renderRuleSets();
      renderRules();
      refreshGeoDatalist();
    }, "danger"));
    list.append(item);
  });
}

function renderGeoSection() {
  for (const kind of ["geoip", "geosite"]) {
    const src = routingGeo[kind] || FoxTunnel.DEFAULT_GEO_SOURCE();
    $(`${kind}SourceType`).value = src.sourceType || "none";
    $(`${kind}Url`).value = src.url || "";
    $(`${kind}Path`).value = src.path || "";
    syncGeoBoxes(kind);
    renderGeoMeta(kind);
  }
  $("geoUpdateViaProxy").checked = Boolean(routingGeo.updateViaProxy);
  renderRuleSets();
  refreshGeoDatalist();
}

function refreshGeoDatalist() {
  const list = $("geoTagSuggestions");
  const kind = $("ruleKind").value;
  list.replaceChildren();
  let suggestions = [];
  if (kind === "geoip") {
    suggestions = (routingGeo.geoip?.sampleTags?.length ? routingGeo.geoip.sampleTags : ["ru", "us", "de", "nl", "private", "cloudflare", "telegram", "google"]);
  } else if (kind === "geosite") {
    suggestions = (routingGeo.geosite?.sampleTags?.length ? routingGeo.geosite.sampleTags : ["youtube", "google", "discord", "twitter", "telegram", "category-ads-all", "geolocation-!cn", "category-ru"]);
  } else if (kind === "ruleset") {
    suggestions = (routingGeo.ruleSets || []).map(r => r.tag);
  }
  for (const s of suggestions) {
    const opt = document.createElement("option");
    opt.value = s;
    list.append(opt);
  }
}

function updateRuleInputHint() {
  const hint = ruleKindHints[$("ruleKind").value] || ruleKindHints.suffix;
  $("ruleValueLabel").textContent = hint.label;
  $("ruleValue").placeholder = hint.placeholder;
  refreshGeoDatalist();
}

async function refreshGeoDiskStatus() {
  try {
    geoDiskStatus = await send("geoStatus", { geo: routingGeo });
    renderGeoMeta("geoip");
    renderGeoMeta("geosite");
    renderRuleSets();
    renderRules();
  } catch {}
}

function fillFields(ids, source) {
  for (const id of ids) {
    const el = $(id);
    if (el.type === "checkbox") el.checked = source[id];
    else el.value = source[id];
  }
}
function collectFields(ids) {
  const out = {};
  for (const id of ids) {
    const el = $(id);
    out[id] = el.type === "checkbox" ? el.checked : el.type === "number" ? Number(el.value) : el.value;
  }
  return out;
}
function fillAll(force = false) {
  renderSubscriptions();
  renderProfiles();
  if (force || !dirtyRouting) {
    fillFields(routingFields, savedSettings);
    routingRules = structuredClone(savedSettings.rules);
    routingGeo = structuredClone(savedSettings.geo || FoxTunnel.defaults().geo);
    dirtyRouting = false;
    renderGeoSection();
    renderRules();
  }
  if (force || !dirtySecurity) {
    fillFields(securityFields, savedSettings);
    $("dohFields").hidden = savedSettings.dnsMode !== "doh";
    updateThemeUi(savedSettings.theme);
    dirtySecurity = false;
  }
  updateDirtyIndicators();
}
async function saveMerged(patch, message, options = {}) {
  const candidate = FoxTunnel.validateSettings({ ...savedSettings, ...patch });
  try {
    const state = await send("saveSettings", { settings: candidate });
    savedSettings = structuredClone(state.settings);
    if (options.clearDirty === "routing") dirtyRouting = false;
    if (options.clearDirty === "security") dirtySecurity = false;
    status(state);
    fillAll(Boolean(options.forceAll));
    toast(message);
  } catch (e) {
    // Reload state so savedSettings stays aligned if storage saved before core restart failed.
    try {
      const latest = await send("getState");
      savedSettings = structuredClone(latest.settings);
      status(latest);
      fillAll(Boolean(options.forceAll));
    } catch {}
    throw e;
  }
}
async function importText(text) {
  const profiles = FoxTunnel.parseSubscription(text);
  let added = 0;
  const nextProfiles = structuredClone(savedSettings.profiles);
  const existing = new Set(nextProfiles.map(p => JSON.stringify(p.outbound)));
  for (const p of profiles) {
    const key = JSON.stringify(p.outbound);
    if (!existing.has(key)) {
      nextProfiles.push(p);
      existing.add(key);
      added++;
    }
  }
  const nextSelected = savedSettings.selectedId || nextProfiles[0]?.id || "";
  await saveMerged({ profiles: nextProfiles, selectedId: nextSelected }, `Добавлено профилей: ${added}. Дубликаты пропущены.`);
}
function resetEditor(skipConfirm = false) {
  if (!skipConfirm && dirtyEditor && !confirm("Очистить несохранённые изменения в редакторе профиля?")) return;
  editId = "";
  $("profileName").value = "";
  $("outbound").value = "";
  $("editorTitle").textContent = "Профиль вручную";
  $("editorProbeLine").textContent = "";
  $("editorProbeLine").className = "probe-line";
  dirtyEditor = false;
}
function editor() {
  let parsed;
  try { parsed = JSON.parse($("outbound").value); }
  catch { throw new Error("Некорректный JSON в поле outbound."); }
  return FoxTunnel.validateOutbound(parsed);
}

for (const tab of document.querySelectorAll("[data-tab]")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll("[data-tab]")) t.setAttribute("aria-selected", String(t === tab));
    for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = panel.dataset.panel !== tab.dataset.tab;
  });
}
for (const id of routingFields) {
  $(id).addEventListener("change", () => { dirtyRouting = true; updateDirtyIndicators(); });
}
for (const id of securityFields) {
  $(id).addEventListener("input", () => { dirtySecurity = true; updateDirtyIndicators(); });
  $(id).addEventListener("change", () => { dirtySecurity = true; updateDirtyIndicators(); });
}
$("theme").addEventListener("change", () => {
  updateThemeUi($("theme").value);
});
for (const id of ["profileName", "outbound"]) {
  $(id).addEventListener("input", () => { dirtyEditor = true; });
}

$("themeToggle").addEventListener("click", async () => {
  const current = savedSettings.theme || "system";
  const next = themeOrder[(themeOrder.indexOf(current) + 1) % themeOrder.length];
  updateThemeUi(next);
  if (!dirtySecurity) $("theme").value = next;
  try {
    await saveMerged({ theme: next }, themeLabels[next]);
  } catch (e) {
    toast(e.message, true);
  }
});

$("probeAll").addEventListener("click", async () => {
  if (probeAllRunning || !savedSettings.profiles.length) return;
  probeAllRunning = true;
  probeAllAborted = false;
  $("probeAll").disabled = true;
  $("stopProbeAll").hidden = false;
  const snapshot = structuredClone(savedSettings.profiles);
  try {
    for (const p of snapshot) {
      if (probeAllAborted) break;
      await runSingleProbe(p);
    }
    toast(probeAllAborted ? "Проверка серверов остановлена." : `Проверка завершена (${snapshot.length}).`);
  } finally {
    probeAllRunning = false;
    $("stopProbeAll").hidden = true;
    renderProfiles();
  }
});
$("stopProbeAll").addEventListener("click", () => {
  probeAllAborted = true;
  $("stopProbeAll").hidden = true;
});

$("subscriptionAutoUpdate").addEventListener("change", async () => {
  try {
    await saveMerged(
      { subscriptionAutoUpdate: $("subscriptionAutoUpdate").checked },
      $("subscriptionAutoUpdate").checked ? "Автообновление подписок включено." : "Автообновление подписок отключено."
    );
  } catch (e) {
    $("subscriptionAutoUpdate").checked = Boolean(savedSettings.subscriptionAutoUpdate);
    toast(e.message, true);
  }
});

handle("refreshAllSubs", async () => {
  const res = await send("refreshAllSubscriptions");
  savedSettings = structuredClone(res.state.settings);
  status(res.state);
  fillAll(false);
  if (res.errors?.length) {
    toast(`Обновлено ${res.updated} из ${res.total}. Ошибки:\n${res.errors.join("\n")}`, true);
  } else {
    toast(`Подписки обновлены (${res.updated}/${res.total}).`);
  }
});

handle("importLinks", async () => { await importText($("links").value); $("links").value = ""; });
handle("importFile", () => $("linksFile").click());
$("linksFile").addEventListener("change", async e => {
  try {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 1048576) throw new Error("Файл больше 1 МБ.");
    await importText(await file.text());
  } catch (error) { toast(error.message, true); }
  finally { e.target.value = ""; }
});
handle("fetchSubscription", async () => {
  const rawUrl = $("subscriptionUrl").value;
  FoxTunnel.validateSubscriptionUrl(rawUrl);
  if (!confirm("Загрузить подписку через текущий маршрут? Адрес и ваш IP будут доступны серверу подписки. Редиректы не разрешены.")) return;
  const saveSub = $("saveSubscription").checked;
  const res = await send("addSubscription", {
    url: rawUrl,
    name: $("subscriptionName").value,
    save: saveSub
  });
  savedSettings = structuredClone(res.state.settings);
  status(res.state);
  fillAll(false);
  $("subscriptionUrl").value = "";
  $("subscriptionName").value = "";
  if (res.saved) {
    toast(`Подписка «${res.name}» ${res.updatedExisting ? "обновлена" : "сохранена"} (${res.count} серв.).`);
  } else {
    toast(`Добавлено профилей: ${res.added} (из ${res.count}). Дубликаты пропущены.`);
  }
});
handle("saveProfile", async () => {
  const name = $("profileName").value.trim();
  if (!name) throw new Error("Укажите название профиля.");
  const profile = { id: editId || crypto.randomUUID(), name, outbound: editor(), subscriptionId: "" };
  const nextProfiles = structuredClone(savedSettings.profiles);
  const index = nextProfiles.findIndex(p => p.id === profile.id);
  if (index < 0) nextProfiles.push(profile);
  else nextProfiles[index] = profile;
  const nextSelected = savedSettings.selectedId || profile.id;
  await saveMerged({ profiles: nextProfiles, selectedId: nextSelected }, "Профиль сохранён.");
  resetEditor(true);
});
handle("checkProfile", async () => {
  const result = await send("checkProfile", { outbound: editor() });
  toast(`Конфигурация корректна. ${result.coreVersion}`);
});
handle("probeEditor", async () => {
  const line = $("editorProbeLine");
  line.textContent = "Проверяем соединение через конфиг…";
  line.className = "probe-line wait";
  try {
    const res = await send("probeProfile", { outbound: editor() });
    line.textContent = `Доступен · ${res.latencyMs} мс (HTTP ${res.status}, ${res.host})`;
    line.className = "probe-line ok";
  } catch (e) {
    line.textContent = `Недоступен: ${e.message}`;
    line.className = "probe-line err";
    throw e;
  }
});
handle("resetEditor", () => resetEditor(false));
$("ruleKind").addEventListener("change", updateRuleInputHint);
$("geoUpdateViaProxy").addEventListener("change", () => {
  routingGeo.updateViaProxy = $("geoUpdateViaProxy").checked;
  dirtyRouting = true;
  updateDirtyIndicators();
});

async function runGeoUpdate(targets, ruleSetIds = []) {
  let geoPayload;
  if (targets.length === 1 && targets[0] === "geoip") {
    geoPayload = {
      ...savedSettings.geo,
      geoip: FoxTunnel.validateGeoSource(routingGeo.geoip, "GeoIP"),
      updateViaProxy: Boolean(routingGeo.updateViaProxy)
    };
  } else if (targets.length === 1 && targets[0] === "geosite") {
    geoPayload = {
      ...savedSettings.geo,
      geosite: FoxTunnel.validateGeoSource(routingGeo.geosite, "Geosite / Geodata"),
      updateViaProxy: Boolean(routingGeo.updateViaProxy)
    };
  } else if (targets.length === 1 && targets[0] === "ruleset" && ruleSetIds.length === 1) {
    const rawEntry = (routingGeo.ruleSets || []).find(item => item.id === ruleSetIds[0]);
    if (!rawEntry) throw new Error("Rule-Set не найден.");
    const validEntry = FoxTunnel.validateRuleSetEntry(rawEntry);
    const mergedList = [
      ...(savedSettings.geo?.ruleSets || []).filter(item => item.id !== validEntry.id && item.tag !== validEntry.tag),
      validEntry
    ];
    geoPayload = {
      ...savedSettings.geo,
      ruleSets: mergedList,
      updateViaProxy: Boolean(routingGeo.updateViaProxy)
    };
  } else {
    geoPayload = FoxTunnel.validateGeoSettings(routingGeo);
  }
  toast("Скачивание Geo-базы…");
  const res = await send("geoUpdate", { targets, ruleSetIds, geo: geoPayload });
  savedSettings = structuredClone(res.state.settings);
  if (res.geoip && res.geo?.geoip) routingGeo.geoip = structuredClone(res.geo.geoip);
  if (res.geosite && res.geo?.geosite) routingGeo.geosite = structuredClone(res.geo.geosite);
  if (res.ruleSets && res.geo?.ruleSets) {
    const updatedMap = new Map(res.geo.ruleSets.map(r => [r.id, r]));
    routingGeo.ruleSets = (routingGeo.ruleSets || []).map(r => (res.ruleSets[r.id] && updatedMap.get(r.id) ? structuredClone(updatedMap.get(r.id)) : r));
  }
  status(res.state);
  renderGeoSection();
  renderRules();
  refreshGeoDiskStatus();
  const errList = Object.values(res.errors || {});
  if (errList.length) {
    toast(`Обновлено баз: ${res.updatedCount}. Ошибки:\n${errList.join("\n")}`, true);
  } else {
    toast(`Обновлено баз: ${res.updatedCount}${res.viaProxy ? " (через активный VPN)" : ""}.`);
  }
}

function bindGeoSourceCard(kind, label) {
  const cap = kind === "geoip" ? "Geoip" : "Geosite";
  $(`${kind}SourceType`).addEventListener("change", () => {
    const nextType = $(`${kind}SourceType`).value;
    routingGeo[kind] = {
      ...FoxTunnel.DEFAULT_GEO_SOURCE(),
      sourceType: nextType,
      url: routingGeo[kind]?.url || ""
    };
    syncGeoBoxes(kind);
    renderGeoMeta(kind);
    dirtyRouting = true;
    updateDirtyIndicators();
    renderRules();
  });
  $(`${kind}Url`).addEventListener("input", () => {
    routingGeo[kind].url = $(`${kind}Url`).value;
    dirtyRouting = true;
    updateDirtyIndicators();
  });
  $(`${kind}Path`).addEventListener("input", () => {
    routingGeo[kind].path = $(`${kind}Path`).value;
    routingGeo[kind].fileName = "";
    routingGeo[kind].size = 0;
    routingGeo[kind].tagsCount = 0;
    routingGeo[kind].sampleTags = [];
    renderGeoMeta(kind);
    dirtyRouting = true;
    updateDirtyIndicators();
  });
  for (const [suffix, presetKey] of [["Loyal", "loyal"], ["Runet", "runet"]]) {
    $(`preset${cap}${suffix}`).addEventListener("click", () => {
      routingGeo[kind] = {
        ...FoxTunnel.DEFAULT_GEO_SOURCE(),
        sourceType: "remote",
        url: GEO_PRESETS[kind][presetKey]
      };
      renderGeoSection();
      renderRules();
      dirtyRouting = true;
      updateDirtyIndicators();
    });
  }
  handle(`update${cap}`, () => runGeoUpdate([kind]));
  handle(`inspect${cap}`, async () => {
    const info = await send("geoInspect", { path: $(`${kind}Path`).value, target: kind });
    routingGeo[kind] = {
      ...routingGeo[kind],
      sourceType: "local",
      path: info.path,
      fileName: info.fileName,
      format: info.format,
      updatedAt: info.updatedAt,
      size: info.size,
      tagsCount: info.tagsCount,
      sampleTags: info.sampleTags || []
    };
    renderGeoSection();
    renderRules();
    refreshGeoDiskStatus();
    dirtyRouting = true;
    updateDirtyIndicators();
    toast(`${label}: файл проверен (${info.tagsCount ? `${info.tagsCount} категорий` : `.${info.format}`}).`);
  });
  $(`pick${cap}File`).addEventListener("click", () => $(`${kind}FileInput`).click());
  $(`${kind}FileInput`).addEventListener("change", async e => {
    try {
      const file = e.target.files[0];
      if (!file) return;
      toast(`Загрузка ${file.name}…`);
      const info = await uploadGeoFile(file, kind);
      routingGeo[kind] = {
        ...routingGeo[kind],
        sourceType: "local",
        path: info.path,
        fileName: info.fileName,
        format: info.format,
        updatedAt: info.updatedAt,
        size: info.size,
        tagsCount: info.tagsCount,
        sampleTags: info.sampleTags || []
      };
      renderGeoSection();
      renderRules();
      refreshGeoDiskStatus();
      dirtyRouting = true;
      updateDirtyIndicators();
      toast(`${label}: файл «${info.fileName}» загружен. Нажмите «Сохранить маршруты».`);
    } catch (err) { toast(err.message, true); }
    finally { e.target.value = ""; }
  });
}

bindGeoSourceCard("geoip", "GeoIP");
bindGeoSourceCard("geosite", "Geosite");
handle("updateAllGeo", () => runGeoUpdate(["geoip", "geosite", "ruleset"]));

let pendingRsId = crypto.randomUUID();
let pendingRsMeta = null;
$("rsSourceType").addEventListener("change", () => {
  const isRemote = $("rsSourceType").value === "remote";
  $("rsRemoteBox").hidden = !isRemote;
  $("rsLocalBox").hidden = isRemote;
});
$("pickRsFile").addEventListener("click", () => $("rsFileInput").click());
$("rsFileInput").addEventListener("change", async e => {
  try {
    const file = e.target.files[0];
    if (!file) return;
    toast(`Загрузка ${file.name}…`);
    const info = await uploadGeoFile(file, "ruleset", pendingRsId);
    pendingRsMeta = info;
    $("rsPath").value = info.path;
    $("rsFormat").value = info.format === "json" ? "source" : "binary";
    if (!$("rsTag").value.trim()) {
      $("rsTag").value = file.name.replace(/\.(srs|json)$/i, "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
    }
    toast(`Файл «${info.fileName}» загружен. Нажмите «Добавить Rule-Set».`);
  } catch (err) { toast(err.message, true); }
  finally { e.target.value = ""; }
});
handle("addRuleSet", () => {
  const isRemote = $("rsSourceType").value === "remote";
  const raw = {
    id: pendingRsId,
    tag: $("rsTag").value,
    enabled: true,
    sourceType: isRemote ? "remote" : "local",
    format: $("rsFormat").value,
    url: isRemote ? $("rsUrl").value : "",
    path: isRemote ? "" : $("rsPath").value,
    fileName: !isRemote && pendingRsMeta?.path === $("rsPath").value ? pendingRsMeta.fileName : "",
    updatedAt: !isRemote && pendingRsMeta?.path === $("rsPath").value ? pendingRsMeta.updatedAt : "",
    size: !isRemote && pendingRsMeta?.path === $("rsPath").value ? pendingRsMeta.size : 0
  };
  const entry = FoxTunnel.validateRuleSetEntry(raw);
  if ((routingGeo.ruleSets || []).some(r => r.tag === entry.tag)) {
    throw new Error(`Rule-Set с тегом «${entry.tag}» уже существует.`);
  }
  routingGeo.ruleSets = [...(routingGeo.ruleSets || []), entry];
  pendingRsId = crypto.randomUUID();
  pendingRsMeta = null;
  $("rsTag").value = "";
  $("rsUrl").value = "";
  $("rsPath").value = "";
  dirtyRouting = true;
  updateDirtyIndicators();
  renderRuleSets();
  renderRules();
  refreshGeoDatalist();
});

handle("addRule", () => {
  routingRules.push(FoxTunnel.normalizeRule({
    kind: $("ruleKind").value,
    action: $("ruleAction").value,
    value: $("ruleValue").value
  }));
  $("ruleValue").value = "";
  dirtyRouting = true;
  updateDirtyIndicators();
  renderRules();
});
async function saveRoutingAction() {
  const patch = {
    ...collectFields(routingFields),
    rules: routingRules,
    geo: FoxTunnel.validateGeoSettings({ ...routingGeo, updateViaProxy: $("geoUpdateViaProxy").checked })
  };
  await saveMerged(patch, "Маршрутизация и Geo-базы сохранены. Перезагрузите нужные вкладки.", { clearDirty: "routing" });
  refreshGeoDiskStatus();
}
handle("saveRouting", saveRoutingAction);
handle("saveGeoRouting", saveRoutingAction);
handle("saveSecurity", async () => {
  const patch = collectFields(securityFields);
  await saveMerged(patch, "Настройки сети и защиты сохранены.", { clearDirty: "security" });
});
$("dnsMode").addEventListener("change", () => { $("dohFields").hidden = $("dnsMode").value !== "doh"; });
handle("testRoute", async () => {
  let url;
  try { url = new URL($("testUrl").value); } catch { throw new Error("Введите корректный URL для проверки."); }
  const result = await send("routePreview", { url: url.href });
  const note = dirtyRouting ? " (проверено по сохранённым правилам)" : "";
  $("routeResult").textContent = `${url.hostname} → ${labels[result] || result}${note}`;
});
handle("diagnostics", async () => { $("diagnosticOutput").textContent = JSON.stringify(await send("diagnostics"), null, 2); });
handle("getLogs", async () => { const result = await send("logs"); $("coreLogs").textContent = result.text || "Журнал пуст."; });
handle("connect", async () => {
  const state = await send("connect");
  status(state);
  toast("Ядро запущено. Для проверки туннеля откройте сайт проверки IP через VPN-маршрут.");
});
handle("disconnect", async () => {
  const state = await send("disconnect");
  status(state);
  toast("Отключено. Трафик идёт напрямую.");
});
handle("recoverDisconnect", async () => {
  const state = await send("disconnect");
  status(state);
  toast("Kill switch отключён. Трафик идёт напрямую.");
});
handle("exportBackup", async () => {
  if (!confirm("Экспорт содержит все секреты подключений в открытом виде. Продолжить?")) return;
  const state = await send("getState");
  const blob = new Blob([JSON.stringify(state.settings, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = url;
  a.download = "foxtunnel-backup.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
});
handle("importBackup", () => $("backupFile").click());
$("backupFile").addEventListener("change", async e => {
  try {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 4194304) throw new Error("Файл больше 4 МБ.");
    const value = FoxTunnel.validateSettings(JSON.parse(await file.text()));
    if (!confirm("Заменить все профили и настройки резервной копией? Активное подключение будет отключено.")) return;
    const state = await send("getState");
    if (state.wanted) await send("disconnect");
    const next = await send("saveSettings", { settings: value });
    savedSettings = structuredClone(next.settings);
    probeResults.clear();
    resetEditor(true);
    fillAll(true);
    status(next);
    toast("Резервная копия загружена.");
  } catch (error) { toast(error.message, true); }
  finally { e.target.value = ""; }
});

window.addEventListener("beforeunload", e => {
  if (dirtyRouting || dirtySecurity || dirtyEditor) {
    e.preventDefault();
    e.returnValue = "";
  }
});

browser.runtime.onMessage.addListener(message => {
  if (message.type !== "stateChanged") return;
  savedSettings = structuredClone(message.state.settings);
  status(message.state);
  fillAll(false);
});

(async () => {
  try {
    updateRuleInputHint();
    const state = await send("getState");
    savedSettings = structuredClone(state.settings);
    fillAll(true);
    status(state);
    refreshGeoDiskStatus();
  } catch (e) { toast(e.message, true); }
})();
