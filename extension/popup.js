/* global browser */
"use strict";
const $ = id => document.getElementById(id);
let state;
let probing = false;

async function send(type, extra = {}) {
  const reply = await browser.runtime.sendMessage({ type, ...extra });
  if (!reply.ok) throw new Error(reply.error);
  return reply.result;
}
function setProbeLine(text = "", kind = "") {
  const el = $("probeLine");
  el.textContent = text;
  el.className = kind ? `probe-line ${kind}` : "probe-line";
}
function render(next) {
  state = next;
  window.applyFoxTunnelTheme?.(state.settings.theme);
  const label = state.busy ? "Запускается…" : state.running ? "Работает" : state.wanted ? "Ошибка" : "Отключено";
  $("status").textContent = label;
  $("statusDot").className = `dot ${state.busy ? "busy" : state.running ? "online" : state.wanted ? "failed" : ""}`;
  $("detail").textContent = state.busy
    ? "Ожидаем ответ локального ядра sing-box…"
    : state.running
      ? `SOCKS5 · 127.0.0.1:${state.settings.port} (ядро запущено)`
      : state.wanted && state.settings.killSwitch
        ? "Kill switch: VPN-запросы заблокированы."
        : "Используется обычное соединение.";
  $("profile").replaceChildren();
  for (const p of state.settings.profiles) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.name;
    $("profile").append(o);
  }
  if (!state.settings.profiles.length) {
    const o = document.createElement("option");
    o.textContent = "Добавьте профиль в настройках";
    o.value = "";
    $("profile").append(o);
  }
  $("profile").value = state.settings.selectedId;
  $("mode").value = state.settings.mode;
  const noVpnTraffic = state.settings.mode === "rules"
    && state.settings.defaultAction === "direct"
    && !state.settings.rules.some(r => r.enabled && r.action === "proxy");
  $("routeWarning").hidden = !noVpnTraffic;
  $("switchGlobal").disabled = state.busy;
  $("toggle").textContent = state.running ? "Отключить" : "Подключить";
  $("toggle").disabled = state.busy || (!state.running && !state.settings.selectedId);
  $("probe").disabled = probing || !state.settings.selectedId;
  const subCount = state.settings.subscriptions?.length || 0;
  $("refreshSubs").hidden = subCount === 0;
  $("refreshSubs").disabled = probing || subCount === 0;
  $("profile").disabled = state.busy;
  $("mode").disabled = state.busy;
  $("error").textContent = state.lastError || "";
  // In an error state users can intentionally turn off the kill switch connection.
  let off = $("stopFailed");
  if (state.wanted && !state.running && !state.busy) {
    if (!off) {
      off = document.createElement("button");
      off.id = "stopFailed";
      off.className = "quiet full";
      off.textContent = "Отключить и разрешить прямой трафик";
      off.addEventListener("click", () => act(() => send("disconnect")));
      $("toggle").after(off);
    }
  } else off?.remove();
}
async function act(fn) {
  try {
    render(await fn());
  } catch (e) {
    $("error").textContent = e.message;
    try { render(await send("getState")); } catch {}
  }
}
$("settings").addEventListener("click", () => browser.runtime.openOptionsPage());
$("switchGlobal").addEventListener("click", () => {
  if (!state) return;
  act(() => send("saveSettings", { settings: { ...state.settings, mode: "global" } }));
});
$("toggle").addEventListener("click", () => {
  if (!state) return;
  act(() => send(state.running ? "disconnect" : "connect"));
});
$("probe").addEventListener("click", async () => {
  if (!state || probing) return;
  const profile = state.settings.profiles.find(p => p.id === state.settings.selectedId);
  if (!profile) return;
  probing = true;
  $("probe").disabled = true;
  setProbeLine("Проверяем соединение через конфиг…", "wait");
  try {
    const res = await send("probeProfile", { outbound: profile.outbound });
    setProbeLine(`Доступен · ${res.latencyMs} мс (HTTP ${res.status}, ${res.host})`, "ok");
  } catch (e) {
    setProbeLine(`Недоступен: ${e.message}`, "err");
  } finally {
    probing = false;
    if (state) $("probe").disabled = !state.settings.selectedId;
  }
});
$("refreshSubs").addEventListener("click", async () => {
  if (!state || probing || !(state.settings.subscriptions?.length)) return;
  probing = true;
  $("refreshSubs").disabled = true;
  $("probe").disabled = true;
  setProbeLine("Обновляем подписки…", "wait");
  try {
    const res = await send("refreshAllSubscriptions");
    if (res.state) render(res.state);
    if (res.errors?.length) {
      setProbeLine(`Обновлено ${res.updated}/${res.total}. Ошибки: ${res.errors.join("; ")}`, "err");
    } else {
      setProbeLine(`Подписки обновлены (${res.updated}/${res.total}).`, "ok");
    }
  } catch (e) {
    setProbeLine(`Ошибка обновления: ${e.message}`, "err");
  } finally {
    probing = false;
    if (state) {
      $("probe").disabled = !state.settings.selectedId;
      $("refreshSubs").disabled = !(state.settings.subscriptions?.length);
    }
  }
});
for (const id of ["profile", "mode"]) {
  $(id).addEventListener("change", () => {
    if (!state) return;
    if (id === "profile") setProbeLine();
    act(() => send("saveSettings", {
      settings: { ...state.settings, selectedId: $("profile").value, mode: $("mode").value }
    }));
  });
}
browser.runtime.onMessage.addListener(message => {
  if (message.type === "stateChanged") render(message.state);
});
act(() => send("getState"));
