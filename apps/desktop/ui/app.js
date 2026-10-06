// ================================================================
// ETHOS — Web controller (opencode-style chrome, Cyber Obsidian)
// Real daemon wiring: sandboxes, full models.dev catalog, attack
// lab, taint/security telemetry. No demo data. No build step.
// ================================================================

"use strict";

// ---------- helpers ----------

const $ = (id) => document.getElementById(id);

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children) if (c != null) el.append(c);
  return el;
}

function fmtCtx(n) {
  if (!n) return "—";
  if (n >= 1000000) return (n / 1000000).toFixed(n % 1000000 ? 1 : 0) + "M";
  if (n >= 1000) return Math.round(n / 1000) + "k";
  return String(n);
}
function fmtCost(m) {
  const i = m.cost_input_per_million, o = m.cost_output_per_million;
  if (!i && !o) return `<span class="badge free">FREE</span>`;
  return `$${Number(i).toFixed(2)}/$${Number(o).toFixed(2)}`;
}

// Subsequence fuzzy match with start/streak bonuses. Returns score or null.
function fuzzy(needle, hay) {
  needle = needle.toLowerCase().trim();
  hay = hay.toLowerCase();
  if (!needle) return 1;
  let score = 0, from = 0, prev = -2;
  for (const ch of needle) {
    const idx = hay.indexOf(ch, from);
    if (idx === -1) return null;
    if (idx === prev + 1) score += 4; else score += 1;
    if (idx === 0 || " -_/.".includes(hay[idx - 1])) score += 2;
    prev = idx; from = idx + 1;
  }
  return score - hay.length * 0.002;
}

// ---------- prefs / state ----------

const getPref = (k, f) => localStorage.getItem("ethos_" + k) ?? f;
const setPref = (k, v) => localStorage.setItem("ethos_" + k, v);

// Inside the Tauri webview the UI is served from tauri.localhost (Win) or
// tauri://localhost (mac/linux), NOT from the daemon — relative /v1 fetches
// would hit the wrong origin. Default the API base to the sidecar daemon
// (main.rs spawns `ethos daemon --port 8000` on startup).
const IN_TAURI = location.hostname === "tauri.localhost" || location.protocol === "tauri:";
const DEFAULT_API_BASE = IN_TAURI ? "http://localhost:8000" : "";

const state = {
  apiBase: getPref("api_base", DEFAULT_API_BASE).replace(/\/$/, ""),
  provider: getPref("provider", ""),
  model: getPref("model", ""),
  providers: [],        // ProviderSummary[]
  models: [],           // ModelSpec[] (full catalog)
  favorites: JSON.parse(getPref("favs", "[]")),   // [{p, m}]
  recents: JSON.parse(getPref("recent", "[]")),    // [{p, m}]
  sessions: [],
  activeSession: null,
  sessionSnaps: {},     // id -> [snapshot_id]
  selectedLab: null,
  labResult: null,
  openTabs: ["dashboard"],
  activeTab: "dashboard",
  daemonOnline: false,
  catalogFilterProvider: null, // null = all
  overlay: null,        // 'palette' | 'model' | 'settings'
  selIdx: 0,            // keyboard selection inside overlay lists
  overlayItems: [],     // current overlay item list for keyboard nav
};

const saveFavs = () => setPref("favs", JSON.stringify(state.favorites));
const saveRecent = () => setPref("recent", JSON.stringify(state.recents.slice(0, 5)));
const modelKey = (x) => x.p + "::" + x.m;
const isFav = (p, m) => state.favorites.some((f) => f.p === p && f.m === m);

function markRecent(p, m) {
  state.recents = [{ p, m }, ...state.recents.filter((r) => !(r.p === p && r.m === m))].slice(0, 5);
  saveRecent();
}

function setActiveModel(p, m) {
  state.provider = p; state.model = m;
  setPref("provider", p); setPref("model", m);
  markRecent(p, m);
  updateStatusbar(); updateModelBadge();
  renderCatalog(); // re-highlight active row
  toast(`Active model → ${m} (${p})`);
}

// ---------- API client ----------

async function api(path, opts = {}) {
  const url = state.apiBase + path;
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  }).catch(() => { throw new Error("daemon unreachable"); });
  if (!res.ok) throw new Error(`${opts.method || "GET"} ${path} → ${res.status}`);
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body ?? {}) });

// ---------- toasts ----------

function toast(msg, kind = "") {
  const t = h("div", { class: "toast " + kind, text: msg });
  $("toast-rack").append(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; }, 2600);
  setTimeout(() => t.remove(), 3000);
}

// ---------- tabs & router ----------

const VIEW_TITLES = { dashboard: "Dashboard", sessions: "Sessions", catalog: "Model Catalog", lab: "Attack Lab", security: "Security" };

function renderTabs() {
  const strip = $("tab-strip");
  strip.replaceChildren();
  for (const v of state.openTabs) {
    const tab = h("div", {
      class: "tab" + (v === state.activeTab ? " active" : ""),
      onclick: () => switchTab(v),
    },
      h("span", { text: VIEW_TITLES[v] || v }),
      h("span", { class: "tab-close", text: "×", title: "Close", onclick: (e) => { e.stopPropagation(); closeTab(v); } })
    );
    strip.append(tab);
  }
}

function openTab(v) {
  if (!state.openTabs.includes(v)) state.openTabs.push(v);
  switchTab(v);
}

function closeTab(v) {
  state.openTabs = state.openTabs.filter((t) => t !== v);
  if (state.openTabs.length === 0) state.openTabs = ["dashboard"];
  if (state.activeTab === v) switchTab(state.openTabs[state.openTabs.length - 1]);
  renderTabs();
}

function switchTab(v) {
  state.activeTab = v;
  if (!state.openTabs.includes(v)) state.openTabs.push(v);
  document.querySelectorAll(".view").forEach((el) => el.classList.toggle("active", el.dataset.view === v));
  document.querySelectorAll(".side-item").forEach((el) => el.classList.toggle("active", el.dataset.view === v));
  renderTabs();
  if (v === "sessions") refreshSessions();
  if (v === "catalog") ensureCatalog();
  if (v === "lab") refreshLab();
  if (v === "security") refreshSecurity();
  if (v === "dashboard") refreshDashboard();
}

// ---------- statusbar / sidebar / health ----------

function updateStatusbar() {
  $("status-provider").textContent = state.provider || "—";
  $("status-model").textContent = state.model || "no model";
}

function updateModelBadge() {
  const b = $("btn-model-picker");
  $("model-badge-text").textContent = state.model ? `${state.provider}/${state.model}` : "no model";
  b.classList.toggle("active", !!state.model);
}

function setDaemonOnline(on) {
  state.daemonOnline = on;
  $("daemon-pill").classList.toggle("online", on);
  $("daemon-text").textContent = on ? "daemon online" : "daemon offline";
}

async function checkHealth() {
  try {
    const j = await api("/health");
    setDaemonOnline(j.status === "healthy");
  } catch { setDaemonOnline(false); }
}

// ---------- dashboard ----------

async function refreshDashboard() {
  await checkHealth();
  const grid = $("metric-grid");
  grid.replaceChildren(h("div", { class: "side-empty", text: state.daemonOnline ? "" : "daemon offline — start with `ethos daemon` or `ethos app`" }));
  if (!state.daemonOnline) return;
  try {
    const m = await api("/v1/metrics");
    const cards = [
      ["Active Sandboxes", m.active_sandboxes ?? 0, "live sessions"],
      ["Total Steps", m.total_steps ?? 0, "tool invocations"],
      ["Active Taint", m.active_taint_count ?? 0, "untrusted resources"],
      ["PromptInject Trips", m.wall_trips_prompt_inject ?? 0, "injection patterns"],
      ["Ouroboros Trips", m.wall_trips_ouroboros ?? 0, "immutability blocks"],
      ["Defense Rate", `${Math.round((m.benchmark_defense_rate ?? 0) * 100)}%`, "blocked attacks"],
    ];
    grid.replaceChildren(...cards.map(([l, v, s]) =>
      h("div", { class: "metric-card" },
        h("div", { class: "metric-label", text: l }),
        h("div", { class: "metric-value", text: String(v) }),
        h("div", { class: "metric-sub", text: s }))
    ));
  } catch (e) { toast(e.message, "warn"); }

  $("walls-summary").replaceChildren(
    h("div", { class: "taint-node" },
      h("span", { class: "res", text: "PromptInjectScanner" }), h("span", { class: "dim", text: " — 7 injection pattern families" })),
    h("div", { class: "taint-node" },
      h("span", { class: "res", text: "OuroborosWall" }), h("span", { class: "dim", text: " — tests/ src/taint/ src/walls/ migrations/ .git/ Cargo.toml + rewind markers" })),
    h("div", { class: "taint-node" },
      h("span", { class: "res", text: "Taint Boundary" }), h("span", { class: "dim", text: " — case-folded sensitive paths, merge-never-downgrade provenance" })),
    h("div", { class: "taint-node" },
      h("span", { class: "res", text: "HalluScan / EmergencyStop" }), h("span", { class: "dim", text: " — path validation + high-severity circuit breaker" })),
  );

  try {
    const events = await api("/v1/metrics/events");
    const rows = (events || []).slice().reverse().map((ev) =>
      h("tr", {},
        h("td", { text: new Date((ev.timestamp || 0) * 1000).toLocaleTimeString() }),
        h("td", { text: ev.event_type || "—" }),
        h("td", { text: ev.action || "—" }),
        h("td", { text: JSON.stringify(ev.details || {}).slice(0, 80) }))
    );
    $("daemon-events").replaceChildren(
      rows.length
        ? h("table", { class: "mtable" }, h("thead", {}, h("tr", {}, h("th", { text: "time" }), h("th", { text: "type" }), h("th", { text: "action" }), h("th", { text: "details" }))), h("tbody", {}, ...rows))
        : h("div", { class: "side-empty", text: "no events yet" })
    );
  } catch { $("daemon-events").replaceChildren(h("div", { class: "side-empty", text: "—" })); }
}

// ---------- sessions ----------

async function refreshSessions() {
  if (!state.daemonOnline) await checkHealth();
  if (!state.daemonOnline) return;
  try {
    const j = await api("/v1/sandboxes");
    state.sessions = j.sandboxes || [];
  } catch (e) { toast(e.message, "warn"); return; }

  const list = $("session-list");
  if (!state.sessions.length) {
    list.replaceChildren(h("div", { class: "side-empty", text: "no sandboxes — create one" }));
  } else {
    list.replaceChildren(...state.sessions.map((id) =>
      h("div", { class: "session-card" + (state.activeSession === id ? " active" : ""), onclick: () => selectSession(id) },
        h("div", { class: "session-card-id", text: id }),
        h("div", { class: "session-card-desc", text: "sandbox session" }))
    ));
  }

  const side = $("side-sessions");
  side.replaceChildren(...state.sessions.map((id) =>
    h("div", { class: "side-session" + (state.activeSession === id ? " active" : ""), text: id, title: id, onclick: () => { openTab("sessions"); selectSession(id); } })
  ));
  if (state.activeSession && !state.sessions.includes(state.activeSession)) {
    state.activeSession = null;
    $("session-detail").replaceChildren(h("div", { class: "side-empty", style: "padding:48px 0", text: "select a sandbox" }));
  }
}

async function createSandbox() {
  try {
    const j = await post("/v1/sandboxes", { description: "web session" });
    toast(`Sandbox ${j.sandbox_id} created`);
    await refreshSessions();
    selectSession(j.sandbox_id);
  } catch (e) { toast(e.message, "err"); }
}

async function selectSession(id) {
  state.activeSession = id;
  await refreshSessions();
  const pane = $("session-detail");
  pane.replaceChildren(h("div", { class: "side-empty", style: "padding:48px 0", text: "loading…" }));
  try {
    const obs = await api(`/v1/sandboxes/${encodeURIComponent(id)}/observe`);
    const tel = await api(`/v1/sandboxes/${encodeURIComponent(id)}/telemetry`);
    renderSessionDetail(id, obs, tel.events || []);
  } catch (e) { pane.replaceChildren(h("div", { class: "side-empty", text: e.message })); }
}

function renderSessionDetail(id, obs, events) {
  const snaps = state.sessionSnaps[id] || [];
  const pane = $("session-detail");

  const files = (obs.created_files || []).map((f) =>
    h("span", { class: "file-chip" + ((obs.tainted_resources || []).includes(f) ? " tainted" : ""), text: f }));
  const blocked = events.filter((e) => e.event_type === "POLICY_BLOCK");
  const snapChips = snaps.map((s) =>
    h("span", { class: "file-chip", title: "click to rewind", style: "cursor:pointer", onclick: () => rewindSession(id, s), text: "⟲ " + s }));

  pane.replaceChildren(
    h("div", { class: "session-detail-inner" },
      h("div", { class: "detail-head" },
        h("div", {},
          h("div", { class: "detail-title", text: id }),
          h("div", { class: "detail-sub", text: `step ${obs.step_id} · taint ${obs.active_taint_count} · files ${files.length}` })),
        h("div", { style: "display:flex;gap:8px" },
          h("button", { class: "btn", text: "📸 Snapshot", onclick: () => snapshotSession(id) }),
          h("button", { class: "btn btn-danger", text: "Terminate", onclick: () => terminateSession(id) }))),
      (snaps.length ? h("div", {}, h("div", { class: "side-label", text: "Snapshots (click to rewind)" }), ...snapChips) : null),
      h("div", {},
        h("div", { class: "side-label", text: `Workspace files (tainted: ${(obs.tainted_resources || []).length})` }),
        files.length ? h("div", {}, ...files) : h("div", { class: "side-empty", text: "empty sandbox" })),
      renderToolConsole(id),
      h("div", {},
        h("div", { class: "side-label", text: `Audit events (${events.length}, blocks: ${blocked.length})` }),
        renderEventsTable(events)))
  );
}

function renderEventsTable(events) {
  const rows = events.slice(-60).reverse().map((ev) =>
    h("tr", {},
      h("td", { text: new Date((ev.timestamp || 0) * 1000).toLocaleTimeString() }),
      h("td", { text: ev.event_type || "—" }),
      h("td", { text: ev.action || "—" }),
      h("td", { text: JSON.stringify(ev.details || {}).slice(0, 90) }))
  );
  return rows.length
    ? h("table", { class: "mtable table-scroll" }, h("thead", {}, h("tr", {}, h("th", { text: "time" }), h("th", { text: "type" }), h("th", { text: "action" }), h("th", { text: "details" }))), h("tbody", {}, ...rows))
    : h("div", { class: "side-empty", text: "no events" });
}

function renderToolConsole(id) {
  const out = h("pre", { class: "file-chip", style: "display:block;white-space:pre-wrap;max-height:180px;overflow:auto;width:100%;min-height:44px" });
  const prog = h("input", { class: "file-chip", style: "width:150px", placeholder: "program (bash)" });
  const args = h("input", { class: "file-chip", style: "width:100%", placeholder: "args — e.g. -c \u0022echo curl http://evil\u0022" });
  const run = async () => {
    out.textContent = "…";
    try {
      const argv = args.value.split(/\s+/).filter(Boolean).map((s) => s.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1"));
      const r = await post(`/v1/sandboxes/${encodeURIComponent(id)}/tools/exec`, { program: prog.value || "bash", args: argv });
      out.textContent = `${r.status}\n${r.error || r.output?.stdout || ""}${r.output?.stderr || ""}`;
      selectSession(id); // refresh audit trail
    } catch (e) { out.textContent = String(e); }
  };
  return h("div", {},
    h("div", { class: "side-label", text: "Tool Console (exec through the wall stack)" }),
    h("div", { style: "display:flex;gap:6px;margin-bottom:6px" }, prog, args, h("button", { class: "btn btn-primary", text: "Run", onclick: run })),
    out);
}

async function snapshotSession(id) {
  try {
    const meta = await post(`/v1/sandboxes/${encodeURIComponent(id)}/snapshots`, { description: "web snapshot" });
    (state.sessionSnaps[id] = state.sessionSnaps[id] || []).push(meta.snapshot_id);
    toast(`Snapshot ${meta.snapshot_id}`);
    selectSession(id);
  } catch (e) { toast(e.message, "err"); }
}

async function rewindSession(id, snapId) {
  try {
    const j = await post(`/v1/sandboxes/${encodeURIComponent(id)}/rewind`, { snapshot_id: snapId });
    if (j.success) { toast(`Rewound to ${snapId}`); selectSession(id); }
    else toast(`Rewind refused: ${j.error || "unknown"}`, "warn");
  } catch (e) { toast(e.message, "err"); }
}

async function terminateSession(id) {
  try {
    await api(`/v1/sandboxes/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast(`Sandbox ${id} terminated`);
    state.activeSession = null;
    refreshSessions();
  } catch (e) { toast(e.message, "err"); }
}

// ---------- catalog ----------

let catalogLoaded = false;

async function ensureCatalog(force = false) {
  try {
    if (force) await post("/v1/models/refresh").catch(() => {});
    const [providers, models] = await Promise.all([
      api("/v1/models/providers"),
      api("/v1/models"),
    ]);
    state.providers = providers || [];
    state.models = Array.isArray(models) ? models : [];
    catalogLoaded = true;
    renderProviderRail();
    renderCatalog();
    $("catalog-count").textContent = state.models.length;
    if (force) toast(`models.dev synced — ${state.models.length} models`);
  } catch (e) {
    toast(e.message, "warn");
    renderProviderRail();
    renderCatalog();
  }
}

function renderProviderRail() {
  const rail = $("provider-rail");
  const byProvider = {};
  for (const m of state.models) (byProvider[m.provider] = (byProvider[m.provider] || 0) + 1);

  const mk = (pid, name, count, extra = "") =>
    h("button", {
      class: "rail-item" + (state.catalogFilterProvider === pid ? " active" : ""),
      onclick: () => { state.catalogFilterProvider = pid; renderProviderRail(); renderCatalog(); },
    }, h("span", { text: name + extra }), h("span", { class: "rail-count", text: String(count) }));

  rail.replaceChildren(
    h("div", { class: "rail-header", text: "Providers" }),
    mk(null, "All providers", state.models.length),
    mk("__fav", "★ Favorites", state.favorites.length),
    h("div", { class: "rail-header", text: `Catalog (${state.providers.length})` }),
    ...state.providers
      .slice()
      .sort((a, b) => (a.is_popular === b.is_popular ? a.name.localeCompare(b.name) : a.is_popular ? -1 : 1))
      .map((p) => mk(p.id, p.name + (p.is_popular ? " ★" : ""), byProvider[p.id] ?? 0)),
  );
}

function modelBadges(m) {
  const b = [];
  if (m.has_tools) b.push(h("span", { class: "badge tools", text: "TOOLS" }));
  if (m.has_vision) b.push(h("span", { class: "badge vision", text: "VISION" }));
  if (m.has_reasoning) b.push(h("span", { class: "badge reason", text: "REASON" }));
  if (m.is_open_weights) b.push(h("span", { class: "badge openw", text: "OPEN" }));
  return h("span", { class: "badge-row" }, ...b);
}

function filteredModels() {
  const q = $("catalog-search").value;
  const tools = $("catalog-tools-only").checked;
  const vision = $("catalog-vision-only").checked;
  const reasoning = $("catalog-reasoning-only").checked;
  const favs = $("catalog-favs-only").checked;

  let list = state.models;
  if (state.catalogFilterProvider === "__fav") list = list.filter((m) => isFav(m.provider, m.id));
  else if (state.catalogFilterProvider) list = list.filter((m) => m.provider === state.catalogFilterProvider);
  if (tools) list = list.filter((m) => m.has_tools);
  if (vision) list = list.filter((m) => m.has_vision);
  if (reasoning) list = list.filter((m) => m.has_reasoning);
  if (favs) list = list.filter((m) => isFav(m.provider, m.id));

  if (q.trim()) {
    list = state.models // search always spans the whole catalog, opencode-style
      .map((m) => ({ m, s: fuzzy(q, m.name + " " + m.provider + " " + m.id) }))
      .filter((x) => x.s != null && passesFilters(x.m))
      .sort((a, b) => b.s - a.s)
      .map((x) => x.m);
  }
  return list;

  function passesFilters(m) {
    if (tools && !m.has_tools) return false;
    if (vision && !m.has_vision) return false;
    if (reasoning && !m.has_reasoning) return false;
    if (favs && !isFav(m.provider, m.id)) return false;
    if (state.catalogFilterProvider === "__fav") return isFav(m.provider, m.id);
    if (state.catalogFilterProvider && m.provider !== state.catalogFilterProvider) return false;
    return true;
  }
}

function renderCatalog() {
  const listEl = $("catalog-list");
  if (!catalogLoaded && !state.models.length) {
    listEl.replaceChildren(h("div", { class: "cat-empty", text: state.daemonOnline ? "loading catalog…" : "daemon offline — catalog unavailable" }));
    return;
  }
  const models = filteredModels();
  if (!models.length) {
    listEl.replaceChildren(h("div", { class: "cat-empty", text: "no models match" }));
    return;
  }

  // group by provider
  const groups = new Map();
  for (const m of models) {
    if (!groups.has(m.provider)) groups.set(m.provider, []);
    groups.get(m.provider).push(m);
  }

  const frag = [];
  for (const [pid, items] of groups) {
    const p = state.providers.find((x) => x.id === pid);
    frag.push(h("div", { class: "cat-section", text: `${p ? p.name : pid} — ${items.length} models` }));
    for (const m of items) {
      const active = state.provider === m.provider && state.model === m.id;
      const fav = isFav(m.provider, m.id);
      frag.push(h("div", {
        class: "model-row" + (active ? " active" : "") + (fav ? " fav-star" : ""),
        onclick: () => setActiveModel(m.provider, m.id),
      },
        h("button", {
          class: "star", text: fav ? "★" : "☆", title: "favorite",
          onclick: (e) => { e.stopPropagation(); toggleFav(m.provider, m.id); },
        }),
        h("span", {}, h("div", { class: "model-name", text: m.name || m.id }), h("div", { class: "model-id", text: m.id })),
        h("span", { class: "model-provider", text: m.provider }),
        h("span", { class: "model-ctx", text: fmtCtx(m.context_window) + " ctx" }),
        h("span", { class: "model-cost", onclick: (e) => e.stopPropagation() }),
        modelBadges(m)));
      // cost is html — patch separately to keep escapeHtml discipline
      frag[frag.length - 1].children[4].innerHTML = fmtCost(m);
    }
  }
  listEl.replaceChildren(...frag);
}

function toggleFav(p, m) {
  if (isFav(p, m)) state.favorites = state.favorites.filter((f) => !(f.p === p && f.m === m));
  else state.favorites.push({ p, m });
  saveFavs();
  renderProviderRail();
  renderCatalog();
}

// ---------- model picker overlay (opencode DialogModel style) ----------

function openOverlay(name) {
  closeOverlay();
  state.overlay = name;
  $(name === "palette" ? "overlay-palette" : name === "model" ? "overlay-model-picker" : "overlay-settings").hidden = false;
  if (name === "model") { $("model-search").value = ""; state.selIdx = 0; renderModelPicker(); setTimeout(() => $("model-search").focus(), 30); }
  if (name === "palette") { $("palette-input").value = ""; state.selIdx = 0; renderPalette(); setTimeout(() => $("palette-input").focus(), 30); }
  if (name === "settings") loadSettingsForm();
}

function closeOverlay() {
  ["overlay-palette", "overlay-model-picker", "overlay-settings"].forEach((id) => $(id).hidden = true);
  state.overlay = null; state.selIdx = 0;
}

function modelPickerItems() {
  const q = $("model-search").value;
  const items = [];
  const add = (section, m) => {
    items.push({
      section, m,
      title: m.name || m.id,
      desc: m.provider,
      active: state.provider === m.provider && state.model === m.id,
      fav: isFav(m.provider, m.id),
    });
  };
  const needle = q.trim();
  const match = (m) => !needle || fuzzy(needle, `${m.name} ${m.provider} ${m.id}`) != null;

  if (!needle) {
    let lastSection = null;
    for (const r of state.recents) {
      const m = state.models.find((x) => x.provider === r.p && x.id === r.m);
      if (m) { add("Recents", m); lastSection = "Recents"; }
    }
    if (lastSection) items[0].section = "Recents";
  }
  // all models grouped by provider, ordered providers-first like opencode
  const groups = new Map();
  for (const m of state.models) if (match(m)) {
    if (!groups.has(m.provider)) groups.set(m.provider, []);
    groups.get(m.provider).push(m);
  }
  const ordered = state.providers.filter((p) => groups.has(p.id)).sort((a, b) => a.name.localeCompare(b.name));
  for (const p of ordered) {
    for (const m of groups.get(p.id)) add(p.name, m);
  }
  if (needle) items.sort((a, b) => fuzzy(needle, a.title + " " + a.desc) - fuzzy(needle, b.title + " " + b.desc)).reverse();
  return items;
}

function renderModelPicker() {
  const items = modelPickerItems();
  state.overlayItems = items;
  const list = $("model-list");
  let lastSection = null;
  const frag = [];
  items.forEach((it, i) => {
    if (it.section && it.section !== lastSection) { frag.push(h("div", { class: "dl-section", text: it.section })); lastSection = it.section; }
    frag.push(h("div", {
      class: "dl-item" + (i === state.selIdx ? " sel" : ""),
      onclick: () => { setActiveModel(it.m.provider, it.m.id); closeOverlay(); },
    },
      h("span", {},
        (it.active ? h("span", { class: "mark", text: "● " }) : null),
        (it.fav ? h("span", { class: "mark", text: "★ " }) : null),
        h("span", { text: it.title })),
      h("span", { class: "desc", text: it.desc }),
      h("span", { class: "desc", text: fmtCtx(it.m.context_window) })));
  });
  list.replaceChildren(...frag);
  const sel = list.querySelector(".dl-item.sel");
  if (sel) sel.scrollIntoView({ block: "nearest" });
}

function toggleFavFromPicker() {
  const it = state.overlayItems[state.selIdx];
  if (!it) return;
  toggleFav(it.m.provider, it.m.id);
  renderModelPicker();
}

// ---------- command palette ----------

function paletteCommands() {
  return [
    { title: "Go to Dashboard", desc: "view", run: () => openTab("dashboard") },
    { title: "Go to Sessions", desc: "view", run: () => openTab("sessions") },
    { title: "Go to Model Catalog", desc: "view", run: () => openTab("catalog") },
    { title: "Go to Attack Lab", desc: "view", run: () => openTab("lab") },
    { title: "Go to Security", desc: "view", run: () => openTab("security") },
    { title: "Select model…", desc: "picker", run: () => openOverlay("model") },
    { title: "New sandbox", desc: "session", run: () => { openTab("sessions"); createSandbox(); } },
    { title: "Sync models.dev catalog", desc: "catalog", run: () => { openTab("catalog"); ensureCatalog(true); } },
    { title: "Open settings", desc: "config", run: () => openOverlay("settings") },
    { title: "Toggle sidebar", desc: "layout", run: () => $("sidebar").classList.toggle("hidden") },
    { title: "Refresh daemon events", desc: "dashboard", run: () => { openTab("dashboard"); refreshDashboard(); } },
  ];
}

function renderPalette() {
  const q = $("palette-input").value;
  const cmds = paletteCommands()
    .map((c) => ({ c, s: fuzzy(q, c.title) }))
    .filter((x) => x.s != null)
    .sort((a, b) => b.s - a.s)
    .map((x) => x.c);
  state.overlayItems = cmds.map((c) => ({ run: c.run }));
  const list = $("palette-list");
  list.replaceChildren(...cmds.map((c, i) =>
    h("div", {
      class: "dl-item" + (i === state.selIdx ? " sel" : ""),
      onclick: () => { closeOverlay(); c.run(); },
    }, h("span", { text: c.title }), h("span", { class: "desc", text: c.desc }))));
  const sel = list.querySelector(".dl-item.sel");
  if (sel) sel.scrollIntoView({ block: "nearest" });
}

// ---------- attack lab ----------

async function refreshLab() {
  if (!state.daemonOnline) await checkHealth();
  if (!state.daemonOnline) return;
  try {
    const scenarios = await api("/v1/lab/scenarios");
    state.labScenarios = scenarios || [];
    const el = $("lab-scenarios");
    if (!state.labScenarios.length) { el.replaceChildren(h("div", { class: "side-empty", text: "no scenarios found" })); return; }
    el.replaceChildren(...state.labScenarios.map((s) =>
      h("div", {
        class: "lab-card" + (state.selectedLab === s.id ? " active" : ""),
        onclick: () => { state.selectedLab = s.id; refreshLab(); runScenario(s.id); },
      },
        h("div", { class: "lab-card-name", text: s.name || s.id }),
        h("div", { class: "lab-card-meta" },
          h("span", { text: s.severity || "" }),
          h("span", { text: s.family || "" }),
          h("span", { text: s.target_tool || "" })))));
  } catch (e) { toast(e.message, "warn"); }
}

async function runScenario(id) {
  const trace = $("lab-trace");
  trace.replaceChildren(h("div", { class: "side-empty", text: "executing scenario…" }));
  try {
    const r = await post("/v1/lab/execute", { scenario_id: id });
    const blocked = r.final_outcome === "ATTACK_BLOCKED_BY_POLICY";
    trace.replaceChildren(
      h("div", { class: "trace-step" },
        h("div", { class: "trace-step-title" }, h("span", { class: blocked ? "outcome-blocked" : "outcome-vulnerable", text: r.final_outcome || "—" })),
        h("div", { class: "trace-step-sub", text: `${r.scenario_name} · walls: ${(r.walls_tripped || []).join(", ") || "none"} · taint records: ${r.taint_records_count}` })),
      ...(r.steps || []).map((s) =>
        h("div", { class: "trace-step" },
          h("div", { class: "trace-step-title", text: `${s.step}. ${s.action} [${s.status}]` }),
          h("div", { class: "trace-step-sub", text: s.output_summary || "" }),
          (s.wall_triggers?.length ? h("div", { class: "trace-step-sub", text: "walls: " + s.wall_triggers.join(", ") }) : null)))
    );
  } catch (e) { trace.replaceChildren(h("div", { class: "side-empty", text: e.message })); }
}

// ---------- security ----------

async function refreshSecurity() {
  if (!state.daemonOnline) await checkHealth();
  if (!state.daemonOnline) return;
  try {
    const g = await api("/v1/taint/graph");
    const nodes = g.nodes || [];
    const graphEl = $("taint-graph");
    graphEl.replaceChildren(...(nodes.length
      ? nodes.map((n) => h("div", { class: "taint-node" },
          h("span", { class: "res", text: n.label || n.id }),
          h("span", { class: "dim", text: `  ${n.trust_level || ""} (${n.sandbox_id || ""})` })))
      : [h("div", { class: "side-empty", text: "no tainted resources — clean ledger" })]));

    let blockedRows = [];
    for (const id of state.sessions) {
      try {
        const tel = await api(`/v1/sandboxes/${encodeURIComponent(id)}/telemetry`);
        for (const ev of (tel.events || [])) {
          if (ev.event_type === "POLICY_BLOCK") blockedRows.push({ id, ev });
        }
      } catch { /* session gone */ }
    }
    $("blocks-count").textContent = String(blockedRows.length);
    $("blocks-log").replaceChildren(...(blockedRows.length
      ? blockedRows.map(({ id, ev }) =>
          h("div", { class: "blocked-row" },
            h("span", { class: "rule", text: (ev.details?.rule_id || ev.details?.reason || "POLICY").toString().slice(0, 60) }),
            h("span", { class: "dim", text: `  ${id} · ${ev.action} · ${JSON.stringify(ev.details || {}).slice(0, 70)}` })))
      : [h("div", { class: "side-empty", text: "no policy blocks recorded" })]));
  } catch (e) { toast(e.message, "warn"); }
}

// ---------- settings ----------

function loadSettingsForm() {
  $("settings-api-base").value = state.apiBase;
  $("settings-api-key").value = getPref("api_key", "");
  const provSel = $("settings-provider");
  provSel.replaceChildren(h("option", { value: "", text: "—" }));
  for (const p of state.providers) provSel.append(h("option", { value: p.id, text: p.name + (p.is_popular ? " ★" : "") }));
  provSel.value = state.provider || "";
  renderSettingsModels();
}

function renderSettingsModels() {
  const pid = $("settings-provider").value;
  const sel = $("settings-model");
  sel.replaceChildren(h("option", { value: "", text: "—" }));
  for (const m of state.models.filter((m) => !pid || m.provider === pid)) {
    sel.append(h("option", { value: m.id, text: m.name || m.id }));
  }
  sel.value = state.model || "";
}

function saveSettings() {
  state.apiBase = $("settings-api-base").value.replace(/\/$/, "");
  setPref("api_base", state.apiBase);
  setPref("api_key", $("settings-api-key").value);
  const pid = $("settings-provider").value;
  const mid = $("settings-model").value;
  if (pid && mid) setActiveModel(pid, mid);
  toast("Settings saved");
  closeOverlay();
  checkHealth();
  refreshSessions();
}

// ---------- keyboard ----------

document.addEventListener("keydown", (e) => {
  const inField = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);

  if ((e.ctrlKey || e.metaKey) && (e.key === "p" || e.key === "k")) {
    e.preventDefault(); openOverlay("palette"); return;
  }
  if ((e.ctrlKey || e.metaKey) && e.key === "b") {
    e.preventDefault(); $("sidebar").classList.toggle("hidden"); return;
  }
  if (e.key === "Escape" && state.overlay) { closeOverlay(); return; }

  if (state.overlay === "palette") {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const n = state.overlayItems.length;
      if (n) { state.selIdx = (state.selIdx + (e.key === "ArrowDown" ? 1 : -1) + n) % n; renderPalette(); }
    } else if (e.key === "Enter") {
      e.preventDefault();
      state.overlayItems[state.selIdx]?.run?.(); closeOverlay();
    } else if (!inField) { setTimeout(renderPalette, 0); }
    return;
  }
  if (state.overlay === "model") {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const n = state.overlayItems.length;
      if (n) { state.selIdx = (state.selIdx + (e.key === "ArrowDown" ? 1 : -1) + n) % n; renderModelPicker(); }
    } else if (e.key === "Enter") {
      e.preventDefault();
      const it = state.overlayItems[state.selIdx];
      if (it) { setActiveModel(it.m.provider, it.m.id); closeOverlay(); }
    } else if ((e.ctrlKey || e.metaKey) && e.key === "f") {
      e.preventDefault(); toggleFavFromPicker();
    }
    return;
  }

  if (e.key === "/" && !inField && state.activeTab === "catalog") {
    e.preventDefault(); $("catalog-search").focus(); return;
  }
});

// ---------- wiring ----------

document.addEventListener("DOMContentLoaded", () => {
  // nav + tabs
  document.querySelectorAll(".side-item").forEach((el) =>
    el.addEventListener("click", () => openTab(el.dataset.view)));
  $("brand-home").addEventListener("click", () => openTab("dashboard"));

  $("btn-sidebar-toggle").addEventListener("click", () => $("sidebar").classList.toggle("hidden"));
  $("btn-palette").addEventListener("click", () => openOverlay("palette"));
  $("btn-model-picker").addEventListener("click", () => openOverlay("model"));
  $("btn-settings").addEventListener("click", () => openOverlay("settings"));
  $("btn-settings-close").addEventListener("click", closeOverlay);
  $("btn-settings-save").addEventListener("click", saveSettings);
  $("settings-provider").addEventListener("change", renderSettingsModels);

  $("btn-refresh-health").addEventListener("click", refreshDashboard);
  $("btn-quick-sandbox").addEventListener("click", createSandbox);
  $("btn-sessions-refresh").addEventListener("click", refreshSessions);
  $("btn-create-sandbox").addEventListener("click", createSandbox);
  $("btn-catalog-refresh").addEventListener("click", () => ensureCatalog(true));
  $("btn-lab-refresh").addEventListener("click", refreshLab);
  $("btn-security-refresh").addEventListener("click", refreshSecurity);

  ["catalog-search", "catalog-tools-only", "catalog-vision-only", "catalog-reasoning-only", "catalog-favs-only"]
    .forEach((id) => $(id).addEventListener("input", renderCatalog));

  ["overlay-palette", "overlay-model-picker", "overlay-settings"].forEach((id) =>
    $(id).addEventListener("mousedown", (e) => { if (e.target.id === id) closeOverlay(); }));

  $("palette-input").addEventListener("input", () => { state.selIdx = 0; renderPalette(); });
  $("model-search").addEventListener("input", () => { state.selIdx = 0; renderModelPicker(); });

  updateStatusbar(); updateModelBadge();
  switchTab("dashboard");
  checkHealth();
  ensureCatalog();
  setInterval(checkHealth, 30000);
});
