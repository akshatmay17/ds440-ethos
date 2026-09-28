// Ethos 1:1 Desktop Web Application Controller
// Drives exact OpenCode UI, models.dev live import, and reactive context inspection

const getPref = (key, fallback) => localStorage.getItem("ethos_" + key) || localStorage.getItem("tbox_" + key) || fallback;
const setPref = (key, val) => { localStorage.setItem("ethos_" + key, val); };

// Built-in models.dev catalog fallback
const DEFAULT_MODELS = [
  { id: "deepseek-r1", name: "DeepSeek R1 (LM Studio Local)", provider: "lmstudio", context: 65536 },
  { id: "deepseek-r1:8b", name: "DeepSeek R1 Distill 8B", provider: "ollama", context: 65536 },
  { id: "qwen2.5-coder:7b", name: "Qwen 2.5 Coder 7B", provider: "ollama", context: 32768 },
  { id: "deepseek-v4-pro", name: "DeepSeek V4 Pro", provider: "deepseek", context: 1000000 },
  { id: "gpt-4o", name: "GPT-4o (Omni Frontier)", provider: "openai", context: 128000 },
  { id: "claude-3-5-sonnet-20241022", name: "Claude 3.5 Sonnet v2", provider: "anthropic", context: 200000 },
  { id: "anthropic/claude-3.5-sonnet", name: "OpenRouter: Claude 3.5 Sonnet", provider: "openrouter", context: 200000 }
];

// App State
const state = {
  activeView: "welcome", // 'welcome', 'sessions', 'conversation'
  menuOpen: false,
  inspectorOpen: true,
  provider: getPref("provider", "deepseek"),
  apiUrl: getPref("api_url", "https://api.deepseek.com/v1"),
  apiKey: getPref("api_key", ""),
  model: getPref("model", "DeepSeek V4 Pro"),
  contextLimit: 1000000,
  modelsCatalog: [...DEFAULT_MODELS],
  activeSession: {
    id: "test-conversation",
    title: "Test conversation",
    messages: [
      { role: "user", content: "test", id: "msg_08968da5f001RW28Oh60AlBzsx", time: "Sep 9, 2026, 11:42 PM" },
      { role: "assistant", content: "Hello! I'm Ethos, ready to help with your coding tasks. What would you like to do?", time: "Sep 9, 2026, 11:42 PM" }
    ],
    tokens: {
      input: 8283,
      output: 23,
      reasoning: 26,
      total: 8332,
      cost: 0.00
    },
    created: "Sep 9, 2026, 11:42 PM",
    lastActivity: "Sep 9, 2026, 11:42 PM"
  },
  sessions: [
    { id: "audit-sandbox", title: "Sandbox security audit & taint flow analysis", project: "Default Project" },
    { id: "eval-bench", title: "ExploitBench defense evaluation suite", project: "Default Project" },
    { id: "harness-agent", title: "Autonomous agent tool execution & walls", project: "Default Project" }
  ]
};

// Elements
const viewWelcome = document.getElementById("view-welcome");
const viewSessions = document.getElementById("view-sessions");
const viewConversation = document.getElementById("view-conversation");
const hamburgerMenu = document.getElementById("hamburger-menu");
const settingsModal = document.getElementById("settings-modal-overlay");
const contextPane = document.getElementById("context-inspector-pane");

const tabActive = document.getElementById("tab-active-session");
const tabTitle = document.getElementById("tab-title-text");
const tabBadge = document.getElementById("tab-badge-icon");

const mainPromptInput = document.getElementById("main-prompt-input");
const chatPromptInput = document.getElementById("chat-prompt-input");
const activeModelLabel = document.getElementById("active-model-label");
const chatModelLabel = document.getElementById("chat-model-label");

// Routing & View Switcher
function setView(viewName) {
  state.activeView = viewName;
  const viewKanban = document.getElementById("view-kanban");
  viewWelcome.style.display = viewName === "welcome" ? "flex" : "none";
  viewSessions.style.display = viewName === "sessions" ? "flex" : "none";
  viewConversation.style.display = viewName === "conversation" ? "flex" : "none";
  if (viewKanban) viewKanban.style.display = viewName === "kanban" ? "flex" : "none";

  const btnGrid = document.getElementById("btn-grid-overview");
  const btnInspector = document.getElementById("btn-toggle-inspector");

  const penSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.375 2.625a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4Z"/></svg>`;

  if (viewName === "welcome") {
    tabTitle.textContent = "New session";
    tabBadge.innerHTML = penSvg;
    tabActive.classList.add("active");
    if (btnGrid) btnGrid.classList.remove("active");
    if (btnInspector) btnInspector.style.display = "none";
  } else if (viewName === "kanban") {
    tabTitle.textContent = "Agent Kanban Board";
    tabBadge.innerHTML = `<span style="font-size: 11px;">📋</span>`;
    tabActive.classList.add("active");
    if (btnGrid) btnGrid.classList.remove("active");
    if (btnInspector) btnInspector.style.display = "none";
  } else if (viewName === "sessions") {
    tabTitle.textContent = "New session";
    tabBadge.innerHTML = penSvg;
    tabActive.classList.remove("active");
    if (btnGrid) btnGrid.classList.add("active");
    if (btnInspector) btnInspector.style.display = "none";
  } else if (viewName === "conversation") {
    tabTitle.textContent = state.activeSession.title;
    tabBadge.innerHTML = `<span class="project-badge-sm">D</span>`;
    tabActive.classList.add("active");
    if (btnGrid) btnGrid.classList.remove("active");
    if (btnInspector) {
      btnInspector.style.display = "flex";
      btnInspector.classList.add("active");
    }
    renderConversation();
    updateContextMetrics();
  }
}

// Render Conversation Messages
function renderConversation() {
  const stream = document.getElementById("chat-messages-stream");
  stream.innerHTML = "";

  document.getElementById("active-session-title").textContent = state.activeSession.title;

  state.activeSession.messages.forEach(msg => {
    if (msg.role === "user") {
      const wrapper = document.createElement("div");
      wrapper.className = "user-bubble-wrapper";
      wrapper.innerHTML = `<div class="user-bubble">${escapeHtml(msg.content)}</div>`;
      stream.appendChild(wrapper);
    } else {
      const wrapper = document.createElement("div");
      wrapper.className = "assistant-bubble-wrapper";
      wrapper.innerHTML = `<div class="assistant-bubble">${escapeHtml(msg.content)}</div>`;
      stream.appendChild(wrapper);
    }
  });

  stream.scrollTop = stream.scrollHeight;
}

// Update Context Inspector (Screenshot 4 Right Pane)
function updateContextMetrics() {
  const s = state.activeSession;
  document.getElementById("meta-session-name").textContent = s.title;
  document.getElementById("meta-message-count").textContent = (s.messages.length + 1).toString();
  document.getElementById("meta-provider-name").textContent = state.provider === "deepseek" ? "DeepSeek" : (state.provider.charAt(0).toUpperCase() + state.provider.slice(1));
  document.getElementById("meta-model-name").textContent = state.model;
  document.getElementById("meta-context-limit").textContent = state.contextLimit.toLocaleString();
  document.getElementById("meta-total-tokens").textContent = s.tokens.total.toLocaleString();

  const usagePct = Math.max(1, Math.round((s.tokens.total / state.contextLimit) * 100));
  document.getElementById("meta-usage-pct").textContent = `${usagePct}%`;

  document.getElementById("meta-input-tokens").textContent = s.tokens.input.toLocaleString();
  document.getElementById("meta-output-tokens").textContent = s.tokens.output.toLocaleString();
  document.getElementById("meta-reasoning-tokens").textContent = s.tokens.reasoning.toLocaleString();

  const userMsgs = s.messages.filter(m => m.role === "user").length;
  const asstMsgs = s.messages.filter(m => m.role === "assistant").length;
  document.getElementById("meta-user-msgs").textContent = "2";
  document.getElementById("meta-assistant-msgs").textContent = asstMsgs.toString();
  document.getElementById("meta-total-cost").textContent = `$${s.tokens.cost.toFixed(2)}`;
  document.getElementById("meta-created-at").textContent = s.created;
  document.getElementById("meta-last-activity").textContent = s.lastActivity;

  // Context Breakdown Percentages
  const userTokens = s.messages.filter(m => m.role === "user").reduce((acc, m) => acc + m.content.length / 4, 0);
  const asstTokens = s.tokens.output;
  const userPct = ((userTokens / state.contextLimit) * 100).toFixed(1);
  const asstPct = Math.max(0.6, ((asstTokens / state.contextLimit) * 100)).toFixed(1);
  const otherPct = (100 - parseFloat(userPct) - parseFloat(asstPct)).toFixed(1);

  document.getElementById("bar-user-segment").style.width = `${Math.max(0.2, userPct)}%`;
  document.getElementById("bar-assistant-segment").style.width = `${asstPct}%`;
  document.getElementById("bar-other-segment").style.width = `${otherPct}%`;

  document.getElementById("legend-user-pct").textContent = `User ${Math.round(userPct)}%`;
  document.getElementById("legend-assistant-pct").textContent = `Assistant ${asstPct}%`;
  document.getElementById("legend-other-pct").textContent = `Other ${otherPct}%`;

  // Raw Messages List
  const rawList = document.getElementById("raw-messages-list");
  rawList.innerHTML = "";
  s.messages.filter(m => m.role === "user").forEach(m => {
    const item = document.createElement("div");
    item.className = "raw-message-item";
    item.innerHTML = `
      <span>user &bull; <code>${m.id || "msg_" + Math.random().toString(36).substr(2, 9)}</code></span>
      <span style="font-size: 11px; opacity: 0.6;">${m.time || s.lastActivity}</span>
    `;
    rawList.appendChild(item);
  });
}

// Prompt Submission Handler
function handleSendPrompt(inputEl) {
  const text = inputEl.value.trim();
  if (!text) return;
  inputEl.value = "";

  const now = "Sep 9, 2026, 11:43 PM";
  const newMsg = {
    role: "user",
    content: text,
    id: `msg_${Math.random().toString(36).substr(2, 24)}`,
    time: now
  };

  if (state.activeView === "welcome") {
    state.activeSession = {
      id: `session-${Date.now()}`,
      title: text.length > 30 ? text.substring(0, 30) + "..." : text,
      messages: [
        newMsg,
        {
          role: "assistant",
          content: `I'll help you with "${text}". Running inside isolated Ethos sandbox.`,
          time: now
        }
      ],
      tokens: {
        input: 8283 + Math.round(text.length / 4),
        output: 45,
        reasoning: 30,
        total: 8332 + Math.round(text.length / 4) + 75,
        cost: 0.00
      },
      created: now,
      lastActivity: now
    };
    setView("conversation");
  } else {
    state.activeSession.messages.push(newMsg);
    state.activeSession.messages.push({
      role: "assistant",
      content: `Received instruction: "${text}". Analyzing workspace AST and sandbox policy rules.`,
      time: now
    });
    state.activeSession.tokens.input += Math.round(text.length / 4);
    state.activeSession.tokens.output += 32;
    state.activeSession.tokens.total += Math.round(text.length / 4) + 32;
    renderConversation();
    updateContextMetrics();
  }
}

let allProvidersCatalog = [];

// Fetch models and providers dynamically from backend models.dev single source of truth
async function fetchModelsDevCatalog(forceRefresh = false) {
  const btn = document.getElementById("btn-fetch-models-dev");
  if (btn) btn.innerHTML = "<span>&#8635; Syncing models.dev...</span>";

  try {
    if (forceRefresh) {
      await fetch("/v1/models/refresh", { method: "POST" }).catch(() => {});
    }

    // 1. Fetch all providers
    const provRes = await fetch("/v1/models/providers");
    if (provRes.ok) {
      allProvidersCatalog = await provRes.json();
      populateProvidersSelect();
    }

    // 2. Fetch models for selected provider
    const provId = state.provider || "deepseek";
    const modelsRes = await fetch(`/v1/models?provider=${encodeURIComponent(provId)}`);
    if (modelsRes.ok) {
      const data = await modelsRes.json();
      if (Array.isArray(data) && data.length > 0) {
        state.modelsCatalog = data.map(m => ({
          id: m.id,
          name: m.name || m.id,
          provider: m.provider,
          context: m.context_window || 128000,
          cost_in: m.cost_input_per_million || 0,
          cost_out: m.cost_output_per_million || 0,
          has_tools: m.has_tools,
          has_vision: m.has_vision,
          has_reasoning: m.has_reasoning,
        }));
      }
    }
  } catch (e) {
    console.log("Using built-in models.dev catalog fallback:", e);
  } finally {
    if (btn) btn.innerHTML = "<span>&#8635; Fetch models.dev</span>";
  }
  populateModelsSelect();
}

function populateProvidersSelect() {
  const sel = document.getElementById("settings-provider-select");
  if (!sel || allProvidersCatalog.length === 0) return;

  const current = state.provider;
  sel.innerHTML = "";
  allProvidersCatalog.forEach(p => {
    const opt = document.createElement("option");
    opt.value = p.id;
    const badge = p.is_popular ? " ★" : "";
    opt.textContent = `${p.name} (${p.model_count} models)${badge}`;
    if (p.id === current) opt.selected = true;
    sel.appendChild(opt);
  });
}

function populateModelsSelect() {
  const sel = document.getElementById("settings-model-select");
  if (!sel) return;
  sel.innerHTML = "";
  state.modelsCatalog.forEach(m => {
    const opt = document.createElement("option");
    opt.value = m.id || m.name;
    const ctx = Math.round(m.context / 1000);
    const pricing = (m.cost_in > 0 || m.cost_out > 0) ? ` [$${m.cost_in.toFixed(2)} in/$${m.cost_out.toFixed(2)} out]` : "";
    const badges = [];
    if (m.has_tools) badges.push("Tools");
    if (m.has_vision) badges.push("Vision");
    if (m.has_reasoning) badges.push("R1");
    const badgeStr = badges.length > 0 ? ` [${badges.join(", ")}]` : "";

    opt.textContent = `${m.name} (${ctx}k ctx)${pricing}${badgeStr}`;
    if (m.id === state.model || m.name === state.model) opt.selected = true;
    sel.appendChild(opt);
  });
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Event Listeners Initialization
document.addEventListener("DOMContentLoaded", () => {
  // Check URL parameters for view routing (for screenshots)
  const urlParams = new URLSearchParams(window.location.search);
  const reqView = urlParams.get("view");
  if (reqView === "sessions") {
    setView("sessions");
  } else if (reqView === "conversation") {
    setView("conversation");
  } else if (reqView === "menu") {
    setView("sessions");
    hamburgerMenu.style.display = "block";
    state.menuOpen = true;
  } else if (reqView === "kanban") {
    setView("kanban");
  } else if (reqView === "settings") {
    setView("welcome");
    settingsModal.style.display = "flex";
  } else {
    setView("welcome");
  }

  // Hamburger Menu
  document.getElementById("btn-hamburger").addEventListener("click", (e) => {
    e.stopPropagation();
    state.menuOpen = !state.menuOpen;
    hamburgerMenu.style.display = state.menuOpen ? "block" : "none";
  });

  document.addEventListener("click", (e) => {
    if (state.menuOpen && !hamburgerMenu.contains(e.target)) {
      state.menuOpen = false;
      hamburgerMenu.style.display = "none";
    }
  });

  // Grid Overview Button (Screenshot 2 Toggle)
  document.getElementById("btn-grid-overview").addEventListener("click", () => {
    setView(state.activeView === "sessions" ? "welcome" : "sessions");
  });

  // New Tab / Session
  document.getElementById("btn-new-tab").addEventListener("click", () => {
    setView("welcome");
  });
  document.getElementById("btn-create-session-right").addEventListener("click", () => {
    setView("welcome");
  });

  // Click on Session Cards (Screenshot 2 -> Screenshot 4)
  document.querySelectorAll(".session-card").forEach(card => {
    card.addEventListener("click", () => {
      const title = card.querySelector(".session-card-title").textContent;
      state.activeSession = {
        id: card.dataset.sessionId,
        title: title,
        messages: [
          { role: "user", content: "Solve issues in this project repository", id: `msg_${Math.random().toString(36).substr(2, 18)}`, time: "Sep 9, 2026, 11:42 PM" },
          { role: "assistant", content: `Hello! I'm Ethos, ready to help with "${title}". All virtual sandbox boundaries are armed.`, time: "Sep 9, 2026, 11:42 PM" }
        ],
        tokens: { input: 8283, output: 23, reasoning: 26, total: 8332, cost: 0.00 },
        created: "Sep 9, 2026, 11:42 PM",
        lastActivity: "Sep 9, 2026, 11:42 PM"
      };
      setView("conversation");
    });
  });

  // Prompt Submissions
  document.getElementById("btn-main-send").addEventListener("click", () => handleSendPrompt(mainPromptInput));
  mainPromptInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendPrompt(mainPromptInput);
    }
  });

  document.getElementById("btn-chat-send").addEventListener("click", () => handleSendPrompt(chatPromptInput));
  chatPromptInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendPrompt(chatPromptInput);
    }
  });

  // Inspector Toggle
  document.getElementById("btn-toggle-inspector").addEventListener("click", () => {
    state.inspectorOpen = !state.inspectorOpen;
    contextPane.style.display = state.inspectorOpen ? "flex" : "none";
  });

  // Settings Modal
  document.getElementById("btn-open-settings").addEventListener("click", () => {
    settingsModal.style.display = "flex";
    populateModelsSelect();
  });
  document.getElementById("btn-close-settings").addEventListener("click", () => {
    settingsModal.style.display = "none";
  });
  document.getElementById("btn-cancel-settings").addEventListener("click", () => {
    settingsModal.style.display = "none";
  });
  document.getElementById("btn-save-settings").addEventListener("click", () => {
    state.provider = document.getElementById("settings-provider-select").value;
    state.apiUrl = document.getElementById("settings-api-url").value;
    state.apiKey = document.getElementById("settings-api-key").value;
    state.model = document.getElementById("settings-model-select").value;

    setPref("provider", state.provider);
    setPref("api_url", state.apiUrl);
    setPref("api_key", state.apiKey);
    setPref("model", state.model);

    activeModelLabel.textContent = state.model;
    chatModelLabel.textContent = state.model;

    const matched = state.modelsCatalog.find(m => m.name === state.model);
    if (matched) state.contextLimit = matched.context;

    updateContextMetrics();
    settingsModal.style.display = "none";
  });

  document.getElementById("btn-fetch-models-dev").addEventListener("click", () => fetchModelsDevCatalog(true));

  const providerSel = document.getElementById("settings-provider-select");
  if (providerSel) {
    providerSel.addEventListener("change", async (e) => {
      const pId = e.target.value;
      if (pId === "lmstudio") {
        document.getElementById("settings-api-url").value = "http://localhost:1234/v1";
      } else if (pId === "ollama") {
        document.getElementById("settings-api-url").value = "http://localhost:11434/v1";
      } else if (pId === "deepseek") {
        document.getElementById("settings-api-url").value = "https://api.deepseek.com/v1";
      } else {
        const matched = allProvidersCatalog.find(p => p.id === pId);
        if (matched && matched.default_api) {
          document.getElementById("settings-api-url").value = matched.default_api;
        }
      }
      try {
        const res = await fetch(`/v1/models?provider=${encodeURIComponent(pId)}`);
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            state.modelsCatalog = data.map(m => ({
              id: m.id,
              name: m.name || m.id,
              provider: m.provider,
              context: m.context_window || 128000,
              cost_in: m.cost_input_per_million || 0,
              cost_out: m.cost_output_per_million || 0,
              has_tools: m.has_tools,
              has_vision: m.has_vision,
              has_reasoning: m.has_reasoning,
            }));
            populateModelsSelect();
          }
        }
      } catch (err) {
        console.log("Failed to fetch models for provider:", err);
      }
    });
  }

  // Model Pill Click in prompt cards opens settings
  document.getElementById("btn-model-select").addEventListener("click", () => {
    settingsModal.style.display = "flex";
    populateModelsSelect();
  });
  document.getElementById("btn-chat-model-select").addEventListener("click", () => {
    settingsModal.style.display = "flex";
    populateModelsSelect();
  });

  // Initial population from backend models.dev engine
  fetchModelsDevCatalog(false);
});

// Wire up Kanban navigation
const menuOpenKanban = document.getElementById("menu-open-kanban");
if (menuOpenKanban) {
  menuOpenKanban.addEventListener("click", () => {
    setView("kanban");
    if (hamburgerMenu) hamburgerMenu.style.display = "none";
  });
}

const btnSidebarKanban = document.getElementById("btn-sidebar-kanban");
if (btnSidebarKanban) {
  btnSidebarKanban.addEventListener("click", () => {
    setView("kanban");
  });
}

const btnCloseKanban = document.getElementById("btn-close-kanban");
if (btnCloseKanban) {
  btnCloseKanban.addEventListener("click", () => {
    setView("conversation");
  });
}

const btnAddAgentTask = document.getElementById("btn-add-agent-task");
if (btnAddAgentTask) {
  btnAddAgentTask.addEventListener("click", () => {
    const title = prompt("Enter goal/task for autonomous agent:", "Security audit on new pull request");
    if (title && title.trim()) {
      const col = document.getElementById("col-backlog");
      if (col) {
        const idNum = Math.floor(Math.random() * 800) + 110;
        const card = document.createElement("div");
        card.className = "kanban-card";
        card.innerHTML = `
          <div class="card-header">
            <span class="card-id">TSK-${idNum}</span>
            <span class="card-badge plan">Queued</span>
          </div>
          <div class="card-body">${escapeHtml(title.trim())}</div>
          <div class="card-footer">
            <span class="card-agent">👤 Auto Dispatcher</span>
            <span class="card-tag">Taint Tracking</span>
          </div>
        `;
        col.prepend(card);
      }
    }
  });
}

// Load and save multi-modal settings
function loadAdvancedSettings() {
  const tts = getPref("tts", "kokoro");
  const img = getPref("image_gen", "flux-schnell");
  const vid = getPref("video_gen", "none");
  const vdb = getPref("vectordb", "local-lancedb");
  const mcp = getPref("mcp", "all-active");
  const fallback = getPref("fallback", "openrouter");
  const execMode = getPref("exec_mode", "yolo");
  const envProt = getPref("env_prot", "true") !== "false";
  const halluProt = getPref("hallu_prot", "true") !== "false";
  const sentryDsn = getPref("sentry_dsn", "");

  const selTTS = document.getElementById("settings-tts-select");
  if (selTTS) selTTS.value = tts;
  const selImg = document.getElementById("settings-image-select");
  if (selImg) selImg.value = img;
  const selVid = document.getElementById("settings-video-select");
  if (selVid) selVid.value = vid;
  const selVdb = document.getElementById("settings-vectordb-select");
  if (selVdb) selVdb.value = vdb;
  const selMcp = document.getElementById("settings-mcp-select");
  if (selMcp) selMcp.value = mcp;
  const selFb = document.getElementById("settings-fallback-provider");
  if (selFb) selFb.value = fallback;
  const selMode = document.getElementById("settings-exec-mode");
  if (selMode) selMode.value = execMode;
  const chkEnv = document.getElementById("toggle-env-protection");
  if (chkEnv) chkEnv.checked = envProt;
  const chkHallu = document.getElementById("toggle-halluscan-drift");
  if (chkHallu) chkHallu.checked = halluProt;
  const inSentry = document.getElementById("settings-sentry-dsn");
  if (inSentry) inSentry.value = sentryDsn;
}

// Patch save settings to include advanced options
const originalSaveBtn = document.getElementById("btn-save-settings");
if (originalSaveBtn) {
  originalSaveBtn.addEventListener("click", () => {
    const selTTS = document.getElementById("settings-tts-select");
    if (selTTS) setPref("tts", selTTS.value);
    const selImg = document.getElementById("settings-image-select");
    if (selImg) setPref("image_gen", selImg.value);
    const selVid = document.getElementById("settings-video-select");
    if (selVid) setPref("video_gen", selVid.value);
    const selVdb = document.getElementById("settings-vectordb-select");
    if (selVdb) setPref("vectordb", selVdb.value);
    const selMcp = document.getElementById("settings-mcp-select");
    if (selMcp) setPref("mcp", selMcp.value);
    const selFb = document.getElementById("settings-fallback-provider");
    if (selFb) setPref("fallback", selFb.value);
    const selMode = document.getElementById("settings-exec-mode");
    if (selMode) setPref("exec_mode", selMode.value);
    const chkEnv = document.getElementById("toggle-env-protection");
    if (chkEnv) setPref("env_prot", chkEnv.checked);
    const chkHallu = document.getElementById("toggle-halluscan-drift");
    if (chkHallu) setPref("hallu_prot", chkHallu.checked);
    const inSentry = document.getElementById("settings-sentry-dsn");
    if (inSentry) setPref("sentry_dsn", inSentry.value);
  });
}

// Call on init
loadAdvancedSettings();

// Platform Detection & macOS Native Enhancements
const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0 || navigator.userAgent.toUpperCase().indexOf("MAC") >= 0;
if (isMac) {
  document.body.classList.add("is-macos");
  document.querySelectorAll("[title]").forEach(el => {
    el.title = el.title.replace(/Ctrl\+/gi, "⌘");
  });
}

// Window Controls (Tauri or Browser)
document.querySelectorAll(".window-ctrl").forEach(btn => {
  btn.addEventListener("click", async () => {
    const isClose = btn.classList.contains("close");
    const title = btn.getAttribute("title") || "";
    if (window.__TAURI__?.window) {
      try {
        const win = window.__TAURI__.window.getCurrentWindow ? window.__TAURI__.window.getCurrentWindow() : window.__TAURI__.window.appWindow;
        if (isClose) {
          await win.close();
        } else if (title.includes("Minimize")) {
          await win.minimize();
        } else if (title.includes("Maximize")) {
          await win.toggleMaximize();
        }
        return;
      } catch (e) {
        console.warn("Tauri window control error:", e);
      }
    }
    if (isClose) {
      if (confirm("Close Ethos session?")) {
        window.close();
      }
    }
  });
});

// Global Keyboard Accelerators (Cross-Platform Cmd/Ctrl)
document.addEventListener("keydown", (e) => {
  const mod = isMac ? e.metaKey : e.ctrlKey;
  if (mod && e.key.toLowerCase() === "t") {
    e.preventDefault();
    setView("welcome");
  } else if (mod && e.key.toLowerCase() === "p") {
    e.preventDefault();
    setView(state.activeView === "sessions" ? "welcome" : "sessions");
  } else if (mod && e.key.toLowerCase() === "m") {
    e.preventDefault();
    state.menuOpen = !state.menuOpen;
    hamburgerMenu.style.display = state.menuOpen ? "block" : "none";
  } else if (mod && e.key === ",") {
    e.preventDefault();
    settingsModal.style.display = "flex";
    populateModelsSelect();
  } else if (e.key === "Escape") {
    if (settingsModal.style.display === "flex") {
      settingsModal.style.display = "none";
    } else if (state.menuOpen) {
      state.menuOpen = false;
      hamburgerMenu.style.display = "none";
    }
  }
});
