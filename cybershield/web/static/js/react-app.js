/**
 * CyberShield Enterprise - React 18 Enterprise SPA Architecture
 * Implements the 18-module navigation, JWT authentication, RBAC guarding,
 * interactive KPI metrics, SVG trend charts, user management, and audit log explorer.
 */

const { useState, useEffect, useMemo, useRef, createElement: h } = React;

// Global API Helper with Bearer Token Injection
const api = {
  getToken: () => localStorage.getItem("cybershield_token"),
  setToken: (token) => localStorage.setItem("cybershield_token", token),
  clearToken: () => localStorage.removeItem("cybershield_token"),

  async fetch(url, options = {}) {
    const token = this.getToken();
    const headers = { "Content-Type": "application/json", ...options.headers };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const resp = await window.fetch(url, { ...options, headers });
    if (resp.status === 401 && !url.includes("/api/auth/login")) {
      this.clearToken();
      window.dispatchEvent(new CustomEvent("auth:logout"));
    }
    return resp;
  }
};

// Main CyberShield React Application Component
function CyberShieldApp() {
  const [currentUser, setCurrentUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [activeNav, setActiveNav] = useState("dashboard");
  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [usernameInput, setUsernameInput] = useState("superadmin");
  const [passwordInput, setPasswordInput] = useState("CyberShield2026!");

  // Dashboard State
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [recentLogs, setRecentLogs] = useState([]);
  const [usersList, setUsersList] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [utcTime, setUtcTime] = useState("");

  // Clock
  useEffect(() => {
    const tick = () => setUtcTime(new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC");
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, []);

  // Auth Initialization
  useEffect(() => {
    const initAuth = async () => {
      const token = api.getToken();
      if (!token) {
        setAuthLoading(false);
        return;
      }
      try {
        const resp = await api.fetch("/api/auth/me");
        if (resp.ok) {
          const user = await resp.json();
          setCurrentUser(user);
        } else {
          api.clearToken();
        }
      } catch (err) {
        console.error("Auth init error:", err);
      } finally {
        setAuthLoading(false);
      }
    };
    initAuth();

    const handleLogout = () => {
      setCurrentUser(null);
      setLoginModalOpen(true);
    };
    window.addEventListener("auth:logout", handleLogout);
    return () => window.removeEventListener("auth:logout", handleLogout);
  }, []);

  // Real-time WebSocket connection
  useEffect(() => {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/ws/soc`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => setWsConnected(true);
    socket.onclose = () => setWsConnected(false);
    socket.onmessage = (evt) => {
      try {
        const packet = JSON.parse(evt.data);
        if (packet.type === "alert.new") {
          setAlerts(prev => [packet.data, ...prev.slice(0, 49)]);
        } else if (packet.type === "telemetry.normalized") {
          setRecentLogs(prev => [packet.data, ...prev.slice(0, 99)]);
        }
      } catch (e) {}
    };

    return () => socket.close();
  }, []);

  // Fetch Dashboard Telemetry
  const refreshData = async () => {
    try {
      const [mRes, aRes, iRes, lRes] = await Promise.all([
        api.fetch("/api/v1/system/metrics"),
        api.fetch("/api/v1/alerts?limit=50"),
        api.fetch("/api/v1/incidents"),
        api.fetch("/api/v1/telemetry/recent?limit=30"),
      ]);
      if (mRes.ok) setMetrics(await mRes.json());
      if (aRes.ok) setAlerts(await aRes.json());
      if (iRes.ok) setIncidents(await iRes.json());
      if (lRes.ok) setRecentLogs(await lRes.json());
    } catch (err) {
      console.error("Telemetry refresh failed:", err);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 10000);
    return () => clearInterval(interval);
  }, []);

  // Fetch Users when Users tab active
  useEffect(() => {
    if (activeNav === "users" && currentUser) {
      api.fetch("/api/users?page_size=50")
        .then(r => r.json())
        .then(d => setUsersList(d.items || []))
        .catch(console.error);
    } else if (activeNav === "audit" && currentUser) {
      api.fetch("/api/audit?page_size=50")
        .then(r => r.json())
        .then(d => setAuditLogs(d.items || []))
        .catch(console.error);
    }
  }, [activeNav, currentUser]);

  // Login handler
  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setLoginError("");
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username_or_email: usernameInput,
          password: passwordInput,
        })
      });
      const data = await res.json();
      if (!res.ok) {
        setLoginError(data.detail || "Authentication failed");
        return;
      }
      api.setToken(data.access_token);
      setCurrentUser(data.user);
      setLoginModalOpen(false);
      refreshData();
    } catch (err) {
      setLoginError("Network connection error");
    }
  };

  const handleLogout = async () => {
    try {
      await api.fetch("/api/auth/logout", { method: "POST" });
    } catch (e) {}
    api.clearToken();
    setCurrentUser(null);
  };

  // Trigger cyber attack simulation
  const triggerSimulation = async (scenario) => {
    try {
      await api.fetch(`/api/v1/simulation/${scenario}`, { method: "POST" });
      setTimeout(refreshData, 500);
    } catch (e) {}
  };

  // 18 Enterprise Sidebar Navigation Items
  const sidebarItems = [
    { id: "dashboard", label: "Dashboard", icon: "📊" },
    { id: "events", label: "Security Events", icon: "⚡" },
    { id: "alerts", label: "Alerts", icon: "🚨" },
    { id: "incidents", label: "Incidents", icon: "🛡️" },
    { id: "threats", label: "Threat Detection", icon: "🎯" },
    { id: "network", label: "Network", icon: "🌐" },
    { id: "devices", label: "Devices", icon: "💻" },
    { id: "ips", label: "IP Addresses", icon: "📍" },
    { id: "vulnerabilities", label: "Vulnerabilities", icon: "🔓" },
    { id: "intel", label: "Threat Intelligence", icon: "🧠" },
    { id: "phishing", label: "Email Security", icon: "📧" },
    { id: "malware", label: "Malware Analysis", icon: "🔬" },
    { id: "logs", label: "Logs", icon: "📜" },
    { id: "ml", label: "AI / ML", icon: "🤖" },
    { id: "pipelines", label: "Data Pipelines", icon: "🔄" },
    { id: "analytics", label: "Analytics", icon: "📈" },
    { id: "tasks", label: "Task Processing", icon: "⚙️" },
    { id: "compliance", label: "Compliance GRC", icon: "🏛️" },
    { id: "vault", label: "WORM Audit Vault", icon: "🔐" },
    { id: "reports", label: "Reports", icon: "📑" },
    { id: "health", label: "System Health", icon: "🩺" },
    { id: "users", label: "Users", icon: "👥" },
    { id: "audit", label: "Audit Logs", icon: "📋" },
    { id: "settings", label: "Settings", icon: "⚙️" },
  ];

  return h("div", { className: "app-wrapper" },
    // Sidebar
    h("aside", { className: "app-sidebar" },
      h("div", { className: "sidebar-brand" },
        h("div", { className: "brand-icon" }, "🛡️"),
        h("div", { className: "brand-text" },
          h("div", { className: "brand-name" }, "CYBERSHIELD"),
          h("div", { className: "brand-sub" }, "ENTERPRISE SOC")
        )
      ),

      h("nav", { className: "sidebar-nav" },
        sidebarItems.map(item =>
          h("button", {
            key: item.id,
            className: `sidebar-nav-item ${activeNav === item.id ? "active" : ""}`,
            onClick: () => setActiveNav(item.id)
          },
            h("span", { className: "nav-icon" }, item.icon),
            h("span", { className: "nav-label" }, item.label)
          )
        )
      ),

      h("div", { className: "sidebar-user-panel" },
        currentUser ? h("div", { className: "user-card" },
          h("div", { className: "user-avatar" }, currentUser.username[0].toUpperCase()),
          h("div", { className: "user-info" },
            h("div", { className: "user-name" }, currentUser.username),
            h("div", { className: "user-role-badge" }, currentUser.role)
          ),
          h("button", { className: "btn-logout", onClick: handleLogout, title: "Log Out" }, "🚪")
        ) : h("button", {
          className: "btn btn-primary btn-block",
          onClick: () => setLoginModalOpen(true)
        }, "🔐 Sign In")
      )
    ),

    // Main Content Area
    h("main", { className: "app-main" },
      // Top Status Bar
      h("header", { className: "main-topbar" },
        h("div", { className: "topbar-left" },
          h("h1", { className: "view-title" }, sidebarItems.find(i => i.id === activeNav)?.label || "Dashboard"),
          h("span", { className: "view-desc" }, "Autonomous AI Defense & SIEM Telemetry Console")
        ),
        h("div", { className: "topbar-right" },
          h("div", { className: "connection-pill" },
            h("span", { className: `conn-dot ${wsConnected ? "online" : "offline"}` }),
            h("span", null, wsConnected ? "BUS CONNECTED" : "RECONNECTING")
          ),
          h("div", { className: "utc-clock-badge" }, utcTime)
        )
      ),

      // Simulation Toolbar Strip
      h("div", { className: "sim-action-strip" },
        h("div", { className: "sim-label" }, "⚡ Live Threat Detonation Simulator:"),
        h("div", { className: "sim-btn-group" },
          h("button", { className: "btn btn-danger btn-sm", onClick: () => triggerSimulation("ransomware") }, "Detonate Ransomware"),
          h("button", { className: "btn btn-danger btn-sm", onClick: () => triggerSimulation("bruteforce") }, "Spray Brute Force"),
          h("button", { className: "btn btn-danger btn-sm", onClick: () => triggerSimulation("sqli") }, "Inject SQL Exploit"),
          h("button", { className: "btn btn-danger btn-sm", onClick: () => triggerSimulation("apt29") }, "Execute APT29 Hop"),
          h("button", { className: "btn btn-danger btn-sm", onClick: () => triggerSimulation("exfil") }, "Data Exfiltration")
        )
      ),

      // View Content Router
      h("div", { className: "view-container" },
        activeNav === "dashboard" && h(DashboardView, { metrics, alerts, incidents, recentLogs, onInspect: (a) => setActiveNav("alerts") }),
        activeNav === "alerts" && h(AlertsView, { currentUser, refreshGlobal: refreshData }),
        activeNav === "incidents" && h(IncidentsView, { currentUser, refreshGlobal: refreshData }),
        activeNav === "threats" && h(ThreatDetectionView, { currentUser }),
        activeNav === "events" && h(EventsView, { currentUser }),
        activeNav === "users" && h(UsersView, { users: usersList, currentUser, refresh: () => api.fetch("/api/users?page_size=50").then(r=>r.json()).then(d=>setUsersList(d.items||[])) }),
        activeNav === "audit" && h(AuditView, { auditLogs }),
        activeNav === "network" && h(NetworkTopologyView),
        activeNav === "devices" && h(DevicesView),
        activeNav === "ips" && h(IPManagementView),
        activeNav === "vulnerabilities" && h(VulnerabilitiesView, { currentUser }),
        activeNav === "intel" && h(ThreatIntelView, { currentUser }),
        activeNav === "phishing" && h(PhishingAnalysisView, { currentUser }),
        activeNav === "malware" && h(MalwareAnalysisView, { currentUser }),
        activeNav === "ml" && h(MLView),
        activeNav === "pipelines" && h(DataPipelinesView, { currentUser }),
        activeNav === "analytics" && h(SecurityAnalyticsView, { currentUser }),
        activeNav === "tasks" && h(TaskQueueView, { currentUser }),
        activeNav === "compliance" && h(ComplianceView, { currentUser }),
        activeNav === "vault" && h(AuditVaultView, { currentUser }),
        activeNav === "reports" && h(ReportsView, { currentUser }),
        activeNav === "health" && h(SystemHealthView, { currentUser }),
        activeNav === "settings" && h(SystemSettingsView, { currentUser }),
        !["dashboard", "alerts", "incidents", "threats", "events", "users", "audit", "network", "devices", "ips", "vulnerabilities", "intel", "phishing", "malware", "ml", "pipelines", "analytics", "tasks", "compliance", "vault", "reports", "health", "settings"].includes(activeNav) &&
          h(PlaceholderModuleView, { title: sidebarItems.find(i => i.id === activeNav)?.label })
      )
    ),

    // Authentication Modal
    loginModalOpen && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card auth-modal" },
        h("div", { className: "modal-header" },
          h("h3", null, "🔐 Enterprise Sign In"),
          h("button", { className: "modal-close", onClick: () => setLoginModalOpen(false) }, "✕")
        ),
        h("form", { onSubmit: handleLogin, className: "auth-form" },
          loginError && h("div", { className: "auth-error-alert" }, loginError),
          h("div", { className: "form-group" },
            h("label", null, "Username or Email:"),
            h("input", {
              type: "text",
              value: usernameInput,
              onChange: (e) => setUsernameInput(e.target.value),
              className: "input-field",
              required: true
            })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Password:"),
            h("input", {
              type: "password",
              value: passwordInput,
              onChange: (e) => setPasswordInput(e.target.value),
              className: "input-field",
              required: true
            })
          ),
          h("div", { className: "default-creds-hint" },
            "Default Super Admin: ", h("strong", null, "superadmin"), " / ", h("strong", null, "CyberShield2026!")
          ),
          h("button", { type: "submit", className: "btn btn-primary btn-block" }, "Authenticate Session")
        )
      )
    )
  );
}

// 1. Dashboard Main View
function DashboardView({ metrics, alerts, incidents, recentLogs, onInspect }) {
  const criticalCount = alerts.filter(a => a.severity === "CRITICAL").length;
  const highCount = alerts.filter(a => a.severity === "HIGH").length;

  return h("div", { className: "dashboard-grid" },
    // KPI Cards Row
    h("div", { className: "kpi-cards-row" },
      h("div", { className: `kpi-metric-box ${criticalCount > 0 ? "kpi-crit" : "kpi-safe"}` },
        h("div", { className: "metric-title" }, "DEFCON POSTURE"),
        h("div", { className: "metric-val" }, criticalCount > 0 ? "DEFCON 1" : "DEFCON 4"),
        h("div", { className: "metric-sub" }, criticalCount > 0 ? `${criticalCount} Critical Threats Active` : "System Guarded & Baseline Normal")
      ),
      h("div", { className: "kpi-metric-box" },
        h("div", { className: "metric-title" }, "ACTIVE SECURITY ALERTS"),
        h("div", { className: "metric-val" }, alerts.length),
        h("div", { className: "metric-sub" }, `${highCount} High, ${criticalCount} Critical`)
      ),
      h("div", { className: "kpi-metric-box" },
        h("div", { className: "metric-title" }, "ESCALATED INCIDENTS"),
        h("div", { className: "metric-val" }, incidents.length),
        h("div", { className: "metric-sub" }, "Correlated Attack Campaigns")
      ),
      h("div", { className: "kpi-metric-box" },
        h("div", { className: "metric-title" }, "TELEMETRY PROCESSED"),
        h("div", { className: "metric-val" }, (metrics?.ingestion?.total_ingested_events || recentLogs.length).toLocaleString()),
        h("div", { className: "metric-sub" }, "Sysmon, Zeek, Web, Syslog")
      ),
      h("div", { className: "kpi-metric-box kpi-safe" },
        h("div", { className: "metric-title" }, "MEAN TIME TO RESPOND"),
        h("div", { className: "metric-val" }, `${metrics?.incidents?.avg_mttr_minutes || 14.5}m`),
        h("div", { className: "metric-sub" }, "Autonomous SOAR Active")
      )
    ),

    // Middle Dual Column (Alerts Queue & Live Feed)
    h("div", { className: "dashboard-split-row" },
      // Left: Real-time Alert Table
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" },
          h("h3", null, "🚨 Active Alert Triage Stream"),
          h("span", { className: "badge badge-low" }, "LIVE FEED")
        ),
        h("div", { className: "table-responsive" },
          h("table", { className: "cyber-table" },
            h("thead", null,
              h("tr", null,
                h("th", null, "Severity"),
                h("th", null, "Title"),
                h("th", null, "Engine"),
                h("th", null, "Target"),
                h("th", null, "Status")
              )
            ),
            h("tbody", null,
              alerts.length === 0 ? h("tr", null, h("td", { colSpan: 5, className: "text-muted text-center" }, "No active alerts. System running clean.")) :
              alerts.slice(0, 8).map(a =>
                h("tr", { key: a.alert_id },
                  h("td", null, h("span", { className: `badge badge-${a.severity.toLowerCase()}` }, a.severity)),
                  h("td", null, h("strong", null, a.title)),
                  h("td", null, h("span", { className: "badge badge-info" }, a.detection_engine)),
                  h("td", null, h("code", null, a.impacted_host || a.primary_source_ip || "Internal Subnet")),
                  h("td", null, h("span", { className: "badge badge-low" }, a.status))
                )
              )
            )
          )
        )
      ),

      // Right: Live Telemetry Terminal
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" },
          h("h3", null, "📜 Ingested Telemetry Event Bus"),
          h("span", { className: "badge badge-info" }, "REAL-TIME")
        ),
        h("div", { className: "terminal-container" },
          recentLogs.length === 0 ? h("div", { className: "term-row" }, "[INIT] CyberShield Telemetry Normalization Bus ready.") :
          recentLogs.map((l, i) =>
            h("div", { key: i, className: "term-row" },
              h("span", { className: "term-time" }, `[${(l.timestamp || "").substring(11, 19)}]`),
              " ",
              h("span", { className: "term-tag" }, `<${l.log_source || "LOG"}>`),
              " ",
              h("span", null, `${l.event_action} | ${l.host_name || l.source_ip || "127.0.0.1"} | ${l.process_name || l.http_url || ""}`)
            )
          )
        )
      )
    )
  );
}

// 2. Comprehensive SOC Alerts Management View
function AlertsView({ currentUser, refreshGlobal }) {
  const [alerts, setAlerts] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [newNoteText, setNewNoteText] = useState("");
  const [escalateModal, setEscalateModal] = useState(false);
  const [escalateTarget, setEscalateTarget] = useState(null);
  const [escalateType, setEscalateType] = useState("MALWARE_INFECTION");
  const [escalatePlaybook, setEscalatePlaybook] = useState("IR-MALWARE-CONTAINMENT");
  const [escalateComment, setEscalateComment] = useState("");
  const [loading, setLoading] = useState(true);
  const [actionNotice, setActionNotice] = useState("");

  const showNotice = (msg) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(""), 4000);
  };

  const fetchAlerts = async () => {
    try {
      let url = `/api/alerts?page=${page}&page_size=25`;
      if (severityFilter !== "ALL") url += `&severity=${severityFilter}`;
      if (statusFilter !== "ALL") url += `&status=${statusFilter}`;
      if (search.trim()) url += `&search=${encodeURIComponent(search.trim())}`;

      const [res, kpiRes] = await Promise.all([
        api.fetch(url),
        api.fetch("/api/alerts/kpis")
      ]);

      if (res.ok) {
        const data = await res.json();
        setAlerts(data.items || []);
        setTotal(data.total || 0);
      }
      if (kpiRes.ok) {
        setKpis(await kpiRes.json());
      }
    } catch (e) {
      console.error("Alerts fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, [page, severityFilter, statusFilter, search]);

  const handleTriage = async (alertId, newStatus, assignee = null) => {
    try {
      const body = { status: newStatus };
      if (assignee !== null) body.assignee = assignee;
      const res = await api.fetch(`/api/alerts/${alertId}/triage`, {
        method: "POST",
        body: JSON.stringify(body)
      });
      if (res.ok) {
        const updated = await res.json();
        setAlerts(prev => prev.map(a => a.id === alertId ? updated : a));
        if (selectedAlert && selectedAlert.id === alertId) setSelectedAlert(updated);
        showNotice(`Alert ${alertId} transitioned to ${newStatus}`);
        if (refreshGlobal) refreshGlobal();
      }
    } catch (e) {
      alert("Triage update failed");
    }
  };

  const handleAddNote = async (alertId) => {
    if (!newNoteText.trim()) return;
    try {
      const res = await api.fetch(`/api/alerts/${alertId}/notes`, {
        method: "POST",
        body: JSON.stringify({
          author: currentUser?.username || "analyst",
          note: newNoteText.trim()
        })
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedAlert(updated);
        setAlerts(prev => prev.map(a => a.id === alertId ? updated : a));
        setNewNoteText("");
        showNotice("Analyst note appended.");
      }
    } catch (e) {
      alert("Failed to add note");
    }
  };

  const handleEscalate = async (e) => {
    e.preventDefault();
    if (!escalateTarget) return;
    try {
      const res = await api.fetch(`/api/alerts/${escalateTarget.id}/escalate`, {
        method: "POST",
        body: JSON.stringify({
          lead_analyst: currentUser?.username || "soc_lead",
          incident_type: escalateType,
          severity: escalateTarget.severity,
          playbook: escalatePlaybook,
          comment: escalateComment || "Escalated from SOC Alerts console"
        })
      });
      if (res.ok) {
        const data = await res.json();
        showNotice(`Incident Created: ${data.incident_id} for Alert ${escalateTarget.id}`);
        setEscalateModal(false);
        setEscalateTarget(null);
        fetchAlerts();
        if (refreshGlobal) refreshGlobal();
      } else {
        const err = await res.json();
        alert(err.detail || "Escalation failed");
      }
    } catch (e) {
      alert("Escalation request failed");
    }
  };

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Open Alerts"),
        h("div", { className: "kpi-val cyan" }, kpis.open_alerts),
        h("div", { className: "kpi-sub" }, `${kpis.unassigned_alerts} Unassigned in Queue`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Critical Threats"),
        h("div", { className: "kpi-val red" }, kpis.critical_alerts),
        h("div", { className: "kpi-sub" }, "Immediate SOC Action Required")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Active Incidents"),
        h("div", { className: "kpi-val orange" }, kpis.escalated_incidents),
        h("div", { className: "kpi-sub" }, "Correlated Attack Campaigns")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Avg Triage Time"),
        h("div", { className: "kpi-val green" }, `${kpis.avg_triage_time_min}m`),
        h("div", { className: "kpi-sub" }, `${kpis.suppression_count} Noise Suppression Rules`)
      )
    ),

    actionNotice && h("div", {
      style: {
        padding: "10px 16px",
        background: "var(--accent-subtle)",
        border: "1px solid var(--cyan-neon)",
        borderRadius: "6px",
        color: "var(--cyan-neon)",
        fontSize: "13px",
        display: "flex",
        alignItems: "center",
        gap: "8px"
      }
    }, "✓ " + actionNotice),

    h("div", { className: "panel-box" },
      h("div", { className: "panel-header", style: { flexWrap: "wrap", gap: "12px" } },
        h("div", { style: { display: "flex", alignItems: "center", gap: "12px" } },
          h("h3", null, "🚨 Enterprise Security Alert Triage Queue"),
          h("span", { className: "badge badge-info" }, `${total} Total Alerts`)
        ),
        h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" } },
          h("input", {
            type: "text",
            placeholder: "Search alerts, hosts, IPs...",
            value: search,
            onChange: (e) => setSearch(e.target.value),
            className: "csql-input",
            style: { width: "220px" }
          }),
          h("select", {
            value: severityFilter,
            onChange: (e) => setSeverityFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "5px 10px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Severities"),
            h("option", { value: "CRITICAL" }, "Critical Only"),
            h("option", { value: "HIGH" }, "High"),
            h("option", { value: "MEDIUM" }, "Medium"),
            h("option", { value: "LOW" }, "Low")
          ),
          h("select", {
            value: statusFilter,
            onChange: (e) => setStatusFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "5px 10px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Statuses"),
            h("option", { value: "NEW" }, "New"),
            h("option", { value: "TRIAGED" }, "Triaged"),
            h("option", { value: "INVESTIGATING" }, "Investigating"),
            h("option", { value: "ESCALATED" }, "Escalated"),
            h("option", { value: "RESOLVED" }, "Resolved"),
            h("option", { value: "FALSE_POSITIVE" }, "False Positive")
          ),
          h("button", { className: "btn btn-primary btn-sm", onClick: fetchAlerts }, "⟳ Refresh")
        )
      ),

      h("div", { className: "table-container" },
        h("table", { className: "cyber-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Severity"),
              h("th", null, "Alert Title & Category"),
              h("th", null, "Engine"),
              h("th", null, "Impacted Asset / IP"),
              h("th", null, "Status"),
              h("th", null, "Assignee"),
              h("th", null, "Actions")
            )
          ),
          h("tbody", null,
            loading ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "24px" } }, "Loading Security Alerts...")) :
            alerts.length === 0 ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "24px", color: "var(--text-muted)" } }, "No alerts found matching current filter.")) :
            alerts.map(a =>
              h("tr", { key: a.id, style: { cursor: "pointer" }, onClick: () => setSelectedAlert(a) },
                h("td", null, h("span", { className: `badge badge-${(a.severity || "LOW").toLowerCase()}` }, a.severity)),
                h("td", null,
                  h("div", { style: { fontWeight: "bold", color: "var(--text-primary)" } }, a.title),
                  h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, `${a.category} | ${a.created_at ? a.created_at.substring(0, 19).replace("T", " ") : ""}`)
                ),
                h("td", null, h("span", { className: "badge badge-info" }, a.detection_engine)),
                h("td", null,
                  h("code", null, a.impacted_host || a.source_ip || "Perimeter"),
                  a.destination_ip && h("span", { style: { fontSize: "11px", color: "var(--text-muted)", marginLeft: "4px" } }, `→ ${a.destination_ip}`)
                ),
                h("td", null, h("span", { className: `badge ${a.status === "NEW" ? "badge-critical" : a.status === "INVESTIGATING" ? "badge-high" : a.status === "RESOLVED" ? "badge-low" : "badge-info"}` }, a.status)),
                h("td", null, a.assignee ? h("strong", null, a.assignee) : h("span", { style: { color: "var(--text-muted)", fontStyle: "italic" } }, "Unassigned")),
                h("td", { onClick: (e) => e.stopPropagation() },
                  h("div", { style: { display: "flex", gap: "6px" } },
                    h("button", {
                      className: "btn btn-primary btn-sm",
                      onClick: () => setSelectedAlert(a),
                      title: "Open Triage Console"
                    }, "Inspect"),
                    a.status !== "ESCALATED" && a.status !== "RESOLVED" && h("button", {
                      className: "btn btn-danger btn-sm",
                      onClick: () => { setEscalateTarget(a); setEscalateModal(true); },
                      title: "Escalate to Incident"
                    }, "⚡ Escalate")
                  )
                )
              )
            )
          )
        )
      )
    ),

    selectedAlert && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "750px", maxHeight: "85vh", overflowY: "auto" } },
        h("div", { className: "modal-header" },
          h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
            h("span", { className: `badge badge-${(selectedAlert.severity || "LOW").toLowerCase()}` }, selectedAlert.severity),
            h("h3", null, selectedAlert.title)
          ),
          h("button", { className: "modal-close", onClick: () => setSelectedAlert(null) }, "✕")
        ),
        h("div", { style: { display: "flex", flexDirection: "column", gap: "16px", padding: "16px" } },
          h("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", background: "var(--bg-hover)", padding: "12px", borderRadius: "6px" } },
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "ALERT ID"), h("code", null, selectedAlert.id)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "STATUS"), h("span", { className: "badge badge-info" }, selectedAlert.status)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "DETECTION ENGINE"), h("strong", null, selectedAlert.detection_engine)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "CATEGORY"), selectedAlert.category),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "SOURCE IP / PORT"), h("code", null, `${selectedAlert.source_ip || 'N/A'}:${selectedAlert.source_port || '*'}`)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "DESTINATION IP / PORT"), h("code", null, `${selectedAlert.destination_ip || 'N/A'}:${selectedAlert.destination_port || '*'}`))
          ),

          h("div", null,
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "4px", color: "var(--cyan-neon)" } }, "Description:"),
            h("p", { style: { fontSize: "13px", color: "var(--text-primary)", background: "var(--bg-hover)", padding: "8px", borderRadius: "4px" } }, selectedAlert.description)
          ),

          (selectedAlert.mitre_tactics && selectedAlert.mitre_tactics.length > 0) && h("div", null,
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "4px", color: "var(--text-muted)" } }, "MITRE ATT&CK Matrix:"),
            h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
              selectedAlert.mitre_tactics.map(t => h("span", { key: t, className: "badge badge-high" }, `Tactic: ${t}`)),
              (selectedAlert.mitre_techniques || []).map(tc => h("span", { key: tc, className: "badge badge-info" }, `Technique: ${tc}`))
            )
          ),

          h("div", { style: { borderTop: "1px solid var(--border-color)", paddingTop: "14px" } },
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "8px" } }, "⚡ Rapid SOC Triage Operations:"),
            h("div", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
              h("button", {
                className: "btn btn-primary btn-sm",
                onClick: () => handleTriage(selectedAlert.id, "TRIAGED", currentUser?.username || "analyst")
              }, "Claim & Assign to Me"),
              h("button", {
                className: "btn btn-primary btn-sm",
                onClick: () => handleTriage(selectedAlert.id, "INVESTIGATING")
              }, "Start Investigation"),
              h("button", {
                className: "btn btn-primary btn-sm",
                style: { background: "var(--accent-subtle)", color: "var(--green-neon)", borderColor: "var(--green-neon)" },
                onClick: () => handleTriage(selectedAlert.id, "RESOLVED")
              }, "✓ Resolve Alert"),
              h("button", {
                className: "btn btn-sm",
                style: { background: "var(--bg-hover)", color: "var(--text-secondary)" },
                onClick: () => handleTriage(selectedAlert.id, "FALSE_POSITIVE")
              }, "Mark False Positive"),
              h("button", {
                className: "btn btn-danger btn-sm",
                onClick: () => { setEscalateTarget(selectedAlert); setEscalateModal(true); }
              }, "⚡ Escalate to Incident")
            )
          ),

          h("div", { style: { borderTop: "1px solid var(--border-color)", paddingTop: "14px" } },
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "8px" } }, `📝 Analyst Case Notes (${(selectedAlert.analyst_notes || []).length}):`),
            h("div", { style: { maxHeight: "140px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px", marginBottom: "10px" } },
              (selectedAlert.analyst_notes || []).length === 0 ? h("div", { style: { fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic" } }, "No notes recorded yet.") :
              selectedAlert.analyst_notes.map((n, i) =>
                h("div", { key: i, style: { background: "var(--bg-hover)", padding: "6px 10px", borderRadius: "4px", fontSize: "12px" } },
                  h("span", { style: { color: "var(--cyan-neon)", fontWeight: "bold" } }, `${n.author} `),
                  h("span", { style: { color: "var(--text-muted)", fontSize: "10px" } }, `(${(n.timestamp || "").substring(0, 19).replace("T", " ")}) : `),
                  h("span", null, n.note)
                )
              )
            ),
            h("div", { style: { display: "flex", gap: "8px" } },
              h("input", {
                type: "text",
                placeholder: "Add findings, forensic hashes, or containment notes...",
                value: newNoteText,
                onChange: (e) => setNewNoteText(e.target.value),
                onKeyDown: (e) => { if (e.key === "Enter") handleAddNote(selectedAlert.id); },
                className: "csql-input",
                style: { flex: 1 }
              }),
              h("button", { className: "btn btn-primary btn-sm", onClick: () => handleAddNote(selectedAlert.id) }, "Post Note")
            )
          )
        )
      )
    ),

    escalateModal && escalateTarget && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "480px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `⚡ Escalate Alert to Security Incident`),
          h("button", { className: "modal-close", onClick: () => setEscalateModal(false) }, "✕")
        ),
        h("form", { onSubmit: handleEscalate, className: "auth-form" },
          h("div", { style: { marginBottom: "12px", fontSize: "12px", color: "var(--text-secondary)" } },
            "Escalating: ", h("strong", { style: { color: "var(--text-primary)" } }, escalateTarget.title)
          ),
          h("div", { className: "form-group" },
            h("label", null, "Incident Type Classification:"),
            h("select", {
              className: "input-field",
              value: escalateType,
              onChange: (e) => setEscalateType(e.target.value)
            },
              h("option", { value: "MALWARE_INFECTION" }, "Malware Infection & Ransomware"),
              h("option", { value: "UNAUTHORIZED_ACCESS" }, "Unauthorized Access / Brute Force"),
              h("option", { value: "DATA_EXFILTRATION" }, "Data Exfiltration Breach"),
              h("option", { value: "DENIAL_OF_SERVICE" }, "Denial of Service (DoS/DDoS)"),
              h("option", { value: "APT_CAMPAIGN" }, "Advanced Persistent Threat (APT)")
            )
          ),
          h("div", { className: "form-group" },
            h("label", null, "Assigned Response Playbook:"),
            h("select", {
              className: "input-field",
              value: escalatePlaybook,
              onChange: (e) => setEscalatePlaybook(e.target.value)
            },
              h("option", { value: "IR-MALWARE-CONTAINMENT" }, "IR-01: Malware Containment & Host Isolation"),
              h("option", { value: "IR-ACCOUNT-TAKEOVER" }, "IR-02: Account Compromise & Credential Revocation"),
              h("option", { value: "IR-DATA-EXFILTRATION" }, "IR-03: Firewall Block & Data Breach Forensic"),
              h("option", { value: "IR-APT-REMEDIATION" }, "IR-04: Full Multi-Stage APT Eradication")
            )
          ),
          h("div", { className: "form-group" },
            h("label", null, "Analyst Initial Assessment:"),
            h("input", {
              type: "text",
              className: "input-field",
              placeholder: "Reason for escalation...",
              value: escalateComment,
              onChange: (e) => setEscalateComment(e.target.value)
            })
          ),
          h("button", { type: "submit", className: "btn btn-danger btn-block" }, "Confirm Incident Escalation")
        )
      )
    )
  );
}

// 3. Comprehensive Incident Command & SOAR Response View
function IncidentsView({ currentUser, refreshGlobal }) {
  const [incidents, setIncidents] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [phaseFilter, setPhaseFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState("");
  const [statusToSet, setStatusToSet] = useState("CONTAINED");
  const [statusComment, setStatusComment] = useState("");
  const [soarModal, setSoarModal] = useState(false);
  const [soarAction, setSoarAction] = useState("ISOLATE_HOST");
  const [soarTarget, setSoarTarget] = useState("");
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");

  const showNotice = (msg) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 4000);
  };

  const fetchIncidents = async () => {
    try {
      let url = `/api/incidents?page=${page}&page_size=25`;
      if (statusFilter !== "ALL") url += `&status=${statusFilter}`;
      if (severityFilter !== "ALL") url += `&severity=${severityFilter}`;
      if (typeFilter !== "ALL") url += `&incident_type=${typeFilter}`;
      if (phaseFilter !== "ALL") url += `&kill_chain_phase=${phaseFilter}`;
      if (search.trim()) url += `&search=${encodeURIComponent(search.trim())}`;

      const [res, kpiRes] = await Promise.all([
        api.fetch(url),
        api.fetch("/api/incidents/kpis")
      ]);

      if (res.ok) {
        const d = await res.json();
        setIncidents(d.items || []);
        setTotal(d.total || 0);
      }
      if (kpiRes.ok) {
        setKpis(await kpiRes.json());
      }
    } catch (e) {
      console.error("Incidents fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 10000);
    return () => clearInterval(interval);
  }, [page, statusFilter, severityFilter, typeFilter, phaseFilter, search]);

  const loadDossier = async (incId) => {
    try {
      const res = await api.fetch(`/api/incidents/${incId}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedIncident(data);
        setStatusToSet(data.status);
      }
    } catch (e) {
      alert("Failed to load incident dossier");
    }
  };

  const handleUpdateStatus = async () => {
    if (!selectedIncident) return;
    try {
      const res = await api.fetch(`/api/incidents/${selectedIncident.id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status: statusToSet, comment: statusComment })
      });
      if (res.ok) {
        showNotice(`Incident ${selectedIncident.id} transitioned to ${statusToSet}`);
        loadDossier(selectedIncident.id);
        fetchIncidents();
        if (refreshGlobal) refreshGlobal();
      }
    } catch (e) {
      alert("Failed to update status");
    }
  };

  const handleAddTimeline = async () => {
    if (!newNote.trim() || !selectedIncident) return;
    try {
      const res = await api.fetch(`/api/incidents/${selectedIncident.id}/timeline`, {
        method: "POST",
        body: JSON.stringify({
          action_type: "INVESTIGATION_NOTE",
          description: newNote.trim(),
        })
      });
      if (res.ok) {
        showNotice("Forensic timeline note appended.");
        setNewNote("");
        loadDossier(selectedIncident.id);
      }
    } catch (e) {
      alert("Failed to add note");
    }
  };

  const handleExecuteSOAR = async (e) => {
    if (e) e.preventDefault();
    if (!soarTarget.trim() || !selectedIncident) return;
    try {
      const res = await api.fetch(`/api/incidents/${selectedIncident.id}/contain`, {
        method: "POST",
        body: JSON.stringify({
          action_type: soarAction,
          target: soarTarget.trim(),
        })
      });
      if (res.ok) {
        const d = await res.json();
        showNotice(`SOAR containment executed: ${d.message}`);
        setSoarModal(false);
        loadDossier(selectedIncident.id);
        fetchIncidents();
        if (refreshGlobal) refreshGlobal();
      } else {
        const err = await res.json();
        alert(err.detail || "SOAR action failed");
      }
    } catch (e) {
      alert("SOAR execution request failed");
    }
  };

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Total Incidents"),
        h("div", { className: "kpi-val cyan" }, kpis.total_incidents),
        h("div", { className: "kpi-sub" }, `${kpis.open_incidents} Active Cases Under Triage`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Contained Threats"),
        h("div", { className: "kpi-val green" }, kpis.contained_incidents),
        h("div", { className: "kpi-sub" }, "Perimeter & Host Quarantines Active")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Critical Campaigns"),
        h("div", { className: "kpi-val red" }, kpis.critical_incidents),
        h("div", { className: "kpi-sub" }, "Severe Multi-Stage APT Activity")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Mean Time to Respond"),
        h("div", { className: "kpi-val orange" }, `${kpis.avg_mttr_minutes}m`),
        h("div", { className: "kpi-sub" }, `MTTD: ${kpis.avg_mttd_minutes}m | Autonomous SOAR`)
      )
    ),

    notice && h("div", {
      style: {
        padding: "10px 16px",
        background: "var(--accent-subtle)",
        border: "1px solid var(--cyan-neon)",
        borderRadius: "6px",
        color: "var(--cyan-neon)",
        fontSize: "13px"
      }
    }, "✓ " + notice),

    h("div", { className: "panel-box" },
      h("div", { className: "panel-header", style: { flexWrap: "wrap", gap: "12px" } },
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
          h("h3", null, "🛡️ Incident Response Cases & Kill-Chain Tracking"),
          h("span", { className: "badge badge-info" }, `${total} Cases`)
        ),
        h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap" } },
          h("input", {
            type: "text",
            placeholder: "Search incident ID, title, lead...",
            value: search,
            onChange: (e) => setSearch(e.target.value),
            className: "csql-input",
            style: { width: "220px" }
          }),
          h("select", {
            value: statusFilter,
            onChange: (e) => setStatusFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Statuses"),
            h("option", { value: "OPEN" }, "Open"),
            h("option", { value: "TRIAGED" }, "Triaged"),
            h("option", { value: "CONTAINED" }, "Contained"),
            h("option", { value: "ERADICATED" }, "Eradicated"),
            h("option", { value: "RECOVERED" }, "Recovered"),
            h("option", { value: "CLOSED" }, "Closed")
          ),
          h("select", {
            value: severityFilter,
            onChange: (e) => setSeverityFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Severities"),
            h("option", { value: "CRITICAL" }, "Critical"),
            h("option", { value: "HIGH" }, "High"),
            h("option", { value: "MEDIUM" }, "Medium"),
            h("option", { value: "LOW" }, "Low")
          ),
          h("button", { className: "btn btn-primary btn-sm", onClick: fetchIncidents }, "⟳ Refresh")
        )
      ),

      h("div", { className: "table-container" },
        h("table", { className: "cyber-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Severity"),
              h("th", null, "Incident ID & Campaign Title"),
              h("th", null, "Classification"),
              h("th", null, "Kill-Chain Phase"),
              h("th", null, "Lead Analyst"),
              h("th", null, "Status"),
              h("th", null, "Action")
            )
          ),
          h("tbody", null,
            loading ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px" } }, "Loading Incidents...")) :
            incidents.length === 0 ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px", color: "var(--text-muted)" } }, "No incidents match criteria.")) :
            incidents.map(inc =>
              h("tr", { key: inc.id, style: { cursor: "pointer" }, onClick: () => loadDossier(inc.id) },
                h("td", null, h("span", { className: `badge badge-${(inc.severity || "HIGH").toLowerCase()}` }, inc.severity)),
                h("td", null,
                  h("div", { style: { fontWeight: "bold", color: "var(--text-primary)" } }, `${inc.id} - ${inc.title}`),
                  h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, inc.summary ? inc.summary.substring(0, 90) + "..." : "")
                ),
                h("td", null, h("span", { className: "badge badge-info" }, (inc.incident_type || "").replace("_", " "))),
                h("td", null, h("span", { className: "badge badge-critical" }, inc.kill_chain_phase)),
                h("td", null, inc.lead_analyst),
                h("td", null, h("span", { className: `badge ${inc.status === "OPEN" ? "badge-critical" : inc.status === "CONTAINED" ? "badge-high" : "badge-low"}` }, inc.status)),
                h("td", { onClick: (e) => e.stopPropagation() },
                  h("button", {
                    className: "btn btn-primary btn-sm",
                    onClick: () => loadDossier(inc.id)
                  }, "Inspect Dossier")
                )
              )
            )
          )
        )
      )
    ),

    selectedIncident && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "800px", maxHeight: "88vh", overflowY: "auto" } },
        h("div", { className: "modal-header" },
          h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
            h("span", { className: `badge badge-${(selectedIncident.severity || "HIGH").toLowerCase()}` }, selectedIncident.severity),
            h("h3", null, `${selectedIncident.id}: ${selectedIncident.title}`)
          ),
          h("button", { className: "modal-close", onClick: () => setSelectedIncident(null) }, "✕")
        ),
        h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "16px" } },
          h("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", background: "var(--bg-hover)", padding: "12px", borderRadius: "6px" } },
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "STATUS"), h("span", { className: "badge badge-info" }, selectedIncident.status)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "KILL-CHAIN PHASE"), h("span", { className: "badge badge-critical" }, selectedIncident.kill_chain_phase)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "LEAD ANALYST"), h("strong", null, selectedIncident.lead_analyst)),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "ASSIGNED PLAYBOOK"), h("code", null, selectedIncident.assigned_playbook || "Standard IR")),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "CREATED"), (selectedIncident.created_at || "").substring(0, 19).replace("T", " ")),
            h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "LAST UPDATED"), (selectedIncident.updated_at || "").substring(0, 19).replace("T", " "))
          ),

          h("div", null,
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "4px", color: "var(--cyan-neon)" } }, "Attack Campaign Summary:"),
            h("p", { style: { fontSize: "13px", color: "var(--text-primary)", background: "var(--bg-hover)", padding: "10px", borderRadius: "6px" } }, selectedIncident.summary)
          ),

          h("div", { style: { display: "flex", gap: "20px", flexWrap: "wrap" } },
            h("div", { style: { flex: 1 } },
              h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "4px", color: "var(--text-muted)" } }, "Impacted Hosts & IP Endpoints:"),
              h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
                (selectedIncident.impacted_hosts || []).length === 0 ? h("span", { style: { color: "var(--text-muted)", fontSize: "12px" } }, "None specified") :
                selectedIncident.impacted_hosts.map(h_name => h("code", { key: h_name, style: { background: "var(--accent-subtle)", color: "var(--cyan-neon)", padding: "3px 8px", borderRadius: "4px" } }, h_name))
              )
            ),
            h("div", { style: { flex: 1 } },
              h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "4px", color: "var(--text-muted)" } }, "Compromised User Identities:"),
              h("div", { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
                (selectedIncident.impacted_users || []).length === 0 ? h("span", { style: { color: "var(--text-muted)", fontSize: "12px" } }, "None specified") :
                selectedIncident.impacted_users.map(u => h("span", { key: u, className: "badge badge-high" }, u))
              )
            )
          ),

          h("div", { style: { borderTop: "1px solid var(--border-color)", paddingTop: "14px" } },
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "8px", color: "var(--orange-warning)" } }, "⚡ Automated SOAR Containment Playbooks:"),
            h("div", { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
              h("button", {
                className: "btn btn-danger btn-sm",
                onClick: () => {
                  setSoarAction("ISOLATE_HOST");
                  setSoarTarget(selectedIncident.impacted_hosts?.[0] || "");
                  setSoarModal(true);
                }
              }, "⚡ Isolate Host (Quarantine Network)"),
              h("button", {
                className: "btn btn-danger btn-sm",
                onClick: () => {
                  setSoarAction("REVOKE_USER_CREDENTIALS");
                  setSoarTarget(selectedIncident.impacted_users?.[0] || "");
                  setSoarModal(true);
                }
              }, "🔒 Lock Compromised Account"),
              h("button", {
                className: "btn btn-danger btn-sm",
                onClick: () => {
                  setSoarAction("BLOCK_IP");
                  setSoarTarget("185.220.101.45");
                  setSoarModal(true);
                }
              }, "🛡️ Block IP on Edge Firewall")
            )
          ),

          h("div", { style: { borderTop: "1px solid var(--border-color)", paddingTop: "14px", display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" } },
            h("span", { style: { fontSize: "12px", fontWeight: "bold" } }, "Incident Lifecycle State:"),
            h("select", {
              value: statusToSet,
              onChange: (e) => setStatusToSet(e.target.value),
              style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "5px 10px", borderRadius: "4px" }
            },
              h("option", { value: "OPEN" }, "Open"),
              h("option", { value: "TRIAGED" }, "Triaged"),
              h("option", { value: "CONTAINED" }, "Contained"),
              h("option", { value: "ERADICATED" }, "Eradicated"),
              h("option", { value: "RECOVERED" }, "Recovered"),
              h("option", { value: "CLOSED" }, "Closed")
            ),
            h("input", {
              type: "text",
              placeholder: "Analyst transition comment...",
              value: statusComment,
              onChange: (e) => setStatusComment(e.target.value),
              className: "csql-input",
              style: { flex: 1, minWidth: "160px" }
            }),
            h("button", { className: "btn btn-primary btn-sm", onClick: handleUpdateStatus }, "Apply State")
          ),

          h("div", { style: { borderTop: "1px solid var(--border-color)", paddingTop: "14px" } },
            h("div", { style: { fontSize: "12px", fontWeight: "bold", marginBottom: "8px" } }, `📋 Forensic Investigation Timeline (${(selectedIncident.timeline || []).length} entries):`),
            h("div", { style: { maxHeight: "160px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px", marginBottom: "10px" } },
              (selectedIncident.timeline || []).map(t =>
                h("div", { key: t.id, style: { background: "var(--bg-hover)", padding: "8px 10px", borderRadius: "4px", fontSize: "12px" } },
                  h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "2px" } },
                    h("span", { style: { color: "var(--cyan-neon)", fontWeight: "bold" } }, `[${t.action_type}] ${t.author}`),
                    h("span", { style: { color: "var(--text-muted)", fontSize: "11px" } }, (t.timestamp || "").substring(0, 19).replace("T", " "))
                  ),
                  h("div", { style: { color: "var(--text-primary)" } }, t.description),
                  t.evidence_reference && h("div", { style: { fontSize: "10px", color: "var(--text-muted)", fontStyle: "italic", marginTop: "2px" } }, `Evidence: ${t.evidence_reference}`)
                )
              )
            ),
            h("div", { style: { display: "flex", gap: "8px" } },
              h("input", {
                type: "text",
                placeholder: "Append forensic evidence note or artifact hash...",
                value: newNote,
                onChange: (e) => setNewNote(e.target.value),
                onKeyDown: (e) => { if (e.key === "Enter") handleAddTimeline(); },
                className: "csql-input",
                style: { flex: 1 }
              }),
              h("button", { className: "btn btn-primary btn-sm", onClick: handleAddTimeline }, "Add Timeline Note")
            )
          )
        )
      )
    ),

    soarModal && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "460px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `⚡ Confirm SOAR Action: ${soarAction}`),
          h("button", { className: "modal-close", onClick: () => setSoarModal(false) }, "✕")
        ),
        h("form", { onSubmit: handleExecuteSOAR, className: "auth-form" },
          h("div", { className: "form-group" },
            h("label", null, "Target Asset or Identity:"),
            h("input", {
              type: "text",
              className: "input-field",
              value: soarTarget,
              onChange: (e) => setSoarTarget(e.target.value),
              required: true
            })
          ),
          h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginBottom: "12px" } },
            "Executing this action will immediately invoke enterprise perimeter and host quarantine controls."
          ),
          h("button", { type: "submit", className: "btn btn-danger btn-block" }, `Execute ${soarAction}`)
        )
      )
    )
  );
}

// 4. Threat Detection & Rules Management View
function ThreatDetectionView({ currentUser }) {
  const [rules, setRules] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selectedRule, setSelectedRule] = useState(null);
  const [createModal, setCreateModal] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleDesc, setNewRuleDesc] = useState("");
  const [newRuleType, setNewRuleType] = useState("SIGMA");
  const [newRuleSev, setNewRuleSev] = useState("HIGH");
  const [newRuleContent, setNewRuleContent] = useState(
`title: Suspicious PowerShell Process Spawn
status: stable
description: Detects suspicious PowerShell cradle invocation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'DownloadString'
            - 'Bypass'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001`
  );
  const [testModal, setTestModal] = useState(false);
  const [testContent, setTestContent] = useState(
`title: Mimikatz LSASS Memory Dump
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa'
            - 'logonpasswords'
    condition: selection
level: critical`
  );
  const [testMockCommand, setTestMockCommand] = useState("mimikatz.exe privilege::debug sekurlsa::logonpasswords exit");
  const [testResult, setTestResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [notice, setNotice] = useState("");

  const showNotice = (msg) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 4000);
  };

  const fetchRules = async () => {
    try {
      let url = `/api/detection/rules?page=${page}&page_size=50`;
      if (typeFilter !== "ALL") url += `&rule_type=${typeFilter}`;
      if (sevFilter !== "ALL") url += `&severity=${sevFilter}`;
      if (search.trim()) url += `&search=${encodeURIComponent(search.trim())}`;

      const [res, kpiRes] = await Promise.all([
        api.fetch(url),
        api.fetch("/api/detection/kpis")
      ]);

      if (res.ok) {
        const d = await res.json();
        setRules(d.items || []);
        setTotal(d.total || 0);
      }
      if (kpiRes.ok) {
        setKpis(await kpiRes.json());
      }
    } catch (e) {
      console.error("Rules fetch error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, [page, typeFilter, sevFilter, search]);

  const handleToggle = async (ruleId) => {
    try {
      const res = await api.fetch(`/api/detection/rules/${ruleId}/toggle`, { method: "POST" });
      if (res.ok) {
        const updated = await res.json();
        setRules(prev => prev.map(r => r.id === ruleId ? updated : r));
        showNotice(`Rule '${ruleId}' state updated to ${updated.is_enabled ? 'ENABLED' : 'DISABLED'}`);
      }
    } catch (e) {
      alert("Toggle failed");
    }
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    try {
      const res = await api.fetch("/api/detection/rules", {
        method: "POST",
        body: JSON.stringify({
          name: newRuleName,
          description: newRuleDesc,
          rule_type: newRuleType,
          severity: newRuleSev,
          raw_content: newRuleContent,
        })
      });
      if (res.ok) {
        showNotice("New detection rule compiled and registered.");
        setCreateModal(false);
        fetchRules();
      } else {
        const err = await res.json();
        alert(err.detail || "Failed to create rule");
      }
    } catch (e) {
      alert("Failed to submit rule");
    }
  };

  const handleDryRunTest = async () => {
    setTesting(true);
    try {
      const res = await api.fetch("/api/detection/rules/test", {
        method: "POST",
        body: JSON.stringify({
          rule_type: "SIGMA",
          raw_content: testContent,
          test_payload: {
            process_name: "powershell.exe",
            command_line: testMockCommand,
          }
        })
      });
      if (res.ok) {
        setTestResult(await res.json());
      }
    } catch (e) {
      alert("Dry-run test failed");
    } finally {
      setTesting(false);
    }
  };

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Active Signatures"),
        h("div", { className: "kpi-val cyan" }, kpis.active_rules),
        h("div", { className: "kpi-sub" }, `${kpis.total_rules} Total Rules in Engine`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Sigma AST Rules"),
        h("div", { className: "kpi-val purple" }, kpis.sigma_rules),
        h("div", { className: "kpi-sub" }, "Log & Telemetry Condition Matchers")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "YARA Scanners"),
        h("div", { className: "kpi-val orange" }, kpis.yara_rules),
        h("div", { className: "kpi-sub" }, "Payload & Binary Pattern Detectors")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Detections Triggered"),
        h("div", { className: "kpi-val green" }, (kpis.total_detections_triggered || 0).toLocaleString()),
        h("div", { className: "kpi-sub" }, "Autonomous Telemetry Hits")
      )
    ),

    notice && h("div", {
      style: {
        padding: "10px 16px",
        background: "var(--accent-subtle)",
        border: "1px solid var(--cyan-neon)",
        borderRadius: "6px",
        color: "var(--cyan-neon)",
        fontSize: "13px"
      }
    }, "✓ " + notice),

    h("div", { className: "panel-box" },
      h("div", { className: "panel-header", style: { flexWrap: "wrap", gap: "12px" } },
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
          h("h3", null, "🎯 Sigma & YARA Threat Detection Rules"),
          h("span", { className: "badge badge-info" }, `${total} Signatures`)
        ),
        h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap" } },
          h("input", {
            type: "text",
            placeholder: "Search rule name, ID, tactic...",
            value: search,
            onChange: (e) => setSearch(e.target.value),
            className: "csql-input",
            style: { width: "200px" }
          }),
          h("select", {
            value: typeFilter,
            onChange: (e) => setTypeFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Types"),
            h("option", { value: "SIGMA" }, "Sigma Only"),
            h("option", { value: "YARA" }, "YARA Only")
          ),
          h("select", {
            value: sevFilter,
            onChange: (e) => setSevFilter(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Severities"),
            h("option", { value: "CRITICAL" }, "Critical"),
            h("option", { value: "HIGH" }, "High"),
            h("option", { value: "MEDIUM" }, "Medium")
          ),
          h("button", { className: "btn btn-primary btn-sm", onClick: () => setCreateModal(true) }, "+ Create Rule"),
          h("button", { className: "btn btn-sm", style: { background: "var(--accent-subtle)", color: "var(--cyan-neon)" }, onClick: () => setTestModal(true) }, "⚡ Dry-Run Test")
        )
      ),

      h("div", { className: "table-container" },
        h("table", { className: "cyber-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Type"),
              h("th", null, "Rule ID & Title"),
              h("th", null, "Severity"),
              h("th", null, "MITRE ATT&CK Matrix"),
              h("th", null, "Hits"),
              h("th", null, "Status"),
              h("th", null, "Action")
            )
          ),
          h("tbody", null,
            loading ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px" } }, "Loading Rules...")) :
            rules.length === 0 ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px", color: "var(--text-muted)" } }, "No detection rules match criteria.")) :
            rules.map(r =>
              h("tr", { key: r.id, style: { cursor: "pointer" }, onClick: () => setSelectedRule(r) },
                h("td", null, h("span", { className: `badge ${r.rule_type === "SIGMA" ? "badge-info" : "badge-high"}` }, r.rule_type)),
                h("td", null,
                  h("div", { style: { fontWeight: "bold", color: "var(--text-primary)" } }, r.name),
                  h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, `${r.id} | ${r.description ? r.description.substring(0, 75) + "..." : ""}`)
                ),
                h("td", null, h("span", { className: `badge badge-${(r.severity || "MEDIUM").toLowerCase()}` }, r.severity)),
                h("td", null,
                  (r.mitre_tactics || []).slice(0, 2).map(t => h("span", { key: t, className: "badge badge-low", style: { marginRight: "4px" } }, t)),
                  (r.mitre_techniques || []).slice(0, 2).map(tc => h("code", { key: tc, style: { fontSize: "10px", marginLeft: "2px" } }, tc))
                ),
                h("td", null, h("span", { style: { color: r.match_count > 0 ? "var(--cyan-neon)" : "var(--text-muted)", fontWeight: "bold" } }, `⚡ ${r.match_count}`)),
                h("td", null, h("span", { className: `badge ${r.is_enabled ? "badge-low" : "badge-critical"}` }, r.is_enabled ? "ARMED" : "DISABLED")),
                h("td", { onClick: (e) => e.stopPropagation() },
                  h("div", { style: { display: "flex", gap: "6px" } },
                    h("button", {
                      className: "btn btn-sm",
                      style: { background: "var(--bg-hover)", color: "var(--text-primary)" },
                      onClick: () => setSelectedRule(r)
                    }, "Inspect"),
                    h("button", {
                      className: `btn btn-sm ${r.is_enabled ? "btn-danger" : "btn-primary"}`,
                      onClick: () => handleToggle(r.id)
                    }, r.is_enabled ? "Disable" : "Enable")
                  )
                )
              )
            )
          )
        )
      )
    ),

    selectedRule && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "720px", maxHeight: "85vh", overflowY: "auto" } },
        h("div", { className: "modal-header" },
          h("h3", null, `🔍 Detection Rule: ${selectedRule.name}`),
          h("button", { className: "modal-close", onClick: () => setSelectedRule(null) }, "✕")
        ),
        h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "12px" } },
          h("div", { style: { display: "flex", gap: "10px" } },
            h("span", { className: "badge badge-info" }, selectedRule.rule_type),
            h("span", { className: `badge badge-${(selectedRule.severity || "MEDIUM").toLowerCase()}` }, selectedRule.severity),
            h("span", { className: `badge ${selectedRule.is_enabled ? "badge-low" : "badge-critical"}` }, selectedRule.is_enabled ? "ARMED" : "DISABLED")
          ),
          h("div", null, h("strong", null, "Description: "), selectedRule.description),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" } }, "RAW DEFINITION (YAML / YARA):"),
            h("pre", {
              style: {
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                padding: "12px",
                borderRadius: "6px",
                fontFamily: "var(--font-mono)",
                fontSize: "11px",
                color: "var(--cyan-neon)",
                maxHeight: "220px",
                overflowY: "auto",
                whiteSpace: "pre-wrap"
              }
            }, selectedRule.raw_content)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" } }, "PARSED AST METADATA:"),
            h("pre", {
              style: {
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                padding: "10px",
                borderRadius: "6px",
                fontFamily: "var(--font-mono)",
                fontSize: "11px",
                color: "var(--text-secondary)",
                maxHeight: "140px",
                overflowY: "auto"
              }
            }, JSON.stringify(selectedRule.parsed_ast, null, 2))
          )
        )
      )
    ),

    createModal && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "600px" } },
        h("div", { className: "modal-header" },
          h("h3", null, "Create Custom Detection Rule"),
          h("button", { className: "modal-close", onClick: () => setCreateModal(false) }, "✕")
        ),
        h("form", { onSubmit: handleCreateRule, className: "auth-form" },
          h("div", { className: "form-group" },
            h("label", null, "Rule Name:"),
            h("input", {
              type: "text",
              className: "input-field",
              value: newRuleName,
              onChange: (e) => setNewRuleName(e.target.value),
              required: true
            })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Description:"),
            h("input", {
              type: "text",
              className: "input-field",
              value: newRuleDesc,
              onChange: (e) => setNewRuleDesc(e.target.value),
              required: true
            })
          ),
          h("div", { style: { display: "flex", gap: "10px" } },
            h("div", { className: "form-group", style: { flex: 1 } },
              h("label", null, "Format:"),
              h("select", {
                className: "input-field",
                value: newRuleType,
                onChange: (e) => setNewRuleType(e.target.value)
              },
                h("option", { value: "SIGMA" }, "Sigma YAML"),
                h("option", { value: "YARA" }, "YARA Signature")
              )
            ),
            h("div", { className: "form-group", style: { flex: 1 } },
              h("label", null, "Severity:"),
              h("select", {
                className: "input-field",
                value: newRuleSev,
                onChange: (e) => setNewRuleSev(e.target.value)
              },
                h("option", { value: "CRITICAL" }, "Critical"),
                h("option", { value: "HIGH" }, "High"),
                h("option", { value: "MEDIUM" }, "Medium"),
                h("option", { value: "LOW" }, "Low")
              )
            )
          ),
          h("div", { className: "form-group" },
            h("label", null, "Rule Definition:"),
            h("textarea", {
              className: "input-field",
              rows: 8,
              style: { fontFamily: "var(--font-mono)", fontSize: "11px" },
              value: newRuleContent,
              onChange: (e) => setNewRuleContent(e.target.value),
              required: true
            })
          ),
          h("button", { type: "submit", className: "btn btn-primary btn-block" }, "Register & Compile Rule")
        )
      )
    ),

    testModal && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "650px" } },
        h("div", { className: "modal-header" },
          h("h3", null, "⚡ Detection Rule Dry-Run Test Console"),
          h("button", { className: "modal-close", onClick: () => setTestModal(false) }, "✕")
        ),
        h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "12px" } },
          h("div", { className: "form-group" },
            h("label", null, "Sigma Rule Syntax:"),
            h("textarea", {
              className: "input-field",
              rows: 6,
              style: { fontFamily: "var(--font-mono)", fontSize: "11px" },
              value: testContent,
              onChange: (e) => setTestContent(e.target.value)
            })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Mock Telemetry Command Line:"),
            h("input", {
              type: "text",
              className: "input-field",
              style: { fontFamily: "var(--font-mono)" },
              value: testMockCommand,
              onChange: (e) => setTestMockCommand(e.target.value)
            })
          ),
          h("button", {
            className: "btn btn-primary",
            disabled: testing,
            onClick: handleDryRunTest
          }, testing ? "Evaluating AST..." : "Run Dry-Run Verification"),

          testResult && h("div", {
            style: {
              marginTop: "10px",
              padding: "12px",
              borderRadius: "6px",
              background: testResult.matched ? "rgba(0, 255, 136, 0.1)" : "rgba(255, 51, 102, 0.1)",
              border: testResult.matched ? "1px solid var(--green-neon)" : "1px solid var(--red-critical)"
            }
          },
            h("div", { style: { fontWeight: "bold", color: testResult.matched ? "var(--green-neon)" : "var(--red-critical)" } },
              testResult.matched ? "✓ MATCH DETECTED (Alert Would Be Triggered)" : "✕ NO MATCH (Telemetry Bypassed Condition)"
            ),
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" } },
              `Execution time: ${testResult.execution_time_ms}ms | Details: ${testResult.details || testResult.error || 'N/A'}`
            )
          )
        )
      )
    )
  );
}

// 4. Real-Time Telemetry Stream & CS-QL Query Console
function EventsView({ currentUser }) {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [total, setTotal] = useState(0);
  const [csqlQuery, setCsqlQuery] = useState("");
  const [csqlMeta, setCsqlMeta] = useState(null);
  const [selectedSource, setSelectedSource] = useState("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [ingesting, setIngesting] = useState(false);
  const [notice, setNotice] = useState("");

  const showNotice = (msg) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 4000);
  };

  const fetchEvents = async () => {
    try {
      let url = "/api/events?page=1&page_size=50";
      if (selectedSource !== "ALL") url += `&source_type=${selectedSource}`;
      if (selectedSeverity !== "ALL") url += `&severity=${selectedSeverity}`;

      const [evRes, stRes] = await Promise.all([
        api.fetch(url),
        api.fetch("/api/events/stats")
      ]);

      if (evRes.ok) {
        const data = await evRes.json();
        setEvents(data.items || []);
        setTotal(data.total || 0);
      }
      if (stRes.ok) {
        setStats(await stRes.json());
      }
    } catch (e) {
      console.error("Fetch events error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [selectedSource, selectedSeverity]);

  const runCSQL = async (queryToRun) => {
    const q = queryToRun !== undefined ? queryToRun : csqlQuery;
    if (!q.trim()) {
      setCsqlMeta(null);
      fetchEvents();
      return;
    }
    setLoading(true);
    try {
      const res = await api.fetch("/api/events/csql", {
        method: "POST",
        body: JSON.stringify({ query: q.trim(), limit: 50 })
      });
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setTotal(data.matched_count);
        setCsqlMeta({
          matched: data.matched_count,
          timeMs: data.execution_time_ms,
          query: data.query
        });
      } else {
        const err = await res.json();
        alert(`CS-QL Error: ${err.detail || 'Query execution failed'}`);
      }
    } catch (e) {
      alert("Failed to execute CS-QL query");
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateBatch = async () => {
    setIngesting(true);
    try {
      const sampleEvents = [
        {
          source_type: "SURICATA_EVE",
          event_action: "ET MALWARE Suspicious Inbound CobaltStrike Beaconing",
          severity: "CRITICAL",
          source_ip: "185.220.101.45",
          source_port: 54122,
          destination_ip: "10.0.10.15",
          destination_port: 443,
          protocol: "TCP",
          event_data: { flow_id: 99182312, alert: { action: "allowed", gid: 1, signature_id: 2024101, rev: 4 } },
          raw_log: '{"timestamp":"2026-09-12T10:00:00Z","event_type":"alert","src_ip":"185.220.101.45","dest_ip":"10.0.10.15","proto":"TCP","alert":{"signature":"ET MALWARE Suspicious Inbound CobaltStrike Beaconing","severity":1}}'
        },
        {
          source_type: "WINDOWS_SECURITY",
          event_action: "AUDIT_FAILURE_LOGON_ATTEMPT",
          severity: "HIGH",
          source_ip: "192.168.1.188",
          user_name: "admin_backup",
          host_name: "DC-PRIMARY.CORP",
          event_data: { EventID: 4625, FailureReason: "%%2313 - Unknown user name or bad password", LogonType: 3 },
          raw_log: 'An account failed to log on. Subject: User admin_backup, Failure Reason: Unknown user name or bad password (Event 4625)'
        },
        {
          source_type: "NETFLOW",
          event_action: "EXFILTRATION_BURST_DETECTED",
          severity: "HIGH",
          source_ip: "10.0.10.22",
          source_port: 49201,
          destination_ip: "91.108.4.1",
          destination_port: 8080,
          protocol: "TCP",
          bytes_transferred: 145892000,
          packets_transferred: 98120,
          event_data: { duration_sec: 14, bytes: 145892000, anomaly_type: "high_egress_burst" },
          raw_log: 'NetFlow v9 Flow Record: 10.0.10.22:49201 -> 91.108.4.1:8080 Proto 6 Bytes 145892000 Pkts 98120'
        }
      ];

      const res = await api.fetch("/api/events/ingest", {
        method: "POST",
        body: JSON.stringify({ events: sampleEvents })
      });

      if (res.ok) {
        const d = await res.json();
        showNotice(`Ingested ${d.ingested_count} SIEM telemetry events into normalized store.`);
        fetchEvents();
      }
    } catch (e) {
      alert("Telemetry ingestion failed");
    } finally {
      setIngesting(false);
    }
  };

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    stats && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Ingested Events"),
        h("div", { className: "kpi-val cyan" }, (stats.total_events || 0).toLocaleString()),
        h("div", { className: "kpi-sub" }, "Normalized SIEM Event Store")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Ingestion Rate"),
        h("div", { className: "kpi-val green" }, `${stats.events_per_second || 0} EPS`),
        h("div", { className: "kpi-sub" }, "Zero-Loss Pipeline Active")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Suricata IDS Feed"),
        h("div", { className: "kpi-val purple" }, stats.source_distribution?.SURICATA_EVE || 0),
        h("div", { className: "kpi-sub" }, "Signature & Flow Telemetry")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Windows Audit Logs"),
        h("div", { className: "kpi-val orange" }, stats.source_distribution?.WINDOWS_SECURITY || 0),
        h("div", { className: "kpi-sub" }, "Event 4624 / 4625 / 4688 / 1102")
      )
    ),

    notice && h("div", {
      style: {
        padding: "10px 16px",
        background: "var(--accent-subtle)",
        border: "1px solid var(--cyan-neon)",
        borderRadius: "6px",
        color: "var(--cyan-neon)",
        fontSize: "13px"
      }
    }, "✓ " + notice),

    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "⚡ CS-QL (CyberShield Query Language) Console"),
        h("button", {
          className: "btn btn-primary btn-sm",
          disabled: ingesting,
          onClick: handleSimulateBatch
        }, ingesting ? "⏳ Ingesting..." : "⚡ Simulate SIEM Telemetry Batch")
      ),
      h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "12px" } },
        h("div", { style: { display: "flex", gap: "10px" } },
          h("input", {
            type: "text",
            className: "csql-input",
            placeholder: 'CS-QL syntax: severity = "HIGH" AND protocol = "TCP" or source_type = "SURICATA_EVE"',
            value: csqlQuery,
            onChange: (e) => setCsqlQuery(e.target.value),
            onKeyDown: (e) => { if (e.key === "Enter") runCSQL(); },
            style: { flex: 1, fontFamily: "var(--font-mono)" }
          }),
          h("button", { className: "btn btn-primary", onClick: () => runCSQL() }, "Execute CS-QL"),
          csqlQuery && h("button", {
            className: "btn btn-sm",
            style: { background: "var(--bg-hover)", color: "var(--text-secondary)" },
            onClick: () => { setCsqlQuery(""); setCsqlMeta(null); fetchEvents(); }
          }, "Clear")
        ),

        h("div", { style: { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" } },
          h("span", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "Quick Filters:"),
          [
            { label: "Critical Severity", q: 'severity = "CRITICAL"' },
            { label: "High Severity", q: 'severity = "HIGH"' },
            { label: "Suricata IDS", q: 'source_type = "SURICATA_EVE"' },
            { label: "Windows Security", q: 'source_type = "WINDOWS_SECURITY"' },
            { label: "NetFlow Traffic", q: 'source_type = "NETFLOW"' },
            { label: "Port 443 / HTTPS", q: 'destination_port = 443' }
          ].map(p =>
            h("button", {
              key: p.label,
              className: "filter-btn",
              onClick: () => { setCsqlQuery(p.q); runCSQL(p.q); }
            }, p.label)
          )
        ),

        csqlMeta && h("div", { style: { fontSize: "12px", color: "var(--green-neon)", fontFamily: "var(--font-mono)" } },
          `⚡ CS-QL query matched ${csqlMeta.matched} records in ${csqlMeta.timeMs}ms`
        )
      )
    ),

    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
          h("h3", null, "Unified Security Event Telemetry Stream"),
          h("span", { className: "badge badge-info" }, `${total} Records`)
        ),
        h("div", { style: { display: "flex", gap: "10px" } },
          h("select", {
            value: selectedSource,
            onChange: (e) => setSelectedSource(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Log Sources"),
            h("option", { value: "SURICATA_EVE" }, "Suricata EVE"),
            h("option", { value: "WINDOWS_SECURITY" }, "Windows Security"),
            h("option", { value: "NETFLOW" }, "NetFlow / IPFIX"),
            h("option", { value: "ZEEK_CONN" }, "Zeek Connection")
          ),
          h("select", {
            value: selectedSeverity,
            onChange: (e) => setSelectedSeverity(e.target.value),
            style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
          },
            h("option", { value: "ALL" }, "All Severities"),
            h("option", { value: "CRITICAL" }, "Critical"),
            h("option", { value: "HIGH" }, "High"),
            h("option", { value: "MEDIUM" }, "Medium"),
            h("option", { value: "LOW" }, "Low")
          )
        )
      ),

      h("div", { className: "table-container" },
        h("table", { className: "cyber-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Timestamp"),
              h("th", null, "Source"),
              h("th", null, "Action / Signature"),
              h("th", null, "Host / Source -> Dest"),
              h("th", null, "User"),
              h("th", null, "Severity"),
              h("th", null, "Payload")
            )
          ),
          h("tbody", null,
            loading ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px" } }, "Querying telemetry events...")) :
            events.length === 0 ? h("tr", null, h("td", { colSpan: "7", style: { textAlign: "center", padding: "20px", color: "var(--text-muted)" } }, "No events match current filter.")) :
            events.map((ev, idx) =>
              h("tr", { key: ev.id || idx },
                h("td", null, h("span", { style: { fontFamily: "var(--font-mono)", fontSize: "11px" } }, (ev.timestamp || "").substring(11, 19))),
                h("td", null, h("span", { className: "badge badge-info" }, ev.source_type)),
                h("td", null,
                  h("strong", { style: { color: "var(--text-primary)" } }, ev.event_action),
                  ev.protocol && h("span", { style: { fontSize: "10px", color: "var(--text-muted)", marginLeft: "6px" } }, `[${ev.protocol}]`)
                ),
                h("td", null,
                  h("code", null, ev.host_name || ev.source_ip || "Internal"),
                  ev.destination_ip && h("span", { style: { color: "var(--text-muted)", fontSize: "11px" } }, ` → ${ev.destination_ip}:${ev.destination_port || '*'}`)
                ),
                h("td", null, ev.user_name || h("span", { style: { color: "var(--text-muted)" } }, "SYSTEM")),
                h("td", null, h("span", { className: `badge badge-${(ev.severity || "LOW").toLowerCase()}` }, ev.severity)),
                h("td", null,
                  h("button", {
                    className: "btn btn-sm",
                    style: { background: "var(--bg-hover)", color: "var(--cyan-neon)", fontSize: "10px", padding: "3px 8px" },
                    onClick: () => setSelectedEvent(ev)
                  }, "JSON")
                )
              )
            )
          )
        )
      )
    ),

    selectedEvent && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "700px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `🔍 Raw Event Inspector: ${selectedEvent.source_type}`),
          h("button", { className: "modal-close", onClick: () => setSelectedEvent(null) }, "✕")
        ),
        h("div", { style: { padding: "16px" } },
          h("div", { style: { marginBottom: "10px", display: "flex", gap: "10px" } },
            h("span", { className: "badge badge-info" }, selectedEvent.source_type),
            h("span", { className: `badge badge-${(selectedEvent.severity || "LOW").toLowerCase()}` }, selectedEvent.severity),
            h("span", { style: { fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--text-muted)" } }, selectedEvent.timestamp)
          ),
          h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" } }, "NORMALIZED EVENT OBJECT:"),
          h("pre", {
            style: {
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-color)",
              padding: "12px",
              borderRadius: "6px",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "var(--cyan-neon)",
              maxHeight: "260px",
              overflowY: "auto",
              whiteSpace: "pre-wrap"
            }
          }, JSON.stringify(selectedEvent, null, 2)),
          selectedEvent.raw_log && h("div", { style: { marginTop: "12px" } },
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" } }, "ORIGINAL LOG STRING:"),
            h("pre", {
              style: {
                background: "var(--bg-secondary)",
                border: "1px solid var(--border-color)",
                padding: "10px",
                borderRadius: "6px",
                fontFamily: "var(--font-mono)",
                fontSize: "11px",
                color: "var(--text-primary)",
                maxHeight: "100px",
                overflowY: "auto",
                whiteSpace: "pre-wrap"
              }
            }, selectedEvent.raw_log)
          )
        )
      )
    )
  );
}

// 5. Users Administration View
function UsersView({ users, currentUser, refresh }) {
  const [createModal, setCreateModal] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newFullName, setNewFullName] = useState("");
  const [newRole, setNewRole] = useState("SECURITY_ANALYST");
  const [createError, setCreateError] = useState("");

  const handleCreate = async (e) => {
    e.preventDefault();
    setCreateError("");
    try {
      const res = await api.fetch("/api/users", {
        method: "POST",
        body: JSON.stringify({
          username: newUsername,
          email: newEmail,
          password: newPassword,
          full_name: newFullName,
          role: newRole,
        })
      });
      if (!res.ok) {
        const d = await res.json();
        setCreateError(d.detail || "Failed to create user");
        return;
      }
      setCreateModal(false);
      refresh();
    } catch (err) {
      setCreateError("Error communicating with server");
    }
  };

  const handleUnlock = async (userId) => {
    try {
      await api.fetch(`/api/users/${userId}/unlock`, { method: "POST" });
      refresh();
    } catch (e) {}
  };

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" },
      h("h3", null, "Enterprise User Accounts & Role-Based Access Control"),
      h("button", { className: "btn btn-primary btn-sm", onClick: () => setCreateModal(true) }, "+ Create User")
    ),

    h("div", { className: "table-responsive" },
      h("table", { className: "cyber-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "ID"),
            h("th", null, "Username"),
            h("th", null, "Email"),
            h("th", null, "Role"),
            h("th", null, "Active Status"),
            h("th", null, "Lockout Status"),
            h("th", null, "Actions")
          )
        ),
        h("tbody", null,
          users.map(u =>
            h("tr", { key: u.id },
              h("td", null, u.id),
              h("td", null, h("strong", null, u.username)),
              h("td", null, u.email),
              h("td", null, h("span", { className: "badge badge-info" }, u.role)),
              h("td", null, h("span", { className: `badge ${u.is_active ? "badge-low" : "badge-critical"}` }, u.is_active ? "ACTIVE" : "INACTIVE")),
              h("td", null, h("span", { className: `badge ${u.is_locked ? "badge-critical" : "badge-low"}` }, u.is_locked ? "LOCKED" : "NORMAL")),
              h("td", null,
                u.is_locked && h("button", {
                  className: "btn btn-danger btn-sm",
                  onClick: () => handleUnlock(u.id)
                }, "Unlock Account")
              )
            )
          )
        )
      )
    ),

    // Create User Modal
    createModal && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card" },
        h("div", { className: "modal-header" },
          h("h3", null, "Create Enterprise User"),
          h("button", { className: "modal-close", onClick: () => setCreateModal(false) }, "✕")
        ),
        h("form", { onSubmit: handleCreate, className: "auth-form" },
          createError && h("div", { className: "auth-error-alert" }, createError),
          h("div", { className: "form-group" },
            h("label", null, "Username:"),
            h("input", { type: "text", className: "input-field", required: true, value: newUsername, onChange: e => setNewUsername(e.target.value) })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Email:"),
            h("input", { type: "email", className: "input-field", required: true, value: newEmail, onChange: e => setNewEmail(e.target.value) })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Full Name:"),
            h("input", { type: "text", className: "input-field", required: true, value: newFullName, onChange: e => setNewFullName(e.target.value) })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Password:"),
            h("input", { type: "password", className: "input-field", required: true, value: newPassword, onChange: e => setNewPassword(e.target.value) })
          ),
          h("div", { className: "form-group" },
            h("label", null, "Assigned Role:"),
            h("select", { className: "input-field", value: newRole, onChange: e => setNewRole(e.target.value) },
              h("option", { value: "SUPER_ADMIN" }, "Super Admin"),
              h("option", { value: "SECURITY_ADMIN" }, "Security Administrator"),
              h("option", { value: "SECURITY_ANALYST" }, "Security Analyst"),
              h("option", { value: "NETWORK_ANALYST" }, "Network Analyst"),
              h("option", { value: "INCIDENT_RESPONDER" }, "Incident Responder"),
              h("option", { value: "VIEWER" }, "Viewer (Read Only)")
            )
          ),
          h("button", { type: "submit", className: "btn btn-primary btn-block" }, "Create Account")
        )
      )
    )
  );
}

// 6. Audit Trail View
function AuditView({ auditLogs }) {
  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" },
      h("h3", null, "Immutable Compliance Audit Trail (Scrubbed & Sanitized)")
    ),
    h("div", { className: "table-responsive" },
      h("table", { className: "cyber-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "Timestamp"),
            h("th", null, "User"),
            h("th", null, "Action"),
            h("th", null, "Resource"),
            h("th", null, "IP Address"),
            h("th", null, "Status")
          )
        ),
        h("tbody", null,
          auditLogs.map(a =>
            h("tr", { key: a.id },
              h("td", null, (a.timestamp || "").substring(0, 19).replace("T", " ")),
              h("td", null, h("strong", null, a.username)),
              h("td", null, h("span", { className: "badge badge-info" }, a.action)),
              h("td", null, h("code", null, a.resource)),
              h("td", null, a.ip_address || "127.0.0.1"),
              h("td", null, h("span", { className: `badge ${a.status === "SUCCESS" ? "badge-low" : "badge-critical"}` }, a.status))
            )
          )
        )
      )
    )
  );
}

// 7. Interactive Network Topology View
function NetworkTopologyView() {
  const [topology, setTopology] = useState(null);
  const [summary, setSummary] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchTopology = async () => {
    try {
      const [topRes, sumRes] = await Promise.all([
        api.fetch("/api/network/topology"),
        api.fetch("/api/network/summary"),
      ]);
      if (topRes.ok) setTopology(await topRes.json());
      if (sumRes.ok) setSummary(await sumRes.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTopology();
    const interval = setInterval(fetchTopology, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleIsolate = async (nodeId) => {
    if (!window.confirm(`Initiate emergency host network containment on ${nodeId}?`)) return;
    try {
      await api.fetch(`/api/devices/${nodeId}/isolate`, {
        method: "POST",
        body: JSON.stringify({ reason: "SOC manual quarantine trigger via topology console" })
      });
      fetchTopology();
      setSelectedNode(null);
    } catch (e) {
      alert("Failed to isolate device");
    }
  };

  const handleUnquarantine = async (nodeId) => {
    try {
      await api.fetch(`/api/devices/${nodeId}/unquarantine`, { method: "POST" });
      fetchTopology();
      setSelectedNode(null);
    } catch (e) {
      alert("Failed to restore device");
    }
  };

  if (loading || !topology) {
    return h("div", { className: "panel-box", style: { padding: "40px", textAlign: "center" } }, "Loading Enterprise Network Topology...");
  }

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    // Summary KPI Bar
    summary && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Managed Devices"),
        h("div", { className: "kpi-val cyan" }, summary.total_devices),
        h("div", { className: "kpi-sub" }, `${summary.online_devices} Online / ${summary.isolated_devices} Isolated`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Network Health"),
        h("div", { className: "kpi-val green" }, `${summary.network_health_pct}%`),
        h("div", { className: "kpi-sub" }, "Perimeter & Spine Operational")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Subnets Monitored"),
        h("div", { className: "kpi-val purple" }, summary.subnets_count),
        h("div", { className: "kpi-sub" }, `${summary.total_allocated_ips} Active IP Bindings`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Total Throughput"),
        h("div", { className: "kpi-val orange" }, `${summary.current_throughput_mbps} Mbps`),
        h("div", { className: "kpi-sub" }, `Capacity: ${summary.total_bandwidth_capacity_gbps} Gbps`)
      )
    ),

    // SVG Topology Canvas Panel
    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "🌐 Enterprise Hierarchical & Spine Topology (10 Gbps Backbone)"),
        h("div", { style: { fontSize: "12px", color: "var(--text-muted)" } }, "Click any node to inspect telemetry and trigger host containment.")
      ),
      h("div", { style: { padding: "16px", background: "radial-gradient(circle at center, rgba(124, 58, 237, 0.02) 0%, #FAFAFA 100%)", borderRadius: "8px" } },
        h("svg", {
          viewBox: "0 0 820 480",
          style: { width: "100%", height: "460px", display: "block" }
        },
          // Grid lines
          h("defs", null,
            h("pattern", { id: "top-grid", width: "40", height: "40", patternUnits: "userSpaceOnUse" },
              h("path", { d: "M 40 0 L 0 0 0 40", fill: "none", stroke: "rgba(255,255,255,0.03)", strokeWidth: "1" })
            )
          ),
          h("rect", { width: "820", height: "480", fill: "url(#top-grid)" }),

          // Topology Edges (Links)
          topology.edges.map(e => {
            const src = topology.nodes.find(n => n.id === e.source);
            const dst = topology.nodes.find(n => n.id === e.target);
            if (!src || !dst) return null;
            const isUp = e.status === "UP";
            return h("g", { key: e.id },
              h("line", {
                x1: src.x, y1: src.y,
                x2: dst.x, y2: dst.y,
                stroke: isUp ? "rgba(0, 240, 255, 0.4)" : "rgba(255, 51, 102, 0.7)",
                strokeWidth: e.bandwidth_mbps >= 10000 ? "3" : "1.5",
                strokeDasharray: isUp ? "none" : "4,4"
              }),
              // Middle badge for link speed
              h("text", {
                x: (src.x + dst.x) / 2,
                y: (src.y + dst.y) / 2 - 4,
                fill: "rgba(255, 255, 255, 0.4)",
                fontSize: "9",
                textAnchor: "middle",
                fontFamily: "var(--font-mono)"
              }, `${e.bandwidth_mbps >= 1000 ? (e.bandwidth_mbps/1000)+'G' : e.bandwidth_mbps+'M'} | ${e.latency_ms}ms`)
            );
          }),

          // Topology Nodes
          topology.nodes.map(n => {
            const isSelected = selectedNode && selectedNode.id === n.id;
            const isIsolated = n.status === "ISOLATED";
            const isCompromised = n.status === "COMPROMISED";
            const nodeColor = isIsolated ? "var(--red-critical)" : isCompromised ? "var(--orange-warning)" : n.risk_score > 60 ? "var(--yellow-alert)" : "var(--cyan-neon)";

            // Icon by device type
            let iconChar = "💻";
            if (n.device_type === "FIREWALL") iconChar = "🛡️";
            else if (n.device_type === "SWITCH") iconChar = "🔀";
            else if (n.device_type === "SERVER") iconChar = "🗄️";

            return h("g", {
              key: n.id,
              transform: `translate(${n.x}, ${n.y})`,
              onClick: () => setSelectedNode(n),
              style: { cursor: "pointer" }
            },
              // Glow circle
              h("circle", {
                r: isSelected ? "24" : "18",
                fill: "rgba(10, 18, 38, 0.9)",
                stroke: nodeColor,
                strokeWidth: isSelected ? "3" : "2",
                filter: isSelected ? "drop-shadow(0 0 8px rgba(0, 240, 255, 0.8))" : "none"
              }),
              h("text", {
                x: "0",
                y: "5",
                fontSize: "14",
                textAnchor: "middle"
              }, iconChar),
              // Label
              h("text", {
                x: "0",
                y: "32",
                fill: "#fff",
                fontSize: "10",
                fontWeight: "600",
                textAnchor: "middle",
                fontFamily: "var(--font-mono)"
              }, n.label.split(".")[0]),
              // IP
              h("text", {
                x: "0",
                y: "44",
                fill: "var(--text-muted)",
                fontSize: "9",
                textAnchor: "middle",
                fontFamily: "var(--font-mono)"
              }, n.ip_address),
              // Risk badge
              n.risk_score > 40 && h("text", {
                x: "16",
                y: "-12",
                fill: nodeColor,
                fontSize: "9",
                fontWeight: "bold"
              }, `⚠️ ${n.risk_score}`)
            );
          })
        )
      )
    ),

    // Node Inspector Drawer
    selectedNode && h("div", { className: "panel-box", style: { border: "1px solid var(--cyan-neon)" } },
      h("div", { className: "panel-header", style: { background: "var(--accent-subtle)" } },
        h("h3", null, `🔍 Device Inspector: ${selectedNode.label}`),
        h("button", { className: "modal-close", onClick: () => setSelectedNode(null) }, "✕")
      ),
      h("div", { style: { padding: "20px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px" } },
        h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "DEVICE ID / TYPE"), h("strong", null, `${selectedNode.id} (${selectedNode.device_type})`)),
        h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "IP / ZONE"), h("code", null, `${selectedNode.ip_address} [${selectedNode.zone}]`)),
        h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "OPERATIONAL STATUS"), h("span", { className: `badge ${selectedNode.status === "ONLINE" ? "badge-low" : "badge-critical"}` }, selectedNode.status)),
        h("div", null, h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "RISK PROFILE"), h("span", { style: { color: selectedNode.risk_score > 60 ? "var(--red-critical)" : "var(--green-neon)", fontWeight: "bold" } }, `${selectedNode.risk_score} / 100`)),
        h("div", { style: { gridColumn: "1 / -1", display: "flex", gap: "12px", marginTop: "8px" } },
          selectedNode.status !== "ISOLATED" ? h("button", {
            className: "btn btn-danger",
            onClick: () => handleIsolate(selectedNode.id)
          }, "⚡ Isolate Host (Immediate Network Containment)") : h("button", {
            className: "btn btn-primary",
            onClick: () => handleUnquarantine(selectedNode.id)
          }, "✓ Lift Quarantine (Restore Network Access)")
        )
      )
    )
  );
}

// 8. Device Asset Management View
function DevicesView() {
  const [devices, setDevices] = useState([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);

  const fetchDevices = async () => {
    try {
      let url = "/api/devices?page=1&page_size=50";
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (typeFilter) url += `&device_type=${typeFilter}`;
      if (statusFilter) url += `&status=${statusFilter}`;

      const res = await api.fetch(url);
      if (res.ok) {
        const data = await res.json();
        setDevices(data.items || []);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchDevices(); }, [search, typeFilter, statusFilter]);

  const handleIsolate = async (id) => {
    if (!window.confirm("Quarantine this endpoint immediately?")) return;
    await api.fetch(`/api/devices/${id}/isolate`, {
      method: "POST",
      body: JSON.stringify({ reason: "Manual SOC operator containment" })
    });
    fetchDevices();
  };

  const handleUnquarantine = async (id) => {
    await api.fetch(`/api/devices/${id}/unquarantine`, { method: "POST" });
    fetchDevices();
  };

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" },
      h("h3", null, "💻 Enterprise Managed Device & Endpoint Inventory"),
      h("div", { style: { display: "flex", gap: "10px" } },
        h("input", {
          type: "text",
          placeholder: "Search hostname, IP, or MAC...",
          value: search,
          onChange: (e) => setSearch(e.target.value),
          className: "csql-input",
          style: { width: "240px" }
        }),
        h("select", {
          value: typeFilter,
          onChange: (e) => setTypeFilter(e.target.value),
          style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
        },
          h("option", { value: "" }, "All Types"),
          h("option", { value: "SERVER" }, "Servers"),
          h("option", { value: "WORKSTATION" }, "Workstations"),
          h("option", { value: "FIREWALL" }, "Firewalls"),
          h("option", { value: "SWITCH" }, "Switches")
        ),
        h("select", {
          value: statusFilter,
          onChange: (e) => setStatusFilter(e.target.value),
          style: { background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", padding: "4px 8px", borderRadius: "4px" }
        },
          h("option", { value: "" }, "All Statuses"),
          h("option", { value: "ONLINE" }, "Online"),
          h("option", { value: "ISOLATED" }, "Isolated"),
          h("option", { value: "DEGRADED" }, "Degraded")
        )
      )
    ),

    h("div", { className: "table-container" },
      h("table", { className: "cyber-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "Status"),
            h("th", null, "Hostname"),
            h("th", null, "IP Address"),
            h("th", null, "MAC Address"),
            h("th", null, "Type / OS"),
            h("th", null, "Risk Score"),
            h("th", null, "Open Ports"),
            h("th", null, "Action")
          )
        ),
        h("tbody", null,
          devices.length === 0 ? h("tr", null, h("td", { colSpan: "8", style: { textAlign: "center", color: "var(--text-muted)" } }, "No matching devices found.")) :
          devices.map(d =>
            h("tr", { key: d.id },
              h("td", null, h("span", { className: `badge ${d.status === "ONLINE" ? "badge-low" : "badge-critical"}` }, d.status)),
              h("td", null, h("strong", null, d.hostname), d.is_critical_asset && h("span", { style: { marginLeft: "6px", color: "var(--orange-warning)", fontSize: "11px" } }, "★ Crown Jewel")),
              h("td", null, h("code", null, d.ip_address)),
              h("td", null, h("span", { style: { fontFamily: "var(--font-mono)", fontSize: "11px" } }, d.mac_address)),
              h("td", null, `${d.device_type} / ${d.os_family}`),
              h("td", null,
                h("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
                  h("div", { style: { width: "40px", height: "6px", background: "var(--bg-hover)", borderRadius: "3px", overflow: "hidden" } },
                    h("div", { style: { width: `${d.risk_score}%`, height: "100%", background: d.risk_score > 70 ? "var(--red-critical)" : d.risk_score > 30 ? "var(--yellow-alert)" : "var(--green-neon)" } })
                  ),
                  h("span", { style: { fontSize: "11px", fontWeight: "bold" } }, d.risk_score)
                )
              ),
              h("td", null, (d.open_ports || []).slice(0, 4).map(p => h("span", { key: p, className: "badge badge-info", style: { marginRight: "4px", fontSize: "10px" } }, p))),
              h("td", null,
                d.status !== "ISOLATED" ? h("button", {
                  className: "btn btn-danger btn-sm",
                  onClick: () => handleIsolate(d.id),
                  title: "Quarantine Host"
                }, "⚡ Isolate") : h("button", {
                  className: "btn btn-primary btn-sm",
                  onClick: () => handleUnquarantine(d.id),
                  title: "Lift Isolation"
                }, "✓ Restore")
              )
            )
          )
        )
      )
    )
  );
}

// 9. IP Management & Subnet Discovery View
function IPManagementView() {
  const [subnets, setSubnets] = useState([]);
  const [ips, setIps] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const fetchNetworkData = async () => {
    try {
      const [subRes, ipRes] = await Promise.all([
        api.fetch("/api/networks"),
        api.fetch("/api/ips?page=1&page_size=50")
      ]);
      if (subRes.ok) setSubnets((await subRes.json()).items || []);
      if (ipRes.ok) setIps((await ipRes.json()).items || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => { fetchNetworkData(); }, []);

  const triggerScan = async (subnetId) => {
    setScanning(true);
    try {
      const res = await api.fetch("/api/network/discovery/scan", {
        method: "POST",
        body: JSON.stringify({ subnet_id: subnetId, ping_timeout_ms: 150, port_scan_depth: "STANDARD" })
      });
      if (res.ok) {
        setScanResult(await res.json());
        fetchNetworkData();
      }
    } catch (e) {
      alert("Discovery scan failed");
    } finally {
      setScanning(false);
    }
  };

  return h("div", { style: { display: "flex", flexDirection: "column", gap: "20px" } },
    // Subnet Cards
    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "📍 Enterprise Subnet Partitions & IP Capacity"),
        h("button", {
          className: "btn btn-primary btn-sm",
          disabled: scanning,
          onClick: () => triggerScan("sub-corp-01")
        }, scanning ? "⏳ Scanning Subnet..." : "⚡ Run Subnet Discovery Sweep")
      ),
      h("div", { style: { padding: "20px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" } },
        subnets.map(s =>
          h("div", { key: s.id, style: { background: "var(--bg-hover)", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "16px" } },
            h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "8px" } },
              h("strong", { style: { color: "var(--cyan-neon)" } }, s.name),
              h("span", { className: "badge badge-info" }, s.zone_type)
            ),
            h("div", { style: { fontSize: "12px", fontFamily: "var(--font-mono)", marginBottom: "4px" } }, `CIDR: ${s.cidr} (VLAN ${s.vlan_id || 'Untagged'})`),
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginBottom: "12px" } }, `Gateway: ${s.gateway_ip} | Usable Hosts: ${s.total_ips}`),
            // Capacity bar
            h("div", { style: { display: "flex", justifyContent: "space-between", fontSize: "10px", color: "var(--text-muted)", marginBottom: "4px" } },
              h("span", null, `Allocated: ${s.allocated_ips} IPs`),
              h("span", null, `${s.utilization_pct}% Utilized`)
            ),
            h("div", { style: { height: "6px", background: "var(--bg-hover)", borderRadius: "3px", overflow: "hidden" } },
              h("div", { style: { width: `${s.utilization_pct}%`, height: "100%", background: s.utilization_pct > 80 ? "var(--red-critical)" : "var(--cyan-neon)" } })
            )
          )
        )
      )
    ),

    // Discovery Scan Results Banner
    scanResult && h("div", { className: "panel-box", style: { border: "1px solid var(--orange-warning)" } },
      h("div", { className: "panel-header", style: { background: "var(--accent-subtle)" } },
        h("h3", null, `⚡ Discovery Scan Results: Subnet ${scanResult.subnet_cidr}`),
        h("span", { style: { fontSize: "12px", color: "var(--text-muted)" } }, `Completed in ${scanResult.scan_duration_sec}s`)
      ),
      h("div", { style: { padding: "16px" } },
        h("div", { style: { display: "flex", gap: "20px", marginBottom: "12px" } },
          h("div", null, "Scanned: ", h("strong", null, scanResult.scanned_ips)),
          h("div", null, "Active Hosts: ", h("strong", { style: { color: "var(--green-neon)" } }, scanResult.active_hosts_found)),
          h("div", null, "Rogue Assets: ", h("strong", { style: { color: "var(--red-critical)" } }, scanResult.rogue_devices_count)),
          h("div", null, "IP Conflicts: ", h("strong", { style: { color: "var(--yellow-alert)" } }, scanResult.conflicts_detected))
        ),
        h("ul", { style: { margin: "0 0 0 20px" } },
          scanResult.hosts.map(h_item =>
            h("li", { key: h_item.ip_address, style: { color: !h_item.is_known ? "var(--red-critical)" : "var(--text-secondary)", marginBottom: "4px" } },
              `${h_item.ip_address} - ${h_item.hostname || 'Unknown Host'} (MAC: ${h_item.mac_address}) [${h_item.os_fingerprint}]`,
              !h_item.is_known && h("span", { className: "badge badge-critical", style: { marginLeft: "8px" } }, "ROGUE ASSET DETECTED")
            )
          )
        )
      )
    ),

    // Allocated IP Ledger
    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "📋 IP Address Allocation Ledger")),
      h("div", { className: "table-container" },
        h("table", { className: "cyber-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "IP Address"),
              h("th", null, "Hostname"),
              h("th", null, "MAC Binding"),
              h("th", null, "Subnet"),
              h("th", null, "Type"),
              h("th", null, "Latency"),
              h("th", null, "Status")
            )
          ),
          h("tbody", null,
            ips.map(ip =>
              h("tr", { key: ip.id },
                h("td", null, h("code", null, ip.ip_address)),
                h("td", null, h("strong", null, ip.hostname || "Unassigned")),
                h("td", null, h("span", { style: { fontFamily: "var(--font-mono)", fontSize: "11px" } }, ip.mac_address || "None")),
                h("td", null, ip.subnet_id),
                h("td", null, h("span", { className: "badge badge-info" }, ip.allocation_type)),
                h("td", null, ip.last_ping_latency_ms ? `${ip.last_ping_latency_ms}ms` : "-"),
                h("td", null, h("span", { className: `badge ${ip.status === "ACTIVE" ? "badge-low" : "badge-critical"}` }, ip.status))
              )
            )
          )
        )
      )
    )
  );
}

// ==========================================
// 8. Vulnerability Management & CVSS View
// ==========================================
function VulnerabilitiesView({ currentUser }) {
  const [activeTab, setActiveTab] = useState("catalog"); // "catalog", "assets", "cvss"
  const [cves, setCves] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [assetVulns, setAssetVulns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [selectedCve, setSelectedCve] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");

  // CVSS Live Calculator Controls
  const [cvssAv, setCvssAv] = useState("NETWORK");
  const [cvssAc, setCvssAc] = useState("LOW");
  const [cvssPr, setCvssPr] = useState("NONE");
  const [cvssUi, setCvssUi] = useState("NONE");
  const [cvssScope, setCvssScope] = useState("CHANGED");
  const [cvssConf, setCvssConf] = useState("HIGH");
  const [cvssInteg, setCvssInteg] = useState("HIGH");
  const [cvssAvail, setCvssAvail] = useState("HIGH");
  const [cvssE, setCvssE] = useState("HIGH");
  const [cvssRl, setCvssRl] = useState("OFFICIAL_FIX");
  const [cvssResult, setCvssResult] = useState(null);

  const fetchKpis = async () => {
    try {
      const res = await api.fetch("/api/vulnerabilities/kpis");
      if (res.ok) setKpis(await res.json());
    } catch (e) {}
  };

  const fetchCves = async () => {
    setLoading(true);
    try {
      let url = "/api/vulnerabilities?page_size=50";
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (sevFilter !== "ALL") url += `&severity=${sevFilter}`;
      const res = await api.fetch(url);
      if (res.ok) {
        const data = await res.json();
        setCves(data.items || []);
      }
    } catch (e) {}
    setLoading(false);
  };

  const fetchAssetVulns = async () => {
    try {
      const res = await api.fetch("/api/vulnerabilities/assets?page_size=50");
      if (res.ok) {
        const data = await res.json();
        setAssetVulns(data.items || []);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchKpis();
    if (activeTab === "catalog") fetchCves();
    else if (activeTab === "assets") fetchAssetVulns();
  }, [activeTab, sevFilter]);

  const triggerScan = async () => {
    setScanning(true);
    setScanMessage("");
    try {
      const res = await api.fetch("/api/vulnerabilities/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
      if (res.ok) {
        const d = await res.json();
        setScanMessage(`Scan complete: ${d.scanned_devices} devices audited, ${d.findings_generated} vulnerabilities mapped.`);
        fetchKpis();
        fetchAssetVulns();
      }
    } catch (e) {
      setScanMessage("Scan execution encountered an error.");
    }
    setScanning(false);
  };

  const updateStatus = async (id, newStatus) => {
    try {
      const res = await api.fetch(`/api/vulnerabilities/assets/${id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, analyst_notes: "Status updated by analyst via dashboard" })
      });
      if (res.ok) fetchAssetVulns();
    } catch (e) {}
  };

  const runCvssCalc = async () => {
    try {
      const res = await api.fetch("/api/vulnerabilities/cvss/calculate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_vector: cvssAv,
          attack_complexity: cvssAc,
          privileges_required: cvssPr,
          user_interaction: cvssUi,
          scope: cvssScope,
          confidentiality_impact: cvssConf,
          integrity_impact: cvssInteg,
          availability_impact: cvssAvail,
          exploit_code_maturity: cvssE,
          remediation_level: cvssRl
        })
      });
      if (res.ok) setCvssResult(await res.json());
    } catch (e) {}
  };

  useEffect(() => {
    if (activeTab === "cvss") runCvssCalc();
  }, [cvssAv, cvssAc, cvssPr, cvssUi, cvssScope, cvssConf, cvssInteg, cvssAvail, cvssE, cvssRl]);

  return h("div", { className: "module-container" },
    // KPI Cards
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Total Known CVEs"),
        h("div", { className: "kpi-value highlight-cyan" }, kpis.total_cves),
        h("div", { className: "kpi-sub" }, `${kpis.critical_cves} Critical Severity`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Vulnerable Assets"),
        h("div", { className: "kpi-value highlight-red" }, kpis.total_vulnerable_assets),
        h("div", { className: "kpi-sub" }, `${kpis.unpatched_critical_assets} Unpatched Critical`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Avg Patch Priority"),
        h("div", { className: "kpi-value highlight-orange" }, `${kpis.avg_patch_priority}/100`),
        h("div", { className: "kpi-sub" }, "Weighted Risk Composite")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Compliance Impact"),
        h("div", { className: "kpi-value highlight-purple" }, `${kpis.compliance_breakdown?.["PCI-DSS"] || 0} PCI`),
        h("div", { className: "kpi-sub" }, `${kpis.compliance_breakdown?.["NIST-CSF"] || 0} NIST Controls`)
      )
    ),

    // Sub-Navigation Tabs & Scan Action
    h("div", { className: "tabs-header-strip", style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" } },
      h("div", { className: "tab-buttons", style: { display: "flex", gap: "8px" } },
        h("button", {
          className: `btn ${activeTab === "catalog" ? "btn-primary" : "btn-outline"}`,
          onClick: () => setActiveTab("catalog")
        }, "📖 CVE Vulnerability Catalog"),
        h("button", {
          className: `btn ${activeTab === "assets" ? "btn-primary" : "btn-outline"}`,
          onClick: () => setActiveTab("assets")
        }, "💻 Asset Remediation Ledger"),
        h("button", {
          className: `btn ${activeTab === "cvss" ? "btn-primary" : "btn-outline"}`,
          onClick: () => setActiveTab("cvss")
        }, "⚖️ CVSS v3.1 Calculator")
      ),
      h("button", {
        className: "btn btn-danger",
        onClick: triggerScan,
        disabled: scanning
      }, scanning ? "Scanning Assets..." : "⚡ Run Enterprise Vulnerability Scan")
    ),

    scanMessage && h("div", {
      className: "alert-info",
      style: { padding: "10px 16px", marginBottom: "16px", background: "var(--accent-subtle)", border: "1px solid var(--accent-cyan)", borderRadius: "4px" }
    }, scanMessage),

    // TAB 1: CVE Catalog
    activeTab === "catalog" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        h("h3", null, "Verified Vulnerability Catalog (NIST NVD / Local Database)"),
        h("div", { style: { display: "flex", gap: "10px" } },
          h("input", {
            type: "text",
            className: "form-input",
            placeholder: "Search CVE, title...",
            value: search,
            onChange: (e) => setSearch(e.target.value),
            onKeyDown: (e) => e.key === "Enter" && fetchCves(),
            style: { width: "220px" }
          }),
          h("select", {
            className: "form-input",
            value: sevFilter,
            onChange: (e) => setSevFilter(e.target.value)
          },
            h("option", { value: "ALL" }, "All Severities"),
            h("option", { value: "CRITICAL" }, "Critical"),
            h("option", { value: "HIGH" }, "High"),
            h("option", { value: "MEDIUM" }, "Medium")
          )
        )
      ),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "CVE ID"),
              h("th", null, "Title"),
              h("th", null, "Severity"),
              h("th", null, "CVSS v3.1"),
              h("th", null, "Vector"),
              h("th", null, "Compliance Tags"),
              h("th", null, "Action")
            )
          ),
          h("tbody", null,
            cves.map(cve =>
              h("tr", { key: cve.cve_id },
                h("td", null, h("strong", { style: { color: "var(--accent-cyan)" } }, cve.cve_id)),
                h("td", null, cve.title),
                h("td", null, h("span", {
                  className: `badge ${cve.severity === "CRITICAL" ? "badge-critical" : cve.severity === "HIGH" ? "badge-high" : "badge-medium"}`
                }, cve.severity)),
                h("td", null, h("span", {
                  className: "badge",
                  style: { background: cve.cvss_v31_score >= 9.0 ? "rgba(255, 0, 85, 0.2)" : "rgba(255, 170, 0, 0.2)", color: "var(--text-primary)" }
                }, `${cve.cvss_v31_score}`)),
                h("td", null, h("code", { style: { fontSize: "11px" } }, cve.attack_vector)),
                h("td", null,
                  (cve.compliance_tags || []).map(t =>
                    h("span", { key: t, className: "badge badge-info", style: { marginRight: "4px", fontSize: "10px" } }, t)
                  )
                ),
                h("td", null,
                  h("button", {
                    className: "btn btn-outline btn-sm",
                    onClick: () => setSelectedCve(cve)
                  }, "Dossier")
                )
              )
            )
          )
        )
      )
    ),

    // TAB 2: Asset Remediation Ledger
    activeTab === "assets" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "Enterprise Device Vulnerability Exposure & Patch Prioritization")
      ),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Host / Asset"),
              h("th", null, "IP Address"),
              h("th", null, "CVE Vulnerability"),
              h("th", null, "Service / Port"),
              h("th", null, "Patch Priority"),
              h("th", null, "Status"),
              h("th", null, "Remediation Workflow")
            )
          ),
          h("tbody", null,
            assetVulns.map(av =>
              h("tr", { key: av.id },
                h("td", null, h("strong", null, av.device_hostname)),
                h("td", null, h("code", null, av.device_ip)),
                h("td", null, h("span", { style: { color: "var(--accent-cyan)" } }, av.cve_id)),
                h("td", null, `${av.service_name || "Unknown"} (${av.port || "N/A"})`),
                h("td", null,
                  h("div", { style: { display: "flex", alignItems: "center", gap: "8px" } },
                    h("div", { style: { width: "70px", height: "8px", background: "var(--bg-hover)", borderRadius: "4px", overflow: "hidden" } },
                      h("div", {
                        style: {
                          width: `${av.patch_priority_score}%`,
                          height: "100%",
                          background: av.patch_priority_score >= 80 ? "var(--accent-red)" : "var(--accent-orange)"
                        }
                      })
                    ),
                    h("span", null, `${av.patch_priority_score}`)
                  )
                ),
                h("td", null, h("span", {
                  className: `badge ${av.status === "CLOSED" ? "badge-low" : av.status === "IN_REMEDIATION" ? "badge-info" : "badge-critical"}`
                }, av.status)),
                h("td", null,
                  h("div", { style: { display: "flex", gap: "6px" } },
                    av.status !== "IN_REMEDIATION" && av.status !== "CLOSED" && h("button", {
                      className: "btn btn-outline btn-sm",
                      onClick: () => updateStatus(av.id, "IN_REMEDIATION")
                    }, "Start Patch"),
                    av.status !== "CLOSED" && h("button", {
                      className: "btn btn-outline btn-sm",
                      style: { borderColor: "var(--accent-green)", color: "var(--accent-green)" },
                      onClick: () => updateStatus(av.id, "CLOSED")
                    }, "Verify & Close")
                  )
                )
              )
            )
          )
        )
      )
    ),

    // TAB 3: Interactive CVSS Calculator
    activeTab === "cvss" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "Official FIRST Common Vulnerability Scoring System (CVSS v3.1) Calculator")
      ),
      h("div", { style: { display: "grid", gridTemplateColumns: "1fr 340px", gap: "24px", padding: "24px" } },
        h("div", null,
          h("h4", { style: { color: "var(--accent-cyan)", marginBottom: "16px" } }, "Base Metric Vector Attributes"),
          h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" } },
            h("div", null,
              h("label", { className: "form-label" }, "Attack Vector (AV)"),
              h("select", { className: "form-input", value: cvssAv, onChange: e => setCvssAv(e.target.value) },
                h("option", { value: "NETWORK" }, "Network (N) - 0.85"),
                h("option", { value: "ADJACENT" }, "Adjacent (A) - 0.62"),
                h("option", { value: "LOCAL" }, "Local (L) - 0.55"),
                h("option", { value: "PHYSICAL" }, "Physical (P) - 0.20")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Attack Complexity (AC)"),
              h("select", { className: "form-input", value: cvssAc, onChange: e => setCvssAc(e.target.value) },
                h("option", { value: "LOW" }, "Low (L) - 0.77"),
                h("option", { value: "HIGH" }, "High (H) - 0.44")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Privileges Required (PR)"),
              h("select", { className: "form-input", value: cvssPr, onChange: e => setCvssPr(e.target.value) },
                h("option", { value: "NONE" }, "None (N) - 0.85"),
                h("option", { value: "LOW" }, "Low (L) - 0.62"),
                h("option", { value: "HIGH" }, "High (H) - 0.27")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "User Interaction (UI)"),
              h("select", { className: "form-input", value: cvssUi, onChange: e => setCvssUi(e.target.value) },
                h("option", { value: "NONE" }, "None (N) - 0.85"),
                h("option", { value: "REQUIRED" }, "Required (R) - 0.62")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Scope (S)"),
              h("select", { className: "form-input", value: cvssScope, onChange: e => setCvssScope(e.target.value) },
                h("option", { value: "UNCHANGED" }, "Unchanged (U)"),
                h("option", { value: "CHANGED" }, "Changed (C)")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Confidentiality (C)"),
              h("select", { className: "form-input", value: cvssConf, onChange: e => setCvssConf(e.target.value) },
                h("option", { value: "NONE" }, "None (N)"),
                h("option", { value: "LOW" }, "Low (L)"),
                h("option", { value: "HIGH" }, "High (H)")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Integrity (I)"),
              h("select", { className: "form-input", value: cvssInteg, onChange: e => setCvssInteg(e.target.value) },
                h("option", { value: "NONE" }, "None (N)"),
                h("option", { value: "LOW" }, "Low (L)"),
                h("option", { value: "HIGH" }, "High (H)")
              )
            ),
            h("div", null,
              h("label", { className: "form-label" }, "Availability (A)"),
              h("select", { className: "form-input", value: cvssAvail, onChange: e => setCvssAvail(e.target.value) },
                h("option", { value: "NONE" }, "None (N)"),
                h("option", { value: "LOW" }, "Low (L)"),
                h("option", { value: "HIGH" }, "High (H)")
              )
            )
          )
        ),
        // Score Display Box
        h("div", {
          style: {
            background: "var(--bg-card)",
            border: "1px solid var(--border-color)",
            borderRadius: "8px",
            padding: "24px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center"
          }
        },
          cvssResult ? h("div", null,
            h("div", { style: { fontSize: "14px", color: "var(--text-secondary)", marginBottom: "8px" } }, "CALCULATED CVSS BASE SCORE"),
            h("div", {
              style: {
                fontSize: "48px",
                fontWeight: "bold",
                color: cvssResult.base_score >= 9.0 ? "var(--accent-red)" : cvssResult.base_score >= 7.0 ? "var(--accent-orange)" : "var(--accent-green)",
                marginBottom: "8px"
              }
            }, cvssResult.base_score),
            h("div", {
              className: `badge ${cvssResult.severity === "CRITICAL" ? "badge-critical" : cvssResult.severity === "HIGH" ? "badge-high" : "badge-medium"}`,
              style: { fontSize: "13px", padding: "4px 12px", marginBottom: "16px" }
            }, cvssResult.severity),
            h("div", { style: { fontSize: "12px", wordBreak: "break-all", background: "var(--bg-hover)", padding: "10px", borderRadius: "4px" } },
              h("code", null, cvssResult.vector_string)
            )
          ) : h("p", null, "Calculating score...")
        )
      )
    ),

    // CVE Detail Modal
    selectedCve && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "600px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `🛡️ ${selectedCve.cve_id}: ${selectedCve.title}`),
          h("button", { className: "modal-close", onClick: () => setSelectedCve(null) }, "✕")
        ),
        h("div", { style: { padding: "20px" } },
          h("p", { style: { color: "var(--text-secondary)", marginBottom: "14px" } }, selectedCve.description),
          h("div", { style: { marginBottom: "12px" } },
            h("strong", null, "Remediation Guidance: "),
            h("p", { style: { color: "var(--accent-cyan)", marginTop: "4px" } }, selectedCve.remediation_guidance)
          ),
          h("div", { style: { marginBottom: "12px" } },
            h("strong", null, "Affected Software: "),
            h("div", { style: { marginTop: "4px", display: "flex", flexWrap: "wrap", gap: "6px" } },
              (selectedCve.affected_products || []).map(p => h("span", { key: p, className: "badge badge-info" }, p))
            )
          ),
          h("div", null,
            h("strong", null, "CVSS Vector String: "),
            h("code", { style: { display: "block", marginTop: "4px", padding: "8px", background: "var(--bg-secondary)" } }, selectedCve.cvss_vector)
          )
        )
      )
    )
  );
}

// ==========================================
// 9. Threat Intelligence & IoC Repository View
// ==========================================
function ThreatIntelView({ currentUser }) {
  const [activeTab, setActiveTab] = useState("lookup"); // "lookup", "iocs", "actors", "campaigns"
  const [kpis, setKpis] = useState(null);
  const [queryVal, setQueryVal] = useState("198.51.100.23");
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [iocs, setIocs] = useState([]);
  const [actors, setActors] = useState([]);
  const [campaigns, setCampaigns] = useState([]);

  const fetchKpis = async () => {
    try {
      const res = await api.fetch("/api/intel/kpis");
      if (res.ok) setKpis(await res.json());
    } catch (e) {}
  };

  const fetchIocs = async () => {
    try {
      const res = await api.fetch("/api/intel/iocs?page_size=50");
      if (res.ok) {
        const d = await res.json();
        setIocs(d.items || []);
      }
    } catch (e) {}
  };

  const fetchActors = async () => {
    try {
      const res = await api.fetch("/api/intel/actors");
      if (res.ok) setActors(await res.json());
    } catch (e) {}
  };

  const fetchCampaigns = async () => {
    try {
      const res = await api.fetch("/api/intel/campaigns");
      if (res.ok) setCampaigns(await res.json());
    } catch (e) {}
  };

  useEffect(() => {
    fetchKpis();
    if (activeTab === "iocs") fetchIocs();
    else if (activeTab === "actors") fetchActors();
    else if (activeTab === "campaigns") fetchCampaigns();
  }, [activeTab]);

  const executeLookup = async (overrideVal) => {
    const val = overrideVal || queryVal;
    if (!val) return;
    setLookupLoading(true);
    setLookupResult(null);
    try {
      const res = await api.fetch("/api/intel/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator: val })
      });
      if (res.ok) setLookupResult(await res.json());
    } catch (e) {}
    setLookupLoading(false);
  };

  return h("div", { className: "module-container" },
    // KPI Cards
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Active IoC Indicators"),
        h("div", { className: "kpi-value highlight-cyan" }, kpis.active_iocs),
        h("div", { className: "kpi-sub" }, `${kpis.ip_iocs} IPs, ${kpis.domain_iocs} Domains`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Tracked APT Groups"),
        h("div", { className: "kpi-value highlight-purple" }, kpis.total_threat_actors),
        h("div", { className: "kpi-sub" }, `${kpis.active_campaigns} Active Campaigns`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Malware Hashes"),
        h("div", { className: "kpi-value highlight-red" }, kpis.hash_iocs),
        h("div", { className: "kpi-sub" }, "SHA256 / MD5 Signatures")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Feed Confidence"),
        h("div", { className: "kpi-value highlight-green" }, `${kpis.avg_confidence_score}%`),
        h("div", { className: "kpi-sub" }, "STIX 2.1 & MISP Ingested")
      )
    ),

    // Sub-Nav Tabs
    h("div", { className: "tab-buttons", style: { display: "flex", gap: "8px", marginBottom: "16px" } },
      h("button", {
        className: `btn ${activeTab === "lookup" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("lookup")
      }, "⚡ Sub-Millisecond Bloom Lookup"),
      h("button", {
        className: `btn ${activeTab === "iocs" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("iocs")
      }, "📋 IoC Indicator Ledger"),
      h("button", {
        className: `btn ${activeTab === "actors" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("actors")
      }, "👥 APT Threat Actors"),
      h("button", {
        className: `btn ${activeTab === "campaigns" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("campaigns")
      }, "🎯 Active Campaigns")
    ),

    // TAB 1: Fast Lookup Sandbox
    activeTab === "lookup" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "Sub-Millisecond In-Memory Threat Intelligence Lookup Sandbox")
      ),
      h("div", { style: { padding: "24px" } },
        h("div", { style: { display: "flex", gap: "10px", marginBottom: "16px" } },
          h("input", {
            type: "text",
            className: "form-input",
            placeholder: "Search indicator (IP, domain, URL, SHA256 hash)...",
            value: queryVal,
            onChange: e => setQueryVal(e.target.value),
            onKeyDown: e => e.key === "Enter" && executeLookup()
          }),
          h("button", {
            className: "btn btn-primary",
            onClick: () => executeLookup(),
            disabled: lookupLoading
          }, lookupLoading ? "Checking..." : "🔍 Check Intelligence")
        ),
        h("div", { style: { display: "flex", gap: "8px", marginBottom: "20px" } },
          h("span", { style: { color: "var(--text-secondary)", fontSize: "12px" } }, "Quick Test Seeds: "),
          h("button", { className: "btn btn-outline btn-sm", onClick: () => { setQueryVal("198.51.100.23"); executeLookup("198.51.100.23"); } }, "APT29 C2 IP"),
          h("button", { className: "btn btn-outline btn-sm", onClick: () => { setQueryVal("login-secure-office365-verify.com"); executeLookup("login-secure-office365-verify.com"); } }, "Lazarus Phishing Domain"),
          h("button", { className: "btn btn-outline btn-sm", onClick: () => { setQueryVal("a8b38749e7b233a7e4e138a8d169c9be740e5362e49c7198539265f04b2a8d3e"); executeLookup("a8b38749e7b233a7e4e138a8d169c9be740e5362e49c7198539265f04b2a8d3e"); } }, "Mimikatz Hash")
        ),

        // Result Card
        lookupResult && h("div", {
          style: {
            background: lookupResult.matched ? "rgba(255, 0, 85, 0.08)" : "rgba(0, 255, 136, 0.08)",
            border: `1px solid ${lookupResult.matched ? "var(--accent-red)" : "var(--accent-green)"}`,
            borderRadius: "8px",
            padding: "20px"
          }
        },
          h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" } },
            h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
              h("span", { style: { fontSize: "22px" } }, lookupResult.matched ? "🚨" : "🛡️"),
              h("h4", { style: { margin: 0, color: lookupResult.matched ? "var(--accent-red)" : "var(--accent-green)" } },
                lookupResult.matched ? "MALICIOUS THREAT INDICATOR DETECTED" : "CLEAN - NO THREAT INTELLIGENCE MATCH"
              )
            ),
            h("span", { className: "badge badge-info" }, `⚡ ${lookupResult.lookup_latency_ms} ms Latency`)
          ),
          lookupResult.matched && h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "12px" } },
            h("div", null, h("strong", null, "Threat Actor: "), lookupResult.threat_actor || "Unknown Syndicate"),
            h("div", null, h("strong", null, "Campaign: "), lookupResult.campaign || "Opportunistic Attack"),
            h("div", null, h("strong", null, "Classification: "), lookupResult.threat_type),
            h("div", null, h("strong", null, "Confidence: "), `${lookupResult.confidence_score}%`),
            h("div", null, h("strong", null, "Source Feed: "), lookupResult.source_feed),
            h("div", null, h("strong", null, "MITRE ATT&CK: "), (lookupResult.mitre_tactics || []).join(", "))
          )
        )
      )
    ),

    // TAB 2: IoC Ledger
    activeTab === "iocs" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Persistent Indicator of Compromise (IoC) Ledger")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Indicator Value"),
              h("th", null, "Type"),
              h("th", null, "Threat Class"),
              h("th", null, "Severity"),
              h("th", null, "Confidence"),
              h("th", null, "Threat Actor"),
              h("th", null, "Source Feed")
            )
          ),
          h("tbody", null,
            iocs.map(ioc =>
              h("tr", { key: ioc.id },
                h("td", null, h("code", { style: { color: "var(--accent-cyan)" } }, ioc.indicator_value)),
                h("td", null, h("span", { className: "badge badge-info" }, ioc.indicator_type)),
                h("td", null, ioc.threat_type),
                h("td", null, h("span", { className: `badge ${ioc.severity === "CRITICAL" ? "badge-critical" : "badge-high"}` }, ioc.severity)),
                h("td", null, `${ioc.confidence_score}%`),
                h("td", null, ioc.threat_actor || "-"),
                h("td", null, h("small", null, ioc.source_feed))
              )
            )
          )
        )
      )
    ),

    // TAB 3: APT Threat Actors
    activeTab === "actors" && h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" } },
      actors.map(act =>
        h("div", { key: act.id, className: "panel-box", style: { padding: "20px" } },
          h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
            h("h4", { style: { color: "var(--accent-cyan)", margin: 0 } }, act.name),
            h("span", { className: "badge badge-info" }, act.origin_country)
          ),
          h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" } },
            `Aliases: ${(act.aliases || []).join(", ")}`
          ),
          h("p", { style: { fontSize: "13px", lineHeight: "1.5", marginBottom: "12px" } }, act.description),
          h("div", { style: { display: "flex", flexWrap: "wrap", gap: "6px" } },
            (act.known_ttps || []).map(t => h("span", { key: t, className: "badge", style: { background: "var(--bg-hover)" } }, t))
          )
        )
      )
    ),

    // TAB 4: Active Campaigns
    activeTab === "campaigns" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Active & Monitored Global Cyber Campaigns")),
      h("div", { style: { padding: "20px", display: "grid", gap: "16px" } },
        campaigns.map(camp =>
          h("div", {
            key: camp.id,
            style: { background: "var(--bg-card)", border: "1px solid var(--border-color)", borderRadius: "6px", padding: "16px" }
          },
            h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" } },
              h("h4", { style: { margin: 0, color: "var(--accent-orange)" } }, camp.name),
              h("span", { className: `badge ${camp.status === "ACTIVE" ? "badge-critical" : "badge-medium"}` }, camp.status)
            ),
            h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" } },
              `Attributed Actor: ${camp.associated_actor || "Unknown"}`
            ),
            h("p", { style: { margin: 0, fontSize: "13px" } }, camp.objective)
          )
        )
      )
    )
  );
}

// ==========================================
// 10. Phishing & Email Security Analysis View
// ==========================================
function PhishingAnalysisView({ currentUser }) {
  const [kpis, setKpis] = useState(null);
  const [fromHdr, setFromHdr] = useState("Microsoft Security Alert <security@micros0ft-support.ru>");
  const [returnPath, setReturnPath] = useState("<bounce@attacker-host.com>");
  const [spfHdr, setSpfHdr] = useState("fail (domain does not designate 185.220.101.5 as permitted sender)");
  const [authResults, setAuthResults] = useState("spf=fail; dkim=none; dmarc=fail");
  const [emailBody, setEmailBody] = useState("URGENT: Your Office365 password will expire in 24 hours. Click here to verify your identity: http://login-secure-office365-verify.com/reset");
  const [attFilename, setAttFilename] = useState("Urgent_Invoice.pdf.exe");
  const [inspecting, setInspecting] = useState(false);
  const [report, setReport] = useState(null);
  const [recentScans, setRecentScans] = useState([]);

  // Typosquatting Checker
  const [testDomain, setTestDomain] = useState("paypa1.com");
  const [brandMatch, setBrandMatch] = useState(null);

  const fetchKpis = async () => {
    try {
      const res = await api.fetch("/api/phishing/kpis");
      if (res.ok) setKpis(await res.json());
    } catch (e) {}
  };

  const fetchRecent = async () => {
    try {
      const res = await api.fetch("/api/phishing/recent");
      if (res.ok) setRecentScans(await res.json());
    } catch (e) {}
  };

  useEffect(() => {
    fetchKpis();
    fetchRecent();
  }, []);

  const analyzeEmail = async () => {
    setInspecting(true);
    setReport(null);
    try {
      const payload = {
        headers: {
          "From": fromHdr,
          "Return-Path": returnPath,
          "Received-SPF": spfHdr,
          "Authentication-Results": authResults
        },
        body: emailBody,
        attachments: attFilename ? [{ filename: attFilename }] : []
      };
      const res = await api.fetch("/api/phishing/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        const d = await res.json();
        setReport(d.report);
        fetchKpis();
        fetchRecent();
      }
    } catch (e) {}
    setInspecting(false);
  };

  const checkBrand = async () => {
    try {
      const res = await api.fetch("/api/phishing/brand-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: testDomain })
      });
      if (res.ok) setBrandMatch(await res.json());
    } catch (e) {}
  };

  return h("div", { className: "module-container" },
    // KPI Cards
    kpis && h("div", { className: "kpi-grid" },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Emails Scanned"),
        h("div", { className: "kpi-value highlight-cyan" }, kpis.total_emails_scanned),
        h("div", { className: "kpi-sub" }, "Inbound SMTP Gateway")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Phishing Blocked"),
        h("div", { className: "kpi-value highlight-red" }, kpis.phishing_blocked),
        h("div", { className: "kpi-sub" }, `${kpis.quishing_attacks_detected} QR Quishing Attacks`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Suspicious Tagged"),
        h("div", { className: "kpi-value highlight-orange" }, kpis.suspicious_tagged),
        h("div", { className: "kpi-sub" }, "Warning Banner Inserted")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Clean Delivered"),
        h("div", { className: "kpi-value highlight-green" }, kpis.clean_delivered),
        h("div", { className: "kpi-sub" }, "Legitimate Corporate Mail")
      )
    ),

    // Main 2-Column Inspection Console
    h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" } },
      // Left: Inspection Input Form
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" }, h("h3", null, "📧 Deep Email Header & Body Inspector")),
        h("div", { style: { padding: "20px" } },
          h("div", { style: { marginBottom: "10px" } },
            h("label", { className: "form-label" }, "From Header (Display Name + Address)"),
            h("input", { type: "text", className: "form-input", value: fromHdr, onChange: e => setFromHdr(e.target.value) })
          ),
          h("div", { style: { marginBottom: "10px" } },
            h("label", { className: "form-label" }, "Return-Path (Envelope Sender)"),
            h("input", { type: "text", className: "form-input", value: returnPath, onChange: e => setReturnPath(e.target.value) })
          ),
          h("div", { style: { marginBottom: "10px" } },
            h("label", { className: "form-label" }, "SPF / DMARC Authentication Results"),
            h("input", { type: "text", className: "form-input", value: authResults, onChange: e => setAuthResults(e.target.value) })
          ),
          h("div", { style: { marginBottom: "10px" } },
            h("label", { className: "form-label" }, "Email Body Text & Embedded Links"),
            h("textarea", {
              className: "form-input",
              rows: 4,
              value: emailBody,
              onChange: e => setEmailBody(e.target.value)
            })
          ),
          h("div", { style: { marginBottom: "16px" } },
            h("label", { className: "form-label" }, "Attachment Filename"),
            h("input", { type: "text", className: "form-input", value: attFilename, onChange: e => setAttFilename(e.target.value) })
          ),
          h("button", {
            className: "btn btn-primary btn-block",
            onClick: analyzeEmail,
            disabled: inspecting
          }, inspecting ? "Inspecting Security Vectors..." : "🔍 Inspect Email Security")
        )
      ),

      // Right: Report Card
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" }, h("h3", null, "Forensic Inspection Report")),
        h("div", { style: { padding: "20px" } },
          report ? h("div", null,
            h("div", {
              style: {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "16px",
                borderRadius: "6px",
                background: report.classification === "MALICIOUS" ? "rgba(255,0,85,0.15)" : report.classification === "PHISHING" ? "rgba(255,170,0,0.15)" : "rgba(0,255,136,0.1)",
                marginBottom: "16px"
              }
            },
              h("div", null,
                h("div", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, "VERDICT"),
                h("strong", { style: { fontSize: "20px", color: report.classification === "MALICIOUS" ? "var(--accent-red)" : "var(--accent-orange)" } }, report.classification),
                h("div", { style: { fontSize: "12px", marginTop: "4px" } }, `Action: ${report.recommended_action}`)
              ),
              h("div", { style: { textAlign: "right" } },
                h("div", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, "PHISHING SCORE"),
                h("span", { style: { fontSize: "32px", fontWeight: "bold" } }, `${report.phishing_score}/100`)
              )
            ),
            h("h4", { style: { color: "var(--accent-cyan)", marginBottom: "8px" } }, "Inspection Findings:"),
            h("ul", { style: { paddingLeft: "20px", fontSize: "13px", lineHeight: "1.6" } },
              (report.findings_summary || []).map((f, i) => h("li", { key: i }, f))
            )
          ) : h("div", { style: { textAlign: "center", padding: "40px", color: "var(--text-secondary)" } },
            h("p", null, "Enter email headers and body on the left and click Inspect to view forensic breakdown.")
          )
        )
      )
    ),

    // Typosquatting Brand Checker Strip
    h("div", { className: "panel-box", style: { marginBottom: "20px" } },
      h("div", { className: "panel-header" }, h("h3", null, "🎯 Typosquatting & Brand Impersonation Checker (Levenshtein Distance)")),
      h("div", { style: { padding: "20px", display: "flex", gap: "12px", alignItems: "center" } },
        h("input", {
          type: "text",
          className: "form-input",
          placeholder: "e.g. micros0ft.com, paypa1-verify.net",
          value: testDomain,
          onChange: e => setTestDomain(e.target.value)
        }),
        h("button", { className: "btn btn-outline", onClick: checkBrand }, "Check Typosquatting"),
        brandMatch && h("div", { style: { marginLeft: "12px" } },
          brandMatch.is_impersonation ?
            h("span", { className: "badge badge-critical" }, `Impersonating: ${brandMatch.details.impersonated_brand} (${brandMatch.details.technique})`) :
            h("span", { className: "badge badge-low" }, "No Direct Brand Lookalike Detected")
        )
      )
    )
  );
}

// ==========================================
// 11. Safe Malware & Binary Analysis View
// ==========================================
function MalwareAnalysisView({ currentUser }) {
  const [filename, setFilename] = useState("trojan_beacon.dll");
  const [payloadType, setPayloadType] = useState("text");
  const [payloadText, setPayloadText] = useState(
    "MZ\x90\x00\x03\x00\x00\x00PE\x00\x00VirtualAllocEx WriteProcessMemory CreateRemoteThread IsDebuggerPresent vssadmin delete shadows cmd.exe /c powershell http://198.51.100.23/beacon.bin"
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [report, setReport] = useState(null);
  const [reportsList, setReportsList] = useState([]);

  // Fuzzy hash compare
  const [fHash1, setFHash1] = useState("384:w0d6B...:w0d6");
  const [fHash2, setFHash2] = useState("384:w0d6C...:w0d6");
  const [fuzzyResult, setFuzzyResult] = useState(null);

  const fetchReports = async () => {
    try {
      const res = await api.fetch("/api/malware/reports");
      if (res.ok) setReportsList(await res.json());
    } catch (e) {}
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const analyzeBinary = async () => {
    setAnalyzing(true);
    setReport(null);
    try {
      const res = await api.fetch("/api/malware/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: filename,
          payload_text: payloadText,
          simulated_imports: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent"]
        })
      });
      if (res.ok) {
        const d = await res.json();
        setReport(d);
        fetchReports();
      }
    } catch (e) {}
    setAnalyzing(false);
  };

  const compareFuzzy = async () => {
    try {
      const res = await api.fetch("/api/malware/fuzzy-compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hash1: fHash1, hash2: fHash2 })
      });
      if (res.ok) setFuzzyResult(await res.json());
    } catch (e) {}
  };

  return h("div", { className: "module-container" },
    h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" } },
      // Left: Submission Console
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" }, h("h3", null, "🔬 Safe Static Binary Inspection Sandbox")),
        h("div", { style: { padding: "20px" } },
          h("div", { style: { marginBottom: "12px" } },
            h("label", { className: "form-label" }, "Sample Binary Name"),
            h("input", { type: "text", className: "form-input", value: filename, onChange: e => setFilename(e.target.value) })
          ),
          h("div", { style: { marginBottom: "12px" } },
            h("label", { className: "form-label" }, "Binary Payload Content (Strings / Opcodes / Base64)"),
            h("textarea", {
              className: "form-input",
              rows: 5,
              value: payloadText,
              onChange: e => setPayloadText(e.target.value)
            })
          ),
          h("div", { style: { display: "flex", gap: "8px", marginBottom: "16px" } },
            h("button", {
              className: "btn btn-outline btn-sm",
              onClick: () => {
                setFilename("beacon_x64.dll");
                setPayloadText("MZ\x90\x00PE\x00\x00VirtualAllocEx WriteProcessMemory CreateRemoteThread IsDebuggerPresent http://198.51.100.23/c2");
              }
            }, "Load PE Beacon"),
            h("button", {
              className: "btn btn-outline btn-sm",
              onClick: () => {
                setFilename("blackcat_ransom.exe");
                setPayloadText("MZ\x90\x00PE\x00\x00vssadmin delete shadows YOUR FILES ARE ENCRYPTED pay the ransom bitcoin wallet .onion");
              }
            }, "Load Ransomware Sample")
          ),
          h("button", {
            className: "btn btn-primary btn-block",
            onClick: analyzeBinary,
            disabled: analyzing
          }, analyzing ? "Extracting AST & Entropy..." : "🔬 Execute Static Binary Analysis")
        )
      ),

      // Right: Report Result Card
      h("div", { className: "panel-box" },
        h("div", { className: "panel-header" }, h("h3", null, "Static Analysis Dossier")),
        h("div", { style: { padding: "20px" } },
          report ? h("div", null,
            h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "12px" } },
              h("div", null,
                h("h4", { style: { margin: 0, color: report.risk_score >= 80 ? "var(--accent-red)" : "var(--accent-green)" } }, report.classification),
                h("div", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, report.file_type)
              ),
              h("span", { className: "badge badge-critical" }, `Risk Score: ${report.risk_score}/100`)
            ),
            h("div", { style: { fontSize: "12px", marginBottom: "12px" } },
              h("strong", null, "SHA-256: "), h("code", { style: { wordBreak: "break-all" } }, report.sha256)
            ),
            h("div", { style: { fontSize: "12px", marginBottom: "12px" } },
              h("strong", null, "SSDEEP Fuzzy: "), h("code", { style: { wordBreak: "break-all" } }, report.fuzzy_hash)
            ),
            h("div", { style: { fontSize: "12px", marginBottom: "12px" } },
              h("strong", null, "Shannon Entropy: "), `${report.entropy} / 8.0 ${report.is_packed ? "(PACKED / ENCRYPTED)" : "(Standard)"}`
            ),
            h("h4", { style: { color: "var(--accent-cyan)", marginBottom: "6px" } }, "Detected ATT&CK Capabilities:"),
            h("div", { style: { display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "12px" } },
              (report.matched_mitre || []).map(m => h("span", { key: m, className: "badge badge-high" }, m))
            ),
            h("h4", { style: { color: "var(--accent-cyan)", marginBottom: "6px" } }, "Key Behavioral Findings:"),
            h("ul", { style: { paddingLeft: "20px", fontSize: "12px" } },
              (report.findings || []).map((f, i) => h("li", { key: i }, f))
            )
          ) : h("div", { style: { textAlign: "center", padding: "40px", color: "var(--text-secondary)" } },
            h("p", null, "Submit binary payload to generate forensic static analysis report.")
          )
        )
      )
    ),

    // Fuzzy Hash Comparison Tool Strip
    h("div", { className: "panel-box", style: { marginBottom: "20px" } },
      h("div", { className: "panel-header" }, h("h3", null, "🔗 SSDEEP Fuzzy Hash Binary Similarity Comparator")),
      h("div", { style: { padding: "20px", display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: "12px", alignItems: "center" } },
        h("input", { type: "text", className: "form-input", placeholder: "Sample 1 Fuzzy Hash...", value: fHash1, onChange: e => setFHash1(e.target.value) }),
        h("input", { type: "text", className: "form-input", placeholder: "Sample 2 Fuzzy Hash...", value: fHash2, onChange: e => setFHash2(e.target.value) }),
        h("button", { className: "btn btn-outline", onClick: compareFuzzy }, "Compare Similarity")
      ),
      fuzzyResult && h("div", { style: { padding: "0 20px 20px" } },
        h("span", { className: "badge badge-info" }, `Similarity: ${fuzzyResult.similarity_score}% - ${fuzzyResult.verdict}`)
      )
    ),

    // Recent Reports Table
    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Catalog of Static Binary Analysis Reports")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Report ID"),
              h("th", null, "Filename"),
              h("th", null, "Format"),
              h("th", null, "Classification"),
              h("th", null, "Risk Score"),
              h("th", null, "Entropy"),
              h("th", null, "SHA-256")
            )
          ),
          h("tbody", null,
            reportsList.map(rep =>
              h("tr", { key: rep.id },
                h("td", null, h("strong", { style: { color: "var(--accent-cyan)" } }, rep.id)),
                h("td", null, rep.filename),
                h("td", null, rep.file_type),
                h("td", null, h("span", { className: `badge ${rep.classification === "MALICIOUS" ? "badge-critical" : "badge-medium"}` }, rep.classification)),
                h("td", null, `${rep.risk_score}`),
                h("td", null, `${rep.entropy}`),
                h("td", null, h("code", { style: { fontSize: "11px" } }, rep.sha256?.substring(0, 16) + "..."))
              )
            )
          )
        )
      )
    )
  );
}

// 9. Comprehensive Machine Learning, UEBA & Anomaly Detection View
function MLView({ currentUser }) {
  const [activeTab, setActiveTab] = useState("registry"); // "registry", "playground", "ueba", "datasets"
  const [models, setModels] = useState([]);
  const [kpis, setKpis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [trainingMsg, setTrainingMsg] = useState("");

  // Playground state
  const [payloadText, setPayloadText] = useState("' UNION SELECT null, username, password FROM users --");
  const [payloadRes, setPayloadRes] = useState(null);
  const [flowPackets, setFlowPackets] = useState(15000);
  const [flowBytes, setFlowBytes] = useState(8500000);
  const [flowDuration, setFlowDuration] = useState(30.0);
  const [flowPort, setFlowPort] = useState(443);
  const [flowRatio, setFlowRatio] = useState(0.95);
  const [flowOffHours, setFlowOffHours] = useState(true);
  const [anomalyRes, setAnomalyRes] = useState(null);

  // UEBA state
  const [uebaProfiles, setUebaProfiles] = useState([]);
  const [selectedUser, setSelectedUser] = useState("superadmin");
  const [uebaBytes, setUebaBytes] = useState(12000000);
  const [uebaHour, setUebaHour] = useState(3);
  const [uebaLat, setUebaLat] = useState(51.5074);
  const [uebaLon, setUebaLon] = useState(-0.1278);
  const [uebaCity, setUebaCity] = useState("London");
  const [uebaCountry, setUebaCountry] = useState("UK");
  const [uebaRes, setUebaRes] = useState(null);

  // Datasets state
  const [datasetsList, setDatasetsList] = useState([]);

  const fetchModelsAndKpis = async () => {
    try {
      setLoading(true);
      const [mRes, kRes] = await Promise.all([
        api.fetch("/api/ml/models"),
        api.fetch("/api/ml/kpis")
      ]);
      if (mRes.ok) setModels(await mRes.json());
      if (kRes.ok) setKpis(await kRes.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const fetchUebaProfiles = async () => {
    try {
      const res = await api.fetch("/api/ml/ueba/profiles");
      if (res.ok) setUebaProfiles(await res.json());
    } catch (e) {}
  };

  const fetchDatasets = async () => {
    try {
      const res = await api.fetch("/api/ml/datasets");
      if (res.ok) setDatasetsList(await res.json());
    } catch (e) {}
  };

  useEffect(() => {
    fetchModelsAndKpis();
    if (activeTab === "ueba") fetchUebaProfiles();
    if (activeTab === "datasets") fetchDatasets();
  }, [activeTab]);

  // Retrain Model Trigger
  const triggerRetrain = async (taskType, algorithm) => {
    setTrainingMsg(`Initiating asynchronous training for ${taskType}...`);
    try {
      const res = await api.fetch("/api/ml/train", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_type: taskType, algorithm })
      });
      if (res.ok) {
        const data = await res.json();
        setTrainingMsg(`Model ${data.name} (v${data.version}) trained successfully in ${data.training_duration_sec}s!`);
        fetchModelsAndKpis();
      } else {
        setTrainingMsg("Training failed or insufficient privileges.");
      }
    } catch (e) {
      setTrainingMsg(`Training error: ${e.message}`);
    }
  };

  // Classify Payload
  const classifyPayload = async () => {
    if (!payloadText.trim()) return;
    try {
      const res = await api.fetch("/api/ml/predict/payload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: payloadText })
      });
      if (res.ok) setPayloadRes(await res.json());
    } catch (e) {}
  };

  // Score NetFlow Anomaly
  const scoreAnomaly = async () => {
    try {
      const res = await api.fetch("/api/ml/predict/anomaly", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          packet_count: parseFloat(flowPackets),
          byte_count: parseFloat(flowBytes),
          duration_sec: parseFloat(flowDuration),
          dst_port: parseInt(flowPort),
          protocol: "TCP",
          bytes_out_ratio: parseFloat(flowRatio),
          is_off_hours: Boolean(flowOffHours)
        })
      });
      if (res.ok) setAnomalyRes(await res.json());
    } catch (e) {}
  };

  // Evaluate UEBA Event
  const evaluateUeba = async () => {
    try {
      const res = await api.fetch("/api/ml/predict/ueba", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: selectedUser,
          bytes_transferred: parseFloat(uebaBytes),
          event_hour: parseInt(uebaHour),
          login_latitude: parseFloat(uebaLat),
          login_longitude: parseFloat(uebaLon),
          city: uebaCity,
          country: uebaCountry,
          accessed_resource: "/api/financial/records"
        })
      });
      if (res.ok) setUebaRes(await res.json());
    } catch (e) {}
  };

  return h("div", { className: "module-container" },
    // KPI Banner
    kpis && h("div", { className: "kpi-grid", style: { marginBottom: "20px" } },
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Active ML Models"),
        h("div", { className: "kpi-value", style: { color: "var(--accent-cyan)" } }, `${kpis.active_models} / ${kpis.total_registered_models}`),
        h("div", { className: "kpi-sub" }, "100% On-Premises / Offline")
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Inferences Served"),
        h("div", { className: "kpi-value", style: { color: "var(--accent-blue)" } }, kpis.inferences_served.toLocaleString()),
        h("div", { className: "kpi-sub" }, `Avg Latency: ${kpis.avg_inference_latency_ms} ms`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Anomalies Flagged"),
        h("div", { className: "kpi-value", style: { color: "var(--accent-red)" } }, kpis.anomalies_detected),
        h("div", { className: "kpi-sub" }, `Anomaly Rate: ${kpis.anomaly_rate_percent}%`)
      ),
      h("div", { className: "kpi-card" },
        h("div", { className: "kpi-label" }, "Model Drift Alerts"),
        h("div", { className: "kpi-value", style: { color: "var(--accent-green)" } }, kpis.drift_alerts_count),
        h("div", { className: "kpi-sub" }, "Baseline Retraining Synchronized")
      )
    ),

    // Sub-Navigation Tabs Strip
    h("div", { style: { display: "flex", gap: "10px", marginBottom: "20px" } },
      h("button", {
        className: `btn ${activeTab === "registry" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("registry")
      }, "📦 Model Registry & Lifecycle"),
      h("button", {
        className: `btn ${activeTab === "playground" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("playground")
      }, "🧪 Interactive ML Inference Playground"),
      h("button", {
        className: `btn ${activeTab === "ueba" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("ueba")
      }, "👤 UEBA & Impossible Travel"),
      h("button", {
        className: `btn ${activeTab === "datasets" ? "btn-primary" : "btn-outline"}`,
        onClick: () => setActiveTab("datasets")
      }, "🗄️ Dataset Catalog")
    ),

    // TAB 1: MODEL REGISTRY
    activeTab === "registry" && h("div", null,
      trainingMsg && h("div", {
        style: {
          padding: "12px 16px",
          backgroundColor: "rgba(0, 229, 255, 0.1)",
          border: "1px solid var(--accent-cyan)",
          borderRadius: "6px",
          color: "var(--accent-cyan)",
          marginBottom: "16px",
          fontSize: "13px"
        }
      }, `ℹ️ ${trainingMsg}`),

      h("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "20px", marginBottom: "24px" } },
        models.map(m =>
          h("div", { key: m.id, className: "panel-box" },
            h("div", { className: "panel-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
              h("h3", null, m.name),
              h("span", { className: `badge ${m.status === "ACTIVE" ? "badge-info" : "badge-medium"}` }, m.status)
            ),
            h("div", { style: { padding: "20px" } },
              h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "8px", fontSize: "13px" } },
                h("span", { style: { color: "var(--text-secondary)" } }, "Model Version:"),
                h("strong", null, `v${m.version}`)
              ),
              h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "8px", fontSize: "13px" } },
                h("span", { style: { color: "var(--text-secondary)" } }, "Algorithm:"),
                h("code", null, m.algorithm)
              ),
              h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "8px", fontSize: "13px" } },
                h("span", { style: { color: "var(--text-secondary)" } }, "Task Type:"),
                h("span", { className: "badge badge-primary" }, m.task_type)
              ),
              h("div", { style: { display: "flex", justifyContent: "space-between", marginBottom: "12px", fontSize: "13px" } },
                h("span", { style: { color: "var(--text-secondary)" } }, "Training Dataset:"),
                h("span", null, m.dataset_name || "Built-in")
              ),

              // Metrics Highlight
              h("div", { style: { background: "var(--bg-card)", padding: "12px", borderRadius: "6px", marginBottom: "16px" } },
                h("div", { style: { fontSize: "12px", fontWeight: "bold", color: "var(--accent-cyan)", marginBottom: "6px" } }, "Validation Metrics:"),
                m.metrics.accuracy !== undefined && h("div", { style: { fontSize: "12px", marginBottom: "4px" } }, `Accuracy: ${(m.metrics.accuracy * 100).toFixed(1)}%`),
                m.metrics.weighted_f1 !== undefined && h("div", { style: { fontSize: "12px", marginBottom: "4px" } }, `Weighted F1 Score: ${(m.metrics.weighted_f1 * 100).toFixed(1)}%`),
                m.metrics.anomaly_rate !== undefined && h("div", { style: { fontSize: "12px", marginBottom: "4px" } }, `Contamination Anomaly Rate: ${(m.metrics.anomaly_rate * 100).toFixed(1)}%`),
                m.metrics.samples_trained && h("div", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, `Trained on ${m.metrics.samples_trained.toLocaleString()} samples`)
              ),

              h("button", {
                className: "btn btn-outline btn-block",
                onClick: () => triggerRetrain(m.task_type, m.algorithm)
              }, "🔄 Retrain & Update Checkpoint")
            )
          )
        )
      )
    ),

    // TAB 2: INTERACTIVE ML PLAYGROUND
    activeTab === "playground" && h("div", null,
      h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" } },
        // Left: Payload Attack Classifier Sandbox
        h("div", { className: "panel-box" },
          h("div", { className: "panel-header" }, h("h3", null, "🎯 Web Attack Payload Classifier")),
          h("div", { style: { padding: "20px" } },
            h("label", { className: "form-label" }, "Input Suspicious Payload or HTTP Request:"),
            h("textarea", {
              className: "form-input",
              rows: 4,
              value: payloadText,
              onChange: e => setPayloadText(e.target.value)
            }),
            h("div", { style: { display: "flex", gap: "6px", margin: "10px 0 16px" } },
              h("button", { className: "btn btn-outline btn-sm", onClick: () => setPayloadText("' OR 1=1 --") }, "SQLi"),
              h("button", { className: "btn btn-outline btn-sm", onClick: () => setPayloadText("<script>alert(document.cookie)</script>") }, "XSS"),
              h("button", { className: "btn btn-outline btn-sm", onClick: () => setPayloadText("; cat /etc/passwd") }, "Cmd Injection"),
              h("button", { className: "btn btn-outline btn-sm", onClick: () => setPayloadText("../../../../etc/shadow") }, "Path Traversal"),
              h("button", { className: "btn btn-outline btn-sm", onClick: () => setPayloadText("search?q=cybersecurity&page=2") }, "Benign")
            ),
            h("button", { className: "btn btn-primary btn-block", onClick: classifyPayload }, "⚡ Classify Payload (TF-IDF + Naive Bayes)"),

            payloadRes && h("div", { style: { marginTop: "16px", background: "var(--bg-card)", padding: "14px", borderRadius: "6px" } },
              h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
                h("h4", { style: { margin: 0, color: payloadRes.predicted_class === "BENIGN" ? "var(--accent-green)" : "var(--accent-red)" } }, payloadRes.predicted_class),
                h("span", { className: "badge badge-critical" }, `Confidence: ${(payloadRes.confidence * 100).toFixed(1)}%`)
              ),
              h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" } }, `Inference Latency: ${payloadRes.latency_ms} ms`),
              payloadRes.matched_indicators && payloadRes.matched_indicators.length > 0 && h("div", { style: { marginBottom: "8px" } },
                h("strong", { style: { fontSize: "12px" } }, "Explainability Indicators: "),
                payloadRes.matched_indicators.map((ind, i) => h("span", { key: i, className: "badge badge-medium", style: { marginRight: "4px" } }, ind))
              ),
              h("div", { style: { fontSize: "11px", color: "var(--text-secondary)" } },
                h("strong", null, "Class Probabilities: "),
                Object.entries(payloadRes.probabilities || {}).map(([k, v]) => `${k}: ${(v * 100).toFixed(0)}%`).join(" | ")
              )
            )
          )
        ),

        // Right: Isolation Forest NetFlow Anomaly Lab
        h("div", { className: "panel-box" },
          h("div", { className: "panel-header" }, h("h3", null, "🌲 Isolation Forest Network Flow Anomaly Lab")),
          h("div", { style: { padding: "20px" } },
            h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" } },
              h("div", null,
                h("label", { className: "form-label" }, "Packet Count:"),
                h("input", { type: "number", className: "form-input", value: flowPackets, onChange: e => setFlowPackets(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Byte Volume:"),
                h("input", { type: "number", className: "form-input", value: flowBytes, onChange: e => setFlowBytes(e.target.value) })
              )
            ),
            h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", marginBottom: "12px" } },
              h("div", null,
                h("label", { className: "form-label" }, "Duration (sec):"),
                h("input", { type: "number", className: "form-input", value: flowDuration, onChange: e => setFlowDuration(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Dst Port:"),
                h("input", { type: "number", className: "form-input", value: flowPort, onChange: e => setFlowPort(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Egress Ratio:"),
                h("input", { type: "number", step: "0.05", min: "0", max: "1", className: "form-input", value: flowRatio, onChange: e => setFlowRatio(e.target.value) })
              )
            ),
            h("div", { style: { marginBottom: "16px" } },
              h("label", { style: { fontSize: "13px", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px" } },
                h("input", { type: "checkbox", checked: flowOffHours, onChange: e => setFlowOffHours(e.target.checked) }),
                "Event Occurred Outside Standard Working Hours (Off-Hours Flag)"
              )
            ),
            h("button", { className: "btn btn-primary btn-block", onClick: scoreAnomaly }, "🌲 Calculate Anomaly Score (Isolation Forest)"),

            anomalyRes && h("div", { style: { marginTop: "16px", background: "var(--bg-card)", padding: "14px", borderRadius: "6px" } },
              h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
                h("h4", { style: { margin: 0, color: anomalyRes.is_anomaly ? "var(--accent-red)" : "var(--accent-green)" } },
                  anomalyRes.is_anomaly ? `⚠️ ${anomalyRes.classification}` : "✅ NORMAL OPERATIONAL FLOW"
                ),
                h("span", { className: `badge ${anomalyRes.is_anomaly ? "badge-critical" : "badge-info"}` }, `Risk: ${anomalyRes.risk_score}/100`)
              ),
              h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "6px" } },
                `Raw Score: ${anomalyRes.anomaly_score} | Latency: ${anomalyRes.latency_ms} ms`
              ),
              h("p", { style: { fontSize: "12px", margin: 0, color: "var(--text-primary)" } }, anomalyRes.explanation)
            )
          )
        )
      )
    ),

    // TAB 3: UEBA & IMPOSSIBLE TRAVEL
    activeTab === "ueba" && h("div", null,
      h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" } },
        // Left: User Behavioral Evaluation Console
        h("div", { className: "panel-box" },
          h("div", { className: "panel-header" }, h("h3", null, "👤 Real-Time User Behavior Evaluation")),
          h("div", { style: { padding: "20px" } },
            h("div", { style: { marginBottom: "12px" } },
              h("label", { className: "form-label" }, "Select User Account:"),
              h("select", { className: "form-input", value: selectedUser, onChange: e => setSelectedUser(e.target.value) },
                uebaProfiles.map(p => h("option", { key: p.username, value: p.username }, `${p.username} (${p.peer_group})`))
              )
            ),
            h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" } },
              h("div", null,
                h("label", { className: "form-label" }, "Bytes Transferred:"),
                h("input", { type: "number", className: "form-input", value: uebaBytes, onChange: e => setUebaBytes(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Login Hour (0-23):"),
                h("input", { type: "number", min: "0", max: "23", className: "form-input", value: uebaHour, onChange: e => setUebaHour(e.target.value) })
              )
            ),
            h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "8px", marginBottom: "16px" } },
              h("div", null,
                h("label", { className: "form-label" }, "Latitude:"),
                h("input", { type: "number", step: "0.01", className: "form-input", value: uebaLat, onChange: e => setUebaLat(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Longitude:"),
                h("input", { type: "number", step: "0.01", className: "form-input", value: uebaLon, onChange: e => setUebaLon(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "City:"),
                h("input", { type: "text", className: "form-input", value: uebaCity, onChange: e => setUebaCity(e.target.value) })
              ),
              h("div", null,
                h("label", { className: "form-label" }, "Country:"),
                h("input", { type: "text", className: "form-input", value: uebaCountry, onChange: e => setUebaCountry(e.target.value) })
              )
            ),
            h("button", { className: "btn btn-primary btn-block", onClick: evaluateUeba }, "📐 Evaluate Event Against User Baseline"),

            uebaRes && h("div", { style: { marginTop: "16px", background: "var(--bg-card)", padding: "14px", borderRadius: "6px" } },
              h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
                h("h4", { style: { margin: 0, color: uebaRes.is_anomalous ? "var(--accent-red)" : "var(--accent-green)" } },
                  uebaRes.is_anomalous ? "🚨 ANOMALOUS USER BEHAVIOR" : "✅ BEHAVIOR WITHIN BASELINE"
                ),
                h("span", { className: `badge ${uebaRes.risk_score >= 60 ? "badge-critical" : "badge-info"}` }, `Risk Score: ${uebaRes.risk_score}/100`)
              ),
              uebaRes.impossible_travel_detected && h("div", { style: { color: "var(--accent-red)", fontWeight: "bold", fontSize: "12px", marginBottom: "6px" } },
                `✈️ Impossible Travel: Velocity ${uebaRes.velocity_kmh} km/h (Distance: ${uebaRes.distance_km} km)`
              ),
              h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "6px" } },
                `Data Volume Z-Score: ${uebaRes.z_score_bytes > 0 ? "+" : ""}${uebaRes.z_score_bytes}σ | Peer Group: ${uebaRes.peer_group}`
              ),
              h("ul", { style: { paddingLeft: "20px", margin: 0, fontSize: "12px" } },
                (uebaRes.anomalous_factors || []).map((f, i) => h("li", { key: i }, f))
              )
            )
          )
        ),

        // Right: Profiles Registry Table
        h("div", { className: "panel-box" },
          h("div", { className: "panel-header" }, h("h3", null, "User Baseline Profiles Ledger")),
          h("div", { className: "table-responsive" },
            h("table", { className: "data-table" },
              h("thead", null,
                h("tr", null,
                  h("th", null, "User"),
                  h("th", null, "Peer Group"),
                  h("th", null, "Typical Hours"),
                  h("th", null, "Avg Daily Vol"),
                  h("th", null, "Risk")
                )
              ),
              h("tbody", null,
                uebaProfiles.map(p =>
                  h("tr", { key: p.id },
                    h("td", null, h("strong", null, p.username)),
                    h("td", null, p.peer_group),
                    h("td", null, `${minHour(p.typical_login_hours)}:00 - ${maxHour(p.typical_login_hours)}:00`),
                    h("td", null, `${(p.avg_bytes_transferred / 1048576.0).toFixed(1)} MB`),
                    h("td", null, h("span", { className: `badge ${p.risk_score > 30 ? "badge-high" : "badge-info"}` }, `${p.risk_score}`))
                  )
                )
              )
            )
          )
        )
      )
    ),

    // TAB 4: DATASETS CATALOG
    activeTab === "datasets" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "🗄️ Standardized Security Datasets for Offline Training")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Dataset Name"),
              h("th", null, "Type"),
              h("th", null, "Samples"),
              h("th", null, "Features"),
              h("th", null, "Class Distribution"),
              h("th", null, "Created At")
            )
          ),
          h("tbody", null,
            datasetsList.map(d =>
              h("tr", { key: d.name },
                h("td", null, h("strong", { style: { color: "var(--accent-cyan)" } }, d.name)),
                h("td", null, d.dataset_type),
                h("td", null, d.samples_count.toLocaleString()),
                h("td", null, d.features_count),
                h("td", null, Object.entries(d.labels_distribution || {}).map(([k, v]) => `${k}: ${v}`).join(", ")),
                h("td", null, d.created_at.substring(0, 19).replace("T", " "))
              )
            )
          )
        )
      )
    )
  );
}

function minHour(hours) {
  if (!hours || !hours.length) return 8;
  return Math.min(...hours);
}

function maxHour(hours) {
  if (!hours || !hours.length) return 18;
  return Math.max(...hours);
}

// 10. Data Pipelines View (Phase 7)
function DataPipelinesView({ currentUser }) {
  const [pipelines, setPipelines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState(null);
  const [runResult, setRunResult] = useState(null);
  const [error, setError] = useState(null);

  const fetchPipelines = async () => {
    try {
      setLoading(true);
      const res = await api.fetch("/api/analytics/pipelines");
      if (res.ok) {
        const data = await res.json();
        setPipelines(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPipelines();
  }, []);

  const runPipeline = async (pipeId) => {
    try {
      setRunningId(pipeId);
      setError(null);
      const res = await api.fetch(`/api/analytics/pipelines/${pipeId}/run`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        setRunResult(data);
        fetchPipelines();
      } else {
        const err = await res.json();
        setError(err.detail || "Pipeline run failed");
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setRunningId(null);
    }
  };

  const totalProcessed = pipelines.reduce((sum, p) => sum + (p.records_processed || 0), 0);

  return h("div", { className: "view-content" },
    // Banner
    h("div", { className: "panel-box mb-4" },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        h("div", null,
          h("h2", { style: { margin: 0, color: "var(--cyan-neon)" } }, "🔄 Scheduled Data Pipelines & Feature Orchestration"),
          h("p", { style: { margin: "4px 0 0", color: "var(--text-secondary)", fontSize: "13px" } },
            "Autonomous batch ETL workflows, time-series telemetry rollups, and offline feature materialization"
          )
        ),
        h("button", {
          className: "btn btn-secondary",
          onClick: fetchPipelines,
          disabled: loading
        }, loading ? "Refreshing..." : "🔄 Refresh Status")
      )
    ),

    // Metric Summary Cards
    h("div", { className: "stats-grid mb-4" },
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Configured Pipelines"),
        h("div", { className: "stat-value", style: { color: "var(--cyan-neon)" } }, pipelines.length),
        h("div", { className: "stat-sub" }, "Automated Cron Workers")
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Running Jobs"),
        h("div", { className: "stat-value", style: { color: runningId ? "var(--yellow-amber)" : "var(--green-neon)" } },
          runningId ? "1 ACTIVE" : "0 IDLE"
        ),
        h("div", { className: "stat-sub" }, runningId ? `Running ID #${runningId}` : "All workers ready")
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Total Records Processed"),
        h("div", { className: "stat-value", style: { color: "var(--purple-accent)" } }, totalProcessed.toLocaleString()),
        h("div", { className: "stat-sub" }, "Events, metrics & vectors")
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Pipeline Engine"),
        h("div", { className: "stat-value", style: { color: "var(--green-neon)" } }, "HEALTHY"),
        h("div", { className: "stat-sub" }, "Zero SaaS dependencies")
      )
    ),

    // Execution Error Alert
    error && h("div", { className: "panel-box mb-4", style: { border: "1px solid var(--red-critical)", background: "var(--accent-subtle)" } },
      h("strong", { style: { color: "var(--red-critical)" } }, "⚠️ Execution Failed: "),
      h("span", null, error)
    ),

    // Run Result Drawer/Modal
    runResult && h("div", { className: "panel-box mb-4", style: { border: "1px solid var(--green-neon)", background: "var(--accent-subtle)" } },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" } },
        h("div", { style: { display: "flex", alignItems: "center", gap: "10px" } },
          h("span", { style: { fontSize: "20px" } }, "✅"),
          h("h4", { style: { margin: 0, color: "var(--green-neon)" } }, `Pipeline Executed: ${runResult.name}`),
          h("span", { className: "badge badge-success" }, runResult.status)
        ),
        h("button", { className: "btn btn-sm btn-secondary", onClick: () => setRunResult(null) }, "✕ Dismiss")
      ),
      h("div", { style: { display: "flex", gap: "24px", fontSize: "13px", marginBottom: "12px", color: "var(--text-secondary)" } },
        h("div", null, h("strong", { style: { color: "var(--text-primary)" } }, "Records Processed: "), runResult.records_processed),
        h("div", null, h("strong", { style: { color: "var(--text-primary)" } }, "Duration: "), `${runResult.duration_ms.toFixed(1)} ms`),
        h("div", null, h("strong", { style: { color: "var(--text-primary)" } }, "Completed At: "), (runResult.completed_at || "").substring(0, 19).replace("T", " "))
      ),
      h("div", { style: { background: "var(--bg-primary)", padding: "12px", borderRadius: "6px", fontFamily: "var(--font-mono)", fontSize: "12px" } },
        h("div", { style: { color: "var(--cyan-neon)", marginBottom: "6px" } }, "Execution Trace Log:"),
        (runResult.execution_log || []).map((step, idx) =>
          h("div", { key: idx, style: { color: "var(--text-muted)", lineHeight: "1.6" } }, `[step ${idx + 1}] ${step}`)
        )
      )
    ),

    // Pipelines List
    h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "Configured ETL Workflows & Data Pipelines")
      ),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "ID"),
              h("th", null, "Pipeline Name"),
              h("th", null, "Type"),
              h("th", null, "Schedule (Cron)"),
              h("th", null, "Status"),
              h("th", null, "Records Processed"),
              h("th", null, "Last Execution"),
              h("th", null, "Action")
            )
          ),
          h("tbody", null,
            pipelines.map(p =>
              h("tr", { key: p.id },
                h("td", null, `#${p.id}`),
                h("td", null,
                  h("strong", { style: { color: "var(--text-primary)" } }, p.name)
                ),
                h("td", null,
                  h("span", { className: "badge badge-info" }, p.pipeline_type.replace(/_/g, " "))
                ),
                h("td", null,
                  h("code", { style: { color: "var(--cyan-neon)" } }, p.schedule_cron)
                ),
                h("td", null,
                  h("span", {
                    className: `badge ${p.status === "completed" ? "badge-success" : p.status === "running" ? "badge-warning" : p.status === "failed" ? "badge-critical" : "badge-info"}`
                  }, p.status.toUpperCase())
                ),
                h("td", null, (p.records_processed || 0).toLocaleString()),
                h("td", null, p.last_run_at ? p.last_run_at.substring(0, 19).replace("T", " ") : "Never"),
                h("td", null,
                  h("button", {
                    className: "btn btn-sm btn-primary",
                    disabled: runningId === p.id,
                    onClick: () => runPipeline(p.id)
                  }, runningId === p.id ? "Running..." : "⚡ Run Now")
                )
              )
            )
          )
        )
      )
    )
  );
}

// 11. Security Analytics & Posture View (Phase 7)
function SecurityAnalyticsView({ currentUser }) {
  const [activeTab, setActiveTab] = useState("posture");
  const [posture, setPosture] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [rollups, setRollups] = useState([]);
  const [loading, setLoading] = useState(true);

  // Feature Store Inspector State
  const [featureEntity, setFeatureEntity] = useState("192.168.1.100");
  const [featureType, setFeatureType] = useState("ip");
  const [featureResult, setFeatureResult] = useState(null);
  const [featureLoading, setFeatureLoading] = useState(false);
  const [featureError, setFeatureError] = useState(null);

  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      const [posRes, mitRes, rolRes] = await Promise.all([
        api.fetch("/api/analytics/posture"),
        api.fetch("/api/analytics/mitre/coverage"),
        api.fetch("/api/analytics/metrics/rollup?hours=24")
      ]);
      if (posRes.ok) setPosture(await posRes.json());
      if (mitRes.ok) setMitreData(await mitRes.json());
      if (rolRes.ok) setRollups(await rolRes.json());
    } catch (err) {
      console.error("Analytics fetch failed:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyticsData();
  }, []);

  const inspectFeature = async () => {
    if (!featureEntity.trim()) return;
    try {
      setFeatureLoading(true);
      setFeatureError(null);
      const res = await api.fetch(`/api/analytics/features/${encodeURIComponent(featureEntity.trim())}?feature_group=${encodeURIComponent(featureType)}`);
      if (res.ok) {
        setFeatureResult(await res.json());
      } else {
        const err = await res.json();
        setFeatureError(err.detail || "Feature record not found");
        setFeatureResult(null);
      }
    } catch (err) {
      setFeatureError(err.message);
    } finally {
      setFeatureLoading(false);
    }
  };

  const currentGrade = posture ? (posture.security_grade || posture.grade || "B") : "B";
  const currentScore = posture ? (posture.overall_score !== undefined ? posture.overall_score : (posture.posture_index || 85.0)) : 85.0;
  const currentCoverage = posture ? (posture.detection_coverage_score !== undefined ? posture.detection_coverage_score : (posture.mitre_coverage_pct || 75.0)) : 75.0;

  const getGradeColor = (grade) => {
    if (!grade) return "var(--cyan-neon)";
    if (grade.startsWith("A")) return "var(--green-neon)";
    if (grade.startsWith("B")) return "var(--cyan-neon)";
    if (grade.startsWith("C")) return "var(--yellow-amber)";
    return "var(--red-critical)";
  };

  const tacticsList = mitreData ? (Array.isArray(mitreData.tactics) ? mitreData.tactics : Object.entries(mitreData.tactics || {}).map(([k, v]) => ({ tactic_name: k, ...v }))) : [];
  const overallCov = mitreData ? (mitreData.coverage_percentage !== undefined ? mitreData.coverage_percentage : (mitreData.overall_coverage_pct || 0)) : 0;
  const coveredCount = mitreData ? (mitreData.covered_tactics !== undefined ? mitreData.covered_tactics : (mitreData.total_covered || 0)) : 0;
  const totalCount = mitreData ? (mitreData.total_tactics !== undefined ? mitreData.total_tactics : (mitreData.total_techniques || 14)) : 14;

  return h("div", { className: "view-content" },
    // Banner & Controls
    h("div", { className: "panel-box mb-4" },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        h("div", null,
          h("h2", { style: { margin: 0, color: "var(--cyan-neon)" } }, "📈 Executive Security Analytics & Posture Management"),
          h("p", { style: { margin: "4px 0 0", color: "var(--text-secondary)", fontSize: "13px" } },
            "Continuous posture scoring (SPI), 14-tactic MITRE ATT&CK coverage matrix, and real-time feature store"
          )
        ),
        h("button", {
          className: "btn btn-secondary",
          onClick: fetchAnalyticsData,
          disabled: loading
        }, loading ? "Refreshing..." : "🔄 Recalculate Analytics")
      )
    ),

    // Sub-Navigation Tabs
    h("div", { className: "tab-bar mb-4" },
      h("button", {
        className: `tab-btn ${activeTab === "posture" ? "active" : ""}`,
        onClick: () => setActiveTab("posture")
      }, "🛡️ Security Posture Index (SPI)"),
      h("button", {
        className: `tab-btn ${activeTab === "mitre" ? "active" : ""}`,
        onClick: () => setActiveTab("mitre")
      }, "🎯 MITRE ATT&CK Defense Matrix"),
      h("button", {
        className: `tab-btn ${activeTab === "rollups" ? "active" : ""}`,
        onClick: () => setActiveTab("rollups")
      }, "⏱️ 24h Hourly Metric Rollups"),
      h("button", {
        className: `tab-btn ${activeTab === "features" ? "active" : ""}`,
        onClick: () => setActiveTab("features")
      }, "🗄️ Feature Store Inspector")
    ),

    // TAB 1: POSTURE INDEX
    activeTab === "posture" && posture && h("div", null,
      // Hero Posture Card
      h("div", { className: "panel-box mb-4", style: { border: `1px solid ${getGradeColor(currentGrade)}`, background: "var(--bg-secondary)" } },
        h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "20px" } },
          h("div", { style: { display: "flex", alignItems: "center", gap: "24px" } },
            h("div", {
              style: {
                width: "90px",
                height: "90px",
                borderRadius: "50%",
                border: `3px solid ${getGradeColor(currentGrade)}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "36px",
                fontWeight: "bold",
                color: getGradeColor(currentGrade),
                boxShadow: `0 0 16px ${getGradeColor(currentGrade)}33`
              }
            }, currentGrade),
            h("div", null,
              h("div", { style: { fontSize: "14px", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "1px" } }, "Enterprise Security Posture Index"),
              h("div", { style: { fontSize: "38px", fontWeight: "800", color: "var(--text-primary)" } },
                `${Number(currentScore).toFixed(1)}`,
                h("span", { style: { fontSize: "20px", color: "var(--text-muted)", fontWeight: "normal" } }, " / 100")
              ),
              h("div", { style: { fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" } },
                (posture.recommendations && posture.recommendations[0]) || "Posture index calculated via multi-vector risk model"
              )
            )
          ),
          h("div", { style: { textAlign: "right", fontSize: "12px", color: "var(--text-muted)" } },
            h("div", null, "Assessment Model: Multi-Vector Bayesian Posture Engine"),
            h("div", null, `Calculated At: ${new Date().toISOString().substring(0, 19).replace("T", " ")} UTC`)
          )
        )
      ),

      // Posture Factor Breakdown Cards
      h("div", { className: "stats-grid mb-4" },
        h("div", { className: "stat-card" },
          h("div", { className: "stat-label" }, "Critical Exposures"),
          h("div", { className: "stat-value", style: { color: (posture.critical_unpatched_assets || 0) > 0 ? "var(--red-critical)" : "var(--green-neon)" } },
            posture.critical_unpatched_assets || 0
          ),
          h("div", { className: "stat-sub" }, "High-Priority Exposures")
        ),
        h("div", { className: "stat-card" },
          h("div", { className: "stat-label" }, "Active Incidents"),
          h("div", { className: "stat-value", style: { color: (posture.active_incidents_count || 0) > 0 ? "var(--red-critical)" : "var(--green-neon)" } },
            posture.active_incidents_count || 0
          ),
          h("div", { className: "stat-sub" }, "Uncontained Threats")
        ),
        h("div", { className: "stat-card" },
          h("div", { className: "stat-label" }, "Attack Surface Score"),
          h("div", { className: "stat-value", style: { color: "var(--cyan-neon)" } },
            `${(posture.attack_surface_score !== undefined ? posture.attack_surface_score : 90).toFixed(0)}/100`
          ),
          h("div", { className: "stat-sub" }, "Host Hardening Index")
        ),
        h("div", { className: "stat-card" },
          h("div", { className: "stat-label" }, "MITRE Defense Coverage"),
          h("div", { className: "stat-value", style: { color: "var(--green-neon)" } }, `${Number(currentCoverage).toFixed(1)}%`),
          h("div", { className: "stat-sub" }, "14 ATT&CK Tactics")
        )
      ),

      // Posture Recommendations Panel
      posture.recommendations && posture.recommendations.length > 0 && h("div", { className: "panel-box" },
        h("div", { className: "panel-header" }, h("h3", null, "Recommended Posture Remediation Actions")),
        h("ul", { style: { paddingLeft: "20px", margin: 0, fontSize: "13px", color: "var(--text-secondary)", lineHeight: "1.8" } },
          posture.recommendations.map((rec, idx) =>
            h("li", { key: idx }, rec)
          )
        )
      )
    ),

    // TAB 2: MITRE ATT&CK MATRIX
    activeTab === "mitre" && mitreData && h("div", null,
      // Overview Bar
      h("div", { className: "panel-box mb-4" },
        h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
          h("div", null,
            h("strong", { style: { fontSize: "16px" } }, "Enterprise MITRE ATT&CK Matrix Coverage"),
            h("span", { style: { marginLeft: "12px", color: "var(--text-secondary)", fontSize: "13px" } },
              `${coveredCount} of ${totalCount} Tactics Actively Monitored`
            )
          ),
          h("span", { className: "badge badge-success", style: { fontSize: "14px" } }, `${Number(overallCov).toFixed(1)}% Defense Coverage`)
        ),
        h("div", { style: { width: "100%", height: "10px", background: "var(--bg-primary)", borderRadius: "5px", overflow: "hidden" } },
          h("div", {
            style: {
              width: `${overallCov}%`,
              height: "100%",
              background: "var(--accent-primary)",
              borderRadius: "5px",
              transition: "width 0.4s ease"
            }
          })
        )
      ),

      // Tactics 14-Grid
      h("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "16px" } },
        tacticsList.map(tac => {
          const isCov = tac.is_covered || (tac.rules_count > 0);
          return h("div", {
            key: tac.tactic_id || tac.tactic_name,
            className: "panel-box",
            style: {
              borderLeft: `4px solid ${isCov ? "var(--green-neon)" : "var(--yellow-amber)"}`,
              padding: "16px"
            }
          },
            h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" } },
              h("strong", { style: { fontSize: "13px", color: "var(--text-primary)" } }, tac.tactic_name),
              h("span", {
                className: `badge ${isCov ? "badge-success" : "badge-warning"}`
              }, isCov ? "COVERED" : "UNCOVERED")
            ),
            h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginBottom: "10px" } },
              `${tac.rules_count || 0} active detection rules`
            ),
            tac.techniques_covered && tac.techniques_covered.length > 0 ? h("div", { style: { display: "flex", flexWrap: "wrap", gap: "4px" } },
              tac.techniques_covered.map(tech =>
                h("span", { key: tech, className: "badge badge-info", style: { fontSize: "10px" } }, tech)
              )
            ) : h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "No rules mapped to this tactic yet")
          );
        })
      )
    ),

    // TAB 3: HOURLY ROLLUPS
    activeTab === "rollups" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" },
        h("h3", null, "24-Hour Telemetry & Performance Metric Rollups")
      ),
      rollups.length === 0 ? h("div", { style: { padding: "24px", textAlign: "center", color: "var(--text-muted)" } },
        "No rollup metrics found for the last 24 hours. Trigger the hourly rollup ETL pipeline to generate time-series metrics."
      ) : h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Time Bucket"),
              h("th", null, "Events Ingested"),
              h("th", null, "Alerts Generated"),
              h("th", null, "Critical Alerts"),
              h("th", null, "MTTD (sec)"),
              h("th", null, "MTTR (sec)"),
              h("th", null, "Surface Score")
            )
          ),
          h("tbody", null,
            rollups.map(r =>
              h("tr", { key: r.id },
                h("td", null, h("code", { style: { color: "var(--cyan-neon)" } }, (r.timestamp || "").substring(0, 19).replace("T", " "))),
                h("td", null, (r.total_events || 0).toLocaleString()),
                h("td", null, r.total_alerts || 0),
                h("td", null,
                  h("span", { className: `badge ${(r.critical_alerts || 0) > 0 ? "badge-critical" : "badge-info"}` }, r.critical_alerts || 0)
                ),
                h("td", null, `${(r.mttd_seconds || 0).toFixed(1)}s`),
                h("td", null, `${(r.mttr_seconds || 0).toFixed(1)}s`),
                h("td", null, `${(r.attack_surface_score || 0).toFixed(0)}/100`)
              )
            )
          )
        )
      )
    ),

    // TAB 4: FEATURE STORE INSPECTOR
    activeTab === "features" && h("div", null,
      h("div", { className: "panel-box mb-4" },
        h("div", { className: "panel-header" },
          h("h3", null, "🔍 Online / Offline Feature Store Lookup")
        ),
        h("div", { style: { display: "flex", gap: "12px", alignItems: "flex-end", flexWrap: "wrap" } },
          h("div", { style: { flex: "1", minWidth: "220px" } },
            h("label", { className: "form-label" }, "Entity Identifier:"),
            h("input", {
              type: "text",
              className: "form-input",
              placeholder: "e.g. 192.168.1.100 or DEV-SRV-01",
              value: featureEntity,
              onChange: e => setFeatureEntity(e.target.value)
            })
          ),
          h("div", { style: { width: "200px" } },
            h("label", { className: "form-label" }, "Feature Group:"),
            h("select", {
              className: "form-input",
              value: featureType,
              onChange: e => setFeatureType(e.target.value)
            },
              h("option", { value: "DEVICE_HOURLY" }, "DEVICE_HOURLY"),
              h("option", { value: "USER_BEHAVIORAL" }, "USER_BEHAVIORAL"),
              h("option", { value: "NETWORK_FLOW" }, "NETWORK_FLOW")
            )
          ),
          h("button", {
            className: "btn btn-primary",
            onClick: inspectFeature,
            disabled: featureLoading
          }, featureLoading ? "Querying Store..." : "Inspect Materialized Features")
        )
      ),

      featureError && h("div", { className: "panel-box mb-4", style: { border: "1px solid var(--orange-warn)", color: "var(--orange-warn)" } },
        `Notice: ${featureError}`
      ),

      featureResult && h("div", { className: "panel-box" },
        h("div", { className: "panel-header" },
          h("h3", null, `Feature Vector: ${featureResult.entity_id} (${featureResult.feature_group})`),
          h("span", { className: "badge badge-info" },
            `Dimension: ${Object.keys(featureResult.feature_vector || {}).length} features`
          )
        ),
        h("div", { style: { display: "flex", gap: "24px", fontSize: "12px", color: "var(--text-secondary)", marginBottom: "16px" } },
          h("div", null, h("strong", null, "Computed At: "), (featureResult.computed_at || "").substring(0, 19).replace("T", " "))
        ),
        h("div", { style: { background: "var(--bg-primary)", padding: "16px", borderRadius: "6px", fontFamily: "var(--font-mono)", fontSize: "13px" } },
          h("div", { style: { color: "var(--cyan-neon)", marginBottom: "8px" } }, "Feature Vector JSON:"),
          h("pre", { style: { margin: 0, color: "var(--text-primary)", overflowX: "auto" } },
            JSON.stringify(featureResult.feature_vector, null, 2)
          )
        )
      )
    )
  );
}

// 12. Distributed Task Processing & Background Workers View (Phase 8)
function TaskQueueView({ currentUser }) {
  const [tasks, setTasks] = useState([]);
  const [poolStatus, setPoolStatus] = useState(null);
  const [eventHistory, setEventHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("tasks");
  const [loading, setLoading] = useState(true);
  const [selectedTask, setSelectedTask] = useState(null);
  const [submittingType, setSubmittingType] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);

  const fetchTaskData = async () => {
    try {
      setLoading(true);
      const [tasksRes, poolRes, evRes] = await Promise.all([
        api.fetch("/api/tasks?limit=50"),
        api.fetch("/api/tasks/workers/status"),
        api.fetch("/api/tasks/events/history?limit=30")
      ]);
      if (tasksRes.ok) setTasks(await tasksRes.json());
      if (poolRes.ok) setPoolStatus(await poolRes.json());
      if (evRes.ok) setEventHistory(await evRes.json());
    } catch (err) {
      console.error("Task data fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTaskData();
    const timer = setInterval(fetchTaskData, 5000);
    return () => clearInterval(timer);
  }, []);

  const dispatchTask = async (taskType, priority = "NORMAL", payload = {}) => {
    try {
      setSubmittingType(taskType);
      setActionMessage(null);
      const res = await api.fetch("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_type: taskType, priority, payload })
      });
      if (res.ok) {
        const newTask = await res.json();
        setActionMessage(`Dispatched task #${newTask.id} (${taskType}) to worker pool.`);
        fetchTaskData();
      } else {
        const err = await res.json();
        setActionMessage(`Failed to dispatch: ${err.detail || "Error"}`);
      }
    } catch (e) {
      setActionMessage(`Network error: ${e.message}`);
    } finally {
      setSubmittingType(null);
    }
  };

  const cancelTask = async (taskId) => {
    try {
      const res = await api.fetch(`/api/tasks/${taskId}/cancel`, { method: "POST" });
      if (res.ok) {
        fetchTaskData();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case "PROCESSING":
        return h("span", { className: "badge badge-warning" }, "⚡ PROCESSING");
      case "SUCCESS":
        return h("span", { className: "badge badge-success" }, "✅ SUCCESS");
      case "FAILED":
        return h("span", { className: "badge badge-critical" }, "❌ FAILED");
      case "CANCELLED":
        return h("span", { className: "badge badge-info" }, "🚫 CANCELLED");
      default:
        return h("span", { className: "badge badge-info" }, "⏳ QUEUED");
    }
  };

  const getPriorityBadge = (prio) => {
    switch (prio) {
      case "CRITICAL":
        return h("span", { className: "badge badge-critical" }, "CRITICAL");
      case "HIGH":
        return h("span", { className: "badge badge-warning" }, "HIGH");
      default:
        return h("span", { className: "badge badge-info" }, prio);
    }
  };

  return h("div", { className: "view-content" },
    // Banner
    h("div", { className: "panel-box mb-4" },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
        h("div", null,
          h("h2", { style: { margin: 0, color: "var(--cyan-neon)" } }, "⚙️ Distributed Background Tasks & Asynchronous Worker Pool"),
          h("p", { style: { margin: "4px 0 0", color: "var(--text-secondary)", fontSize: "13px" } },
            "Decoupled asynchronous worker execution, priority queues, and live event bus telemetry"
          )
        ),
        h("button", {
          className: "btn btn-secondary",
          onClick: fetchTaskData,
          disabled: loading
        }, loading ? "Polling..." : "🔄 Refresh Queue")
      )
    ),

    // Pool Health Metrics Cards
    poolStatus && h("div", { className: "stats-grid mb-4" },
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Worker Pool Health"),
        h("div", { className: "stat-value", style: { color: "var(--green-neon)" } },
          `${poolStatus.active_workers}/${poolStatus.total_workers} BUSY`
        ),
        h("div", { className: "stat-sub" }, `${poolStatus.idle_workers} workers idle and ready`)
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Queue Depth"),
        h("div", { className: "stat-value", style: { color: poolStatus.queued_tasks > 0 ? "var(--yellow-amber)" : "var(--cyan-neon)" } },
          poolStatus.queued_tasks
        ),
        h("div", { className: "stat-sub" }, "Pending worker pickup")
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Tasks in Flight"),
        h("div", { className: "stat-value", style: { color: poolStatus.processing_tasks > 0 ? "var(--purple-accent)" : "var(--green-neon)" } },
          poolStatus.processing_tasks
        ),
        h("div", { className: "stat-sub" }, "Actively processing")
      ),
      h("div", { className: "stat-card" },
        h("div", { className: "stat-label" }, "Tasks Completed"),
        h("div", { className: "stat-value", style: { color: "var(--cyan-neon)" } }, poolStatus.completed_today),
        h("div", { className: "stat-sub" }, `${poolStatus.failed_today} failed executions`)
      )
    ),

    // Fast Action Dispatch Toolbar
    h("div", { className: "panel-box mb-4" },
      h("div", { className: "panel-header" }, h("h3", null, "⚡ One-Click Asynchronous Task Dispatcher")),
      h("div", { style: { display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" } },
        h("button", {
          className: "btn btn-primary",
          disabled: submittingType !== null,
          onClick: () => dispatchTask("TELEMETRY_INGESTION", "NORMAL", { default_host: "SRV-EDGE-01" })
        }, submittingType === "TELEMETRY_INGESTION" ? "Queueing..." : "📥 Ingest Telemetry Batch"),
        h("button", {
          className: "btn btn-secondary",
          disabled: submittingType !== null,
          onClick: () => dispatchTask("MALWARE_ANALYSIS", "HIGH", { file_name: "suspicious_payload.exe", format: "PE" })
        }, submittingType === "MALWARE_ANALYSIS" ? "Queueing..." : "🔬 Deep Malware Binary Scan"),
        h("button", {
          className: "btn btn-secondary",
          disabled: submittingType !== null,
          onClick: () => dispatchTask("INTEL_SYNC", "NORMAL", { feed_name: "CISA-Automated-Indicator-Sharing" })
        }, submittingType === "INTEL_SYNC" ? "Queueing..." : "🧠 Sync Threat Intel Feed"),
        h("button", {
          className: "btn btn-danger",
          disabled: submittingType !== null,
          onClick: () => dispatchTask("SOAR_PLAYBOOK", "CRITICAL", { playbook_name: "RANSOMWARE_CONTAINMENT", target_host: "192.168.1.55" })
        }, submittingType === "SOAR_PLAYBOOK" ? "Queueing..." : "🛡️ Run SOAR Playbook")
      ),
      actionMessage && h("div", { style: { marginTop: "10px", fontSize: "12px", color: "var(--cyan-neon)" } }, `ℹ️ ${actionMessage}`)
    ),

    // Sub-Navigation Tabs
    h("div", { className: "tab-bar mb-4" },
      h("button", {
        className: `tab-btn ${activeTab === "tasks" ? "active" : ""}`,
        onClick: () => setActiveTab("tasks")
      }, `📋 Tasks Ledger (${tasks.length})`),
      h("button", {
        className: `tab-btn ${activeTab === "workers" ? "active" : ""}`,
        onClick: () => setActiveTab("workers")
      }, `💻 Worker Nodes (${(poolStatus?.workers || []).length})`),
      h("button", {
        className: `tab-btn ${activeTab === "events" ? "active" : ""}`,
        onClick: () => setActiveTab("events")
      }, `📡 Live Event Bus Stream (${eventHistory.length})`)
    ),

    // TAB 1: TASKS LEDGER
    activeTab === "tasks" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Asynchronous Background Jobs Ledger")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Task ID"),
              h("th", null, "Category"),
              h("th", null, "Priority"),
              h("th", null, "Status"),
              h("th", null, "Progress"),
              h("th", null, "Worker"),
              h("th", null, "Duration"),
              h("th", null, "Queued At"),
              h("th", null, "Actions")
            )
          ),
          h("tbody", null,
            tasks.length === 0 ? h("tr", null, h("td", { colSpan: 9, style: { textAlign: "center", color: "var(--text-muted)", padding: "24px" } }, "No background tasks logged yet. Dispatch a task above to start."))
            : tasks.map(t =>
              h("tr", { key: t.id },
                h("td", null, h("code", { style: { color: "var(--cyan-neon)" } }, t.id)),
                h("td", null, h("span", { className: "badge badge-info" }, t.task_type.replace(/_/g, " "))),
                h("td", null, getPriorityBadge(t.priority)),
                h("td", null, getStatusBadge(t.status)),
                h("td", { style: { minWidth: "120px" } },
                  h("div", { style: { display: "flex", alignItems: "center", gap: "8px" } },
                    h("div", { style: { flex: 1, height: "6px", background: "var(--bg-primary)", borderRadius: "3px", overflow: "hidden" } },
                      h("div", {
                        style: {
                          width: `${t.progress_pct || 0}%`,
                          height: "100%",
                          background: t.status === "SUCCESS" ? "var(--green-neon)" : t.status === "FAILED" ? "var(--red-critical)" : "var(--cyan-neon)",
                          transition: "width 0.3s ease"
                        }
                      })
                    ),
                    h("span", { style: { fontSize: "11px", color: "var(--text-secondary)" } }, `${Math.round(t.progress_pct || 0)}%`)
                  )
                ),
                h("td", null, t.worker_id || "—"),
                h("td", null, `${(t.duration_sec || 0).toFixed(2)}s`),
                h("td", null, (t.queued_at || "").substring(11, 19)),
                h("td", null,
                  h("div", { style: { display: "flex", gap: "6px" } },
                    h("button", {
                      className: "btn btn-sm btn-secondary",
                      onClick: () => setSelectedTask(t)
                    }, "Inspect"),
                    ["QUEUED", "PROCESSING"].includes(t.status) && h("button", {
                      className: "btn btn-sm btn-danger",
                      onClick: () => cancelTask(t.id)
                    }, "✕")
                  )
                )
              )
            )
          )
        )
      )
    ),

    // TAB 2: WORKER NODES
    activeTab === "workers" && poolStatus && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Active Worker Node Telemetry")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Worker ID"),
              h("th", null, "Status"),
              h("th", null, "Current Task"),
              h("th", null, "Completed"),
              h("th", null, "Failed"),
              h("th", null, "Uptime"),
              h("th", null, "Last Heartbeat")
            )
          ),
          h("tbody", null,
            (poolStatus.workers || []).map(w =>
              h("tr", { key: w.worker_id },
                h("td", null, h("strong", { style: { color: "var(--text-primary)" } }, w.worker_id)),
                h("td", null,
                  h("span", {
                    className: `badge ${w.status === "BUSY" ? "badge-warning" : w.status === "IDLE" ? "badge-success" : "badge-info"}`
                  }, w.status)
                ),
                h("td", null, w.current_task_id ? h("code", { style: { color: "var(--cyan-neon)" } }, w.current_task_id) : "—"),
                h("td", null, w.tasks_completed),
                h("td", null, w.tasks_failed),
                h("td", null, `${Math.round(w.uptime_sec || 0)}s`),
                h("td", null, (w.last_heartbeat || "").substring(11, 19))
              )
            )
          )
        )
      )
    ),

    // TAB 3: EVENT BUS STREAM
    activeTab === "events" && h("div", { className: "panel-box" },
      h("div", { className: "panel-header" }, h("h3", null, "Asynchronous Event Bus Packet Stream")),
      h("div", { className: "table-responsive" },
        h("table", { className: "data-table" },
          h("thead", null,
            h("tr", null,
              h("th", null, "Seq"),
              h("th", null, "Topic"),
              h("th", null, "Payload Summary"),
              h("th", null, "Timestamp")
            )
          ),
          h("tbody", null,
            eventHistory.map((ev, idx) =>
              h("tr", { key: idx },
                h("td", null, `#${ev.seq || idx + 1}`),
                h("td", null, h("code", { style: { color: "var(--green-neon)" } }, ev.topic)),
                h("td", null,
                  h("span", { style: { fontSize: "12px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" } },
                    JSON.stringify(ev.data).substring(0, 80)
                  )
                ),
                h("td", null, (ev.timestamp || "").substring(11, 19))
              )
            )
          )
        )
      )
    ),

    // Task Detail Inspector Modal
    selectedTask && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "700px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `Task Inspector: ${selectedTask.id}`),
          h("button", { className: "modal-close", onClick: () => setSelectedTask(null) }, "✕")
        ),
        h("div", { style: { display: "flex", gap: "16px", marginBottom: "16px", fontSize: "13px" } },
          h("div", null, h("strong", null, "Category: "), selectedTask.task_type),
          h("div", null, h("strong", null, "Priority: "), selectedTask.priority),
          h("div", null, h("strong", null, "Status: "), selectedTask.status),
          h("div", null, h("strong", null, "Duration: "), `${(selectedTask.duration_sec || 0).toFixed(2)}s`)
        ),
        h("div", { style: { marginBottom: "14px" } },
          h("strong", { style: { color: "var(--cyan-neon)", fontSize: "12px" } }, "Trace Execution Logs:"),
          h("div", { style: { background: "var(--bg-primary)", padding: "10px", borderRadius: "4px", maxHeight: "140px", overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: "12px", marginTop: "4px" } },
            (selectedTask.execution_log || []).map((step, idx) =>
              h("div", { key: idx, style: { color: "var(--text-muted)" } }, step)
            )
          )
        ),
        h("div", { style: { marginBottom: "14px" } },
          h("strong", { style: { color: "var(--cyan-neon)", fontSize: "12px" } }, "Output Result:"),
          h("pre", { style: { background: "var(--bg-primary)", padding: "10px", borderRadius: "4px", maxHeight: "150px", overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: "12px", margin: "4px 0 0" } },
            JSON.stringify(selectedTask.result || {}, null, 2)
          )
        ),
        h("div", { style: { textAlign: "right" } },
          h("button", { className: "btn btn-secondary", onClick: () => setSelectedTask(null) }, "Close")
        )
      )
    )
  );
}

// =========================================================================
// 14. ComplianceView (Regulatory Governance & Multi-Standard Auditing)
// =========================================================================
function ComplianceView({ currentUser }) {
  const [overview, setOverview] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFw, setSelectedFw] = useState("SOC2");
  const [controls, setControls] = useState([]);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [assessing, setAssessing] = useState(false);
  const [selectedControl, setSelectedControl] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchCompliance = async () => {
    try {
      setLoading(true);
      const [oRes, fRes] = await Promise.all([
        api.fetch("/api/compliance/overview"),
        api.fetch("/api/compliance/frameworks"),
      ]);
      if (oRes.ok) setOverview(await oRes.json());
      if (fRes.ok) {
        const fwList = await fRes.json();
        setFrameworks(fwList);
        if (fwList.length > 0 && !selectedFw) setSelectedFw(fwList[0].id);
      }
    } catch (e) {
      console.error("Failed to load compliance data:", e);
    } finally {
      setLoading(false);
    }
  };

  const fetchControls = async (fwId) => {
    if (!fwId) return;
    try {
      const res = await api.fetch(`/api/compliance/frameworks/${fwId}/controls`);
      if (res.ok) setControls(await res.json());
    } catch (e) {
      console.error("Failed to load controls:", e);
    }
  };

  useEffect(() => {
    fetchCompliance();
  }, []);

  useEffect(() => {
    if (selectedFw) fetchControls(selectedFw);
  }, [selectedFw]);

  const handleRunAssessment = async () => {
    try {
      setAssessing(true);
      const res = await api.fetch("/api/compliance/assess", { method: "POST" });
      if (res.ok) {
        await fetchCompliance();
        if (selectedFw) await fetchControls(selectedFw);
      }
    } catch (e) {
      console.error("Assessment run failed:", e);
    } finally {
      setAssessing(false);
    }
  };

  const filteredControls = controls.filter(c => {
    if (statusFilter !== "ALL" && c.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (c.control_code || "").toLowerCase().includes(q) ||
             (c.title || "").toLowerCase().includes(q) ||
             (c.domain || "").toLowerCase().includes(q);
    }
    return true;
  });

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
      h("div", null,
        h("h3", null, "🏛️ Regulatory Governance & Multi-Standard Compliance Engine"),
        h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" } },
          "Continuous telemetry auditing across SOC 2 Type II, ISO/IEC 27001:2022, NIST CSF 2.0, PCI-DSS v4.0, HIPAA, and GDPR"
        )
      ),
      h("button", {
        className: "btn btn-primary",
        onClick: handleRunAssessment,
        disabled: assessing,
      }, assessing ? "⚡ Assessing Platform..." : "⚡ Run Audit Assessment")
    ),

    // Executive Hero Scorecard
    overview && h("div", { style: { padding: "16px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-hover)" } },
      h("div", { style: { display: "grid", gridTemplateColumns: "180px 1fr 1fr 1fr", gap: "16px", alignItems: "center" } },
        h("div", { style: { textAlign: "center", borderRight: "1px solid var(--border-color)", paddingRight: "16px" } },
          h("div", { style: { fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" } }, "Global Posture Grade"),
          h("div", { style: { fontSize: "42px", fontWeight: "900", color: overview.global_compliance_score >= 80 ? "var(--green-neon)" : "var(--amber-neon)" } }, overview.letter_grade),
          h("div", { style: { fontSize: "13px", fontWeight: "700", color: "var(--cyan-neon)" } }, `${overview.global_compliance_score}% Compliant`)
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Controls Passed"),
          h("div", { className: "metric-value", style: { color: "var(--green-neon)" } }, overview.compliant_controls),
          h("div", { className: "metric-sub" }, `of ${overview.total_controls} evaluated controls`)
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Partial Compliance"),
          h("div", { className: "metric-value", style: { color: "var(--amber-neon)" } }, overview.partial_controls),
          h("div", { className: "metric-sub" }, "Minor configuration gaps")
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Non-Compliant Gaps"),
          h("div", { className: "metric-value", style: { color: "var(--red-neon)" } }, overview.non_compliant_controls),
          h("div", { className: "metric-sub" }, "Immediate remediation required")
        )
      )
    ),

    // Framework Selector Cards
    h("div", { style: { padding: "16px", borderBottom: "1px solid var(--border-color)" } },
      h("div", { style: { fontSize: "13px", fontWeight: "700", color: "var(--text-secondary)", marginBottom: "10px" } }, "Standards & Frameworks:"),
      h("div", { style: { display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: "10px" } },
        frameworks.map(fw =>
          h("div", {
            key: fw.id,
            onClick: () => setSelectedFw(fw.id),
            style: {
              background: selectedFw === fw.id ? "rgba(56, 189, 248, 0.15)" : "var(--bg-secondary)",
              border: `1px solid ${selectedFw === fw.id ? "var(--cyan-neon)" : "var(--border-color)"}`,
              borderRadius: "6px",
              padding: "12px",
              cursor: "pointer",
              transition: "all 0.2s ease",
            }
          },
            h("div", { style: { fontWeight: "700", fontSize: "13px", color: selectedFw === fw.id ? "var(--cyan-neon)" : "var(--text-primary)" } }, fw.name),
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", margin: "4px 0" } }, fw.version),
            h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "8px" } },
              h("span", { style: { fontSize: "12px", fontWeight: "800", color: fw.overall_score >= 80 ? "var(--green-neon)" : "var(--amber-neon)" } }, `${fw.overall_score}%`),
              h("span", { style: { fontSize: "10px", color: "var(--text-muted)" } }, `${fw.compliant_controls}/${fw.total_controls}`)
            )
          )
        )
      )
    ),

    // Controls Table Filter Strip
    h("div", { style: { padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)" } },
      h("div", { style: { display: "flex", gap: "8px", alignItems: "center" } },
        ["ALL", "COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"].map(status =>
          h("button", {
            key: status,
            className: `btn btn-sm ${statusFilter === status ? "btn-primary" : "btn-secondary"}`,
            onClick: () => setStatusFilter(status),
          }, status.replace("_", " "))
        )
      ),
      h("input", {
        type: "text",
        placeholder: "Search controls, domains, codes...",
        value: searchQuery,
        onChange: e => setSearchQuery(e.target.value),
        className: "input-field",
        style: { width: "260px", padding: "6px 10px", fontSize: "12px" },
      })
    ),

    // Controls Table
    h("div", { className: "table-container", style: { padding: "0 16px 16px" } },
      h("table", { className: "styled-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "Control Code"),
            h("th", null, "Requirement Title"),
            h("th", null, "Domain"),
            h("th", null, "Severity"),
            h("th", null, "Score"),
            h("th", null, "Audit Status"),
            h("th", null, "Action")
          )
        ),
        h("tbody", null,
          filteredControls.length === 0 ?
            h("tr", null, h("td", { colSpan: 7, style: { textAlign: "center", padding: "24px" } }, "No matching regulatory controls.")) :
            filteredControls.map(ctrl =>
              h("tr", { key: ctrl.id },
                h("td", null, h("strong", { style: { color: "var(--cyan-neon)", fontFamily: "var(--font-mono)" } }, ctrl.control_code)),
                h("td", { style: { maxWidth: "260px" } },
                  h("div", { style: { fontWeight: "600" } }, ctrl.title),
                  h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" } }, (ctrl.description || "").substring(0, 80) + "...")
                ),
                h("td", null, ctrl.domain),
                h("td", null,
                  h("span", {
                    className: `badge ${ctrl.severity === "CRITICAL" ? "badge-danger" : ctrl.severity === "HIGH" ? "badge-warning" : "badge-info"}`
                  }, ctrl.severity)
                ),
                h("td", null, `${ctrl.score}%`),
                h("td", null,
                  h("span", {
                    className: `badge ${ctrl.status === "COMPLIANT" ? "badge-success" : ctrl.status === "PARTIALLY_COMPLIANT" ? "badge-warning" : "badge-danger"}`
                  }, ctrl.status.replace("_", " "))
                ),
                h("td", null,
                  h("button", {
                    className: "btn btn-secondary btn-sm",
                    onClick: () => setSelectedControl(ctrl),
                  }, "Evidence")
                )
              )
            )
        )
      )
    ),

    // Control Technical Evidence Modal
    selectedControl && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "680px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `Audit Evidence: ${selectedControl.control_code} - ${selectedControl.title}`),
          h("button", { className: "modal-close", onClick: () => setSelectedControl(null) }, "✕")
        ),
        h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "14px" } },
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" } }, "Compliance Mandate"),
            h("div", { style: { fontSize: "13px", marginTop: "4px", lineHeight: "1.5" } }, selectedControl.description)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" } }, "Technical Evidence Summary"),
            h("div", { style: { fontSize: "13px", color: "var(--green-neon)", marginTop: "4px" } }, selectedControl.evidence_summary || "Automated baseline check recorded.")
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" } }, "Observed Platform Telemetry"),
            h("pre", { style: { background: "var(--bg-primary)", padding: "10px", borderRadius: "4px", fontSize: "12px", fontFamily: "var(--font-mono)", maxHeight: "140px", overflowY: "auto", margin: "4px 0 0" } },
              JSON.stringify(selectedControl.evidence_json || {}, null, 2)
            )
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" } }, "Remediation Guidance"),
            h("div", { style: { fontSize: "12px", color: "var(--amber-neon)", marginTop: "4px" } }, selectedControl.remediation_guidance)
          ),
          h("div", { style: { textAlign: "right", marginTop: "10px" } },
            h("button", { className: "btn btn-secondary", onClick: () => setSelectedControl(null) }, "Close")
          )
        )
      )
    )
  );
}

// =========================================================================
// 15. AuditVaultView (Cryptographic WORM Ledger & Integrity Verification)
// =========================================================================
function AuditVaultView({ currentUser }) {
  const [blocks, setBlocks] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verifying, setVerifying] = useState(false);
  const [verification, setVerification] = useState(null);
  const [certificate, setCertificate] = useState(null);
  const [certModalOpen, setCertModalOpen] = useState(false);
  const [selectedBlock, setSelectedBlock] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchBlocks = async (pg = 1) => {
    try {
      setLoading(true);
      const res = await api.fetch(`/api/audit/vault/blocks?page=${pg}&page_size=25`);
      if (res.ok) {
        const data = await res.json();
        setBlocks(data.items || []);
        setTotal(data.total || 0);
        setPage(pg);
      }
    } catch (e) {
      console.error("Failed to load vault blocks:", e);
    } finally {
      setLoading(false);
    }
  };

  const runVerification = async () => {
    try {
      setVerifying(true);
      const res = await api.fetch("/api/audit/vault/verify", { method: "POST" });
      if (res.ok) setVerification(await res.json());
    } catch (e) {
      console.error("Verification failed:", e);
    } finally {
      setVerifying(false);
    }
  };

  const exportCertificate = async () => {
    try {
      const res = await api.fetch("/api/audit/vault/certificate");
      if (res.ok) {
        setCertificate(await res.json());
        setCertModalOpen(true);
      }
    } catch (e) {
      console.error("Certificate export failed:", e);
    }
  };

  useEffect(() => {
    fetchBlocks(1);
    runVerification();
  }, []);

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
      h("div", null,
        h("h3", null, "🔐 Cryptographic Audit Vault (WORM Tamper-Evident Ledger)"),
        h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" } },
          "Immutable SHA-256 Merkle hash chaining & HMAC cryptographic block signing for forensic non-repudiation"
        )
      ),
      h("div", { style: { display: "flex", gap: "8px" } },
        h("button", {
          className: "btn btn-secondary btn-sm",
          onClick: exportCertificate,
        }, "📄 Export Certificate"),
        h("button", {
          className: "btn btn-primary btn-sm",
          onClick: runVerification,
          disabled: verifying,
        }, verifying ? "🛡️ Verifying Chains..." : "🛡️ Verify Ledger Integrity")
      )
    ),

    // Cryptographic Seal Status Banner
    h("div", { style: { padding: "16px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-hover)" } },
      verification ? h("div", { style: { display: "grid", gridTemplateColumns: "1.5fr 1fr 1fr 1fr", gap: "16px", alignItems: "center" } },
        h("div", { style: { borderRight: "1px solid var(--border-color)", paddingRight: "16px" } },
          h("div", { style: { display: "flex", alignItems: "center", gap: "8px" } },
            h("span", { style: { width: "12px", height: "12px", borderRadius: "50%", background: verification.is_valid ? "var(--green-neon)" : "var(--red-neon)" } }),
            h("span", { style: { fontWeight: "800", color: verification.is_valid ? "var(--green-neon)" : "var(--red-neon)" } },
              verification.is_valid ? "CHAIN INTEGRITY VERIFIED" : "LEDGER TAMPERING DETECTED"
            )
          ),
          h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" } },
            verification.is_valid ? "All SHA-256 links & HMAC block seals 100% authentic." : `Discontinuity at block #${verification.tampered_block_index}: ${verification.error_message}`
          )
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Total Block Height"),
          h("div", { className: "metric-value", style: { color: "var(--cyan-neon)" } }, verification.total_blocks),
          h("div", { className: "metric-sub" }, "Sequential blocks")
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Genesis Root Hash"),
          h("div", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-secondary)", marginTop: "8px" } },
            (verification.genesis_hash || "").substring(0, 16) + "..."
          ),
          h("div", { className: "metric-sub" }, "Block #0 root")
        ),
        h("div", { className: "metric-card" },
          h("div", { className: "metric-label" }, "Digital Seal (HMAC)"),
          h("div", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--green-neon)", marginTop: "8px" } },
            (verification.verification_seal || "").substring(0, 16) + "..."
          ),
          h("div", { className: "metric-sub" }, "Tamper-proof seal")
        )
      ) : h("div", null, "Validating ledger hashes...")
    ),

    // Ledger Blocks Table
    h("div", { className: "table-container", style: { padding: "0 16px 16px" } },
      h("table", { className: "styled-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "Block #"),
            h("th", null, "Timestamp"),
            h("th", null, "Action"),
            h("th", null, "Actor / Role"),
            h("th", null, "Entity"),
            h("th", null, "Block Hash (SHA-256)"),
            h("th", null, "Parent Link"),
            h("th", null, "Seal"),
            h("th", null, "Action")
          )
        ),
        h("tbody", null,
          blocks.map(b =>
            h("tr", { key: b.id },
              h("td", null, h("strong", { style: { color: "var(--cyan-neon)", fontFamily: "var(--font-mono)" } }, `#${b.block_index}`)),
              h("td", { style: { fontSize: "11px", color: "var(--text-muted)" } }, (b.timestamp || "").replace("T", " ").substring(0, 19)),
              h("td", null, h("span", { className: "badge badge-info" }, b.action)),
              h("td", null,
                h("div", { style: { fontWeight: "600" } }, b.actor_id),
                h("div", { style: { fontSize: "10px", color: "var(--text-muted)" } }, b.actor_role)
              ),
              h("td", null, `${b.entity_type}:${b.entity_id}`),
              h("td", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-secondary)" } },
                b.block_hash.substring(0, 12) + "..."
              ),
              h("td", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)" } },
                b.previous_block_hash.substring(0, 10) + "..."
              ),
              h("td", null,
                h("span", { className: "badge badge-success", style: { fontSize: "10px" } }, "✓ SEALED")
              ),
              h("td", null,
                h("button", {
                  className: "btn btn-secondary btn-sm",
                  onClick: () => setSelectedBlock(b),
                }, "Inspect")
              )
            )
          )
        )
      )
    ),

    // Block Inspector Drawer Modal
    selectedBlock && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "680px" } },
        h("div", { className: "modal-header" },
          h("h3", null, `WORM Block #${selectedBlock.block_index} Inspector`),
          h("button", { className: "modal-close", onClick: () => setSelectedBlock(null) }, "✕")
        ),
        h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "12px" } },
          h("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", fontSize: "12px" } },
            h("div", null, h("strong", null, "Action: "), selectedBlock.action),
            h("div", null, h("strong", null, "Actor: "), `${selectedBlock.actor_id} (${selectedBlock.actor_role})`),
            h("div", null, h("strong", null, "Entity: "), `${selectedBlock.entity_type}:${selectedBlock.entity_id}`),
            h("div", null, h("strong", null, "Timestamp: "), selectedBlock.timestamp)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "SHA-256 BLOCK HASH"),
            h("div", { style: { background: "var(--bg-primary)", padding: "6px 10px", borderRadius: "4px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--cyan-neon)", wordBreak: "break-all" } }, selectedBlock.block_hash)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "PARENT BLOCK HASH LINK"),
            h("div", { style: { background: "var(--bg-primary)", padding: "6px 10px", borderRadius: "4px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)", wordBreak: "break-all" } }, selectedBlock.previous_block_hash)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "HMAC-SHA256 SIGNATURE SEAL"),
            h("div", { style: { background: "var(--bg-primary)", padding: "6px 10px", borderRadius: "4px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--green-neon)", wordBreak: "break-all" } }, selectedBlock.hmac_signature)
          ),
          h("div", null,
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)" } }, "CANONICAL PAYLOAD DATA"),
            h("pre", { style: { background: "var(--bg-primary)", padding: "10px", borderRadius: "4px", fontSize: "11px", fontFamily: "var(--font-mono)", maxHeight: "140px", overflowY: "auto", margin: "4px 0 0" } },
              JSON.stringify(selectedBlock.payload_data || {}, null, 2)
            )
          ),
          h("div", { style: { textAlign: "right" } },
            h("button", { className: "btn btn-secondary", onClick: () => setSelectedBlock(null) }, "Close")
          )
        )
      )
    ),

    // Certificate of Authenticity Modal
    certModalOpen && certificate && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "600px", border: "2px solid var(--green-neon)" } },
        h("div", { className: "modal-header" },
          h("h3", null, "📜 Cryptographic Certificate of Authenticity"),
          h("button", { className: "modal-close", onClick: () => setCertModalOpen(false) }, "✕")
        ),
        h("div", { style: { padding: "20px", textAlign: "center" } },
          h("div", { style: { fontSize: "42px", marginBottom: "8px" } }, "🛡️"),
          h("div", { style: { fontSize: "16px", fontWeight: "800", color: "var(--green-neon)" } }, certificate.status),
          h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" } }, `Certificate ID: ${certificate.certificate_id}`),
          h("div", { style: { background: "var(--bg-primary)", padding: "16px", borderRadius: "8px", marginTop: "16px", textAlign: "left", fontSize: "12px" } },
            h("div", { style: { marginBottom: "8px" } }, h("strong", null, "Issuer: "), certificate.issuer),
            h("div", { style: { marginBottom: "8px" } }, h("strong", null, "Issued At: "), certificate.issued_at),
            h("div", { style: { marginBottom: "8px" } }, h("strong", null, "Blocks Verified: "), certificate.verification_details?.total_blocks),
            h("div", { style: { marginBottom: "8px" } }, h("strong", null, "Chain Integrity: "), "100% Mathematically Continuous"),
            h("div", null, h("strong", null, "Cryptographic Seal: "),
              h("div", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--green-neon)", wordBreak: "break-all", marginTop: "4px" } }, certificate.digital_seal)
            )
          ),
          h("div", { style: { marginTop: "20px" } },
            h("button", { className: "btn btn-primary", onClick: () => setCertModalOpen(false) }, "Accept & Close")
          )
        )
      )
    )
  );
}

// =========================================================================
// 16. ReportsView (Automated Executive & Forensic Report Generator)
// =========================================================================
function ReportsView({ currentUser }) {
  const [reports, setReports] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState("EXECUTIVE_POSTURE");
  const [format, setFormat] = useState("HTML");
  const [customTitle, setCustomTitle] = useState("");
  const [viewingReport, setViewingReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchReports = async (pg = 1) => {
    try {
      setLoading(true);
      const res = await api.fetch(`/api/reports?page=${pg}&page_size=20`);
      if (res.ok) {
        const data = await res.json();
        setReports(data.items || []);
        setTotal(data.total || 0);
        setPage(pg);
      }
    } catch (e) {
      console.error("Failed to fetch reports:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async () => {
    try {
      setGenerating(true);
      const res = await api.fetch("/api/reports/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_type: reportType,
          format: format,
          title: customTitle || undefined,
        }),
      });
      if (res.ok) {
        const newReport = await res.json();
        setViewingReport(newReport);
        await fetchReports(1);
      }
    } catch (e) {
      console.error("Report generation failed:", e);
    } finally {
      setGenerating(false);
    }
  };

  const viewReportDetail = async (id) => {
    try {
      const res = await api.fetch(`/api/reports/${id}`);
      if (res.ok) setViewingReport(await res.json());
    } catch (e) {
      console.error("Failed to load report detail:", e);
    }
  };

  useEffect(() => {
    fetchReports(1);
  }, []);

  const templates = [
    {
      id: "EXECUTIVE_POSTURE",
      title: "Executive Posture Summary",
      icon: "📊",
      desc: "High-level board readout: SPI score, asset hygiene, incident metrics, and cross-framework compliance grades.",
    },
    {
      id: "COMPLIANCE_ATTESTATION",
      title: "Regulatory Attestation",
      icon: "🏛️",
      desc: "Formal audit attestation covering SOC 2, ISO 27001, NIST, PCI-DSS, HIPAA, and GDPR controls with technical evidence.",
    },
    {
      id: "VULNERABILITY_ASSESSMENT",
      title: "Vulnerability Exposure",
      icon: "🔓",
      desc: "Comprehensive CVSS attack surface analysis, high/critical CVEs, affected software, and remediation SLAs.",
    },
    {
      id: "INCIDENT_DOSSIER",
      title: "Incident Forensics Dossier",
      icon: "🚨",
      desc: "Technical post-mortem detailing incident timelines, MITRE ATT&CK kill chains, and forensic evidence custody.",
    },
  ];

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" },
      h("h3", null, "📑 Automated Enterprise Report Generator"),
      h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" } },
        "Compile live telemetry into publication-grade HTML, JSON, and CSV executive summaries and audit attestations"
      )
    ),

    // Report Generation Studio Strip
    h("div", { style: { padding: "16px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-hover)" } },
      h("div", { style: { fontSize: "13px", fontWeight: "700", color: "var(--text-secondary)", marginBottom: "12px" } }, "Select Report Template:"),
      h("div", { style: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" } },
        templates.map(tpl =>
          h("div", {
            key: tpl.id,
            onClick: () => setReportType(tpl.id),
            style: {
              background: reportType === tpl.id ? "rgba(56, 189, 248, 0.15)" : "var(--bg-secondary)",
              border: `1px solid ${reportType === tpl.id ? "var(--cyan-neon)" : "var(--border-color)"}`,
              borderRadius: "8px",
              padding: "14px",
              cursor: "pointer",
              transition: "all 0.2s ease",
            }
          },
            h("div", { style: { fontSize: "24px", marginBottom: "6px" } }, tpl.icon),
            h("div", { style: { fontWeight: "700", fontSize: "13px", color: reportType === tpl.id ? "var(--cyan-neon)" : "var(--text-primary)" } }, tpl.title),
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginTop: "4px", lineHeight: "1.4" } }, tpl.desc)
          )
        )
      ),
      h("div", { style: { display: "flex", gap: "12px", alignItems: "center" } },
        h("input", {
          type: "text",
          placeholder: "Custom Report Title (Optional)...",
          value: customTitle,
          onChange: e => setCustomTitle(e.target.value),
          className: "input-field",
          style: { flex: 1, padding: "8px 12px" },
        }),
        h("select", {
          value: format,
          onChange: e => setFormat(e.target.value),
          className: "input-field",
          style: { width: "120px", padding: "8px" },
        },
          h("option", { value: "HTML" }, "HTML5"),
          h("option", { value: "JSON" }, "JSON Data"),
          h("option", { value: "CSV" }, "CSV Table")
        ),
        h("button", {
          className: "btn btn-primary",
          onClick: handleGenerate,
          disabled: generating,
        }, generating ? "⚡ Generating..." : "⚡ Generate Report Now")
      )
    ),

    // Generated Reports Archive Table
    h("div", { className: "table-container", style: { padding: "16px" } },
      h("div", { style: { fontSize: "13px", fontWeight: "700", marginBottom: "10px", color: "var(--text-secondary)" } }, "Archived Generated Reports:"),
      h("table", { className: "styled-table" },
        h("thead", null,
          h("tr", null,
            h("th", null, "Report ID"),
            h("th", null, "Title"),
            h("th", null, "Category"),
            h("th", null, "Format"),
            h("th", null, "Generated By"),
            h("th", null, "Created At"),
            h("th", null, "Actions")
          )
        ),
        h("tbody", null,
          reports.length === 0 ?
            h("tr", null, h("td", { colSpan: 7, style: { textAlign: "center", padding: "20px" } }, "No reports generated yet.")) :
            reports.map(r =>
              h("tr", { key: r.id },
                h("td", null, h("strong", { style: { color: "var(--cyan-neon)", fontFamily: "var(--font-mono)" } }, r.id)),
                h("td", { style: { fontWeight: "600" } }, r.title),
                h("td", null, h("span", { className: "badge badge-info" }, r.report_type)),
                h("td", null, r.format),
                h("td", null, r.generated_by),
                h("td", { style: { fontSize: "11px", color: "var(--text-muted)" } }, (r.created_at || "").replace("T", " ").substring(0, 19)),
                h("td", null,
                  h("div", { style: { display: "flex", gap: "6px" } },
                    h("button", {
                      className: "btn btn-secondary btn-sm",
                      onClick: () => viewReportDetail(r.id),
                    }, "👁️ View"),
                    h("a", {
                      href: `/api/reports/${r.id}/download`,
                      className: "btn btn-secondary btn-sm",
                      target: "_blank",
                    }, "⬇️ Download")
                  )
                )
              )
            )
        )
      )
    ),

    // Live Report Viewer Modal
    viewingReport && h("div", { className: "modal-backdrop" },
      h("div", { className: "modal-card", style: { maxWidth: "900px", height: "85vh", display: "flex", flexDirection: "column" } },
        h("div", { className: "modal-header" },
          h("h3", null, viewingReport.title),
          h("div", { style: { display: "flex", gap: "8px", alignItems: "center" } },
            h("a", {
              href: `/api/reports/${viewingReport.id}/download`,
              className: "btn btn-primary btn-sm",
            }, "⬇️ Download File"),
            h("button", { className: "modal-close", onClick: () => setViewingReport(null) }, "✕")
          )
        ),
        h("div", { style: { flex: 1, padding: "16px", overflowY: "auto", background: "var(--bg-secondary)" } },
          viewingReport.content_html ?
            h("iframe", {
              srcDoc: viewingReport.content_html,
              style: { width: "100%", height: "100%", border: "none", borderRadius: "6px", background: "var(--bg-secondary)" },
            }) :
            h("pre", { style: { color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: "12px" } },
              JSON.stringify(viewingReport.raw_data || {}, null, 2)
            )
        )
      )
    )
  );
}

// =========================================================================
// 17. SystemSettingsView (Centralized Platform Configuration Manager)
// =========================================================================
function SystemSettingsView({ currentUser }) {
  const [settings, setSettings] = useState([]);
  const [category, setCategory] = useState("ALL");
  const [editValues, setEditValues] = useState({});
  const [savingKey, setSavingKey] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSettings = async () => {
    try {
      setLoading(true);
      const res = await api.fetch("/api/settings");
      if (res.ok) {
        const data = await res.json();
        setSettings(data);
        const vals = {};
        data.forEach(s => { vals[s.key] = s.raw_value; });
        setEditValues(vals);
      }
    } catch (e) {
      console.error("Failed to load settings:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSave = async (key) => {
    try {
      setSavingKey(key);
      setFeedback(null);
      const res = await api.fetch(`/api/settings/${key}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: String(editValues[key]) }),
      });
      if (res.ok) {
        setFeedback({ type: "success", msg: `Setting '${key}' saved and recorded in WORM ledger.` });
        await fetchSettings();
      } else {
        const err = await res.json();
        setFeedback({ type: "error", msg: err.detail || "Failed to update setting." });
      }
    } catch (e) {
      setFeedback({ type: "error", msg: "Network error saving setting." });
    } finally {
      setSavingKey(null);
    }
  };

  const handleReset = async (key) => {
    try {
      setSavingKey(key);
      setFeedback(null);
      const res = await api.fetch(`/api/settings/${key}/reset`, { method: "POST" });
      if (res.ok) {
        setFeedback({ type: "success", msg: `Setting '${key}' reset to factory default.` });
        await fetchSettings();
      } else {
        setFeedback({ type: "error", msg: "Failed to reset setting." });
      }
    } catch (e) {
      setFeedback({ type: "error", msg: "Network error resetting setting." });
    } finally {
      setSavingKey(null);
    }
  };

  const categories = [
    { id: "ALL", label: "All Settings" },
    { id: "SECURITY_POLICY", label: "Security Policy" },
    { id: "DETECTION_SOAR", label: "Threat Detection & SOAR" },
    { id: "RETENTION_STORAGE", label: "Retention & Storage" },
    { id: "ML_ANALYTICS", label: "AI / ML & Analytics" },
  ];

  const filtered = settings.filter(s => category === "ALL" || s.category === category);

  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" },
      h("h3", null, "⚙️ Centralized Platform Configuration & Runtime Settings"),
      h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" } },
        "Manage security policies, autonomous SOAR thresholds, retention windows, and AI/ML model parameters"
      )
    ),

    // Feedback Alert Banner
    feedback && h("div", {
      style: {
        padding: "10px 16px",
        background: feedback.type === "success" ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
        borderBottom: `1px solid ${feedback.type === "success" ? "var(--green-neon)" : "var(--red-neon)"}`,
        color: feedback.type === "success" ? "var(--green-neon)" : "var(--red-neon)",
        fontSize: "13px",
        fontWeight: "600",
      }
    }, feedback.msg),

    // Category Tabs
    h("div", { style: { padding: "12px 16px", display: "flex", gap: "8px", borderBottom: "1px solid var(--border-color)", background: "var(--bg-secondary)" } },
      categories.map(c =>
        h("button", {
          key: c.id,
          className: `btn btn-sm ${category === c.id ? "btn-primary" : "btn-secondary"}`,
          onClick: () => setCategory(c.id),
        }, c.label)
      )
    ),

    // Settings Grid
    h("div", { style: { padding: "16px", display: "flex", flexDirection: "column", gap: "12px" } },
      filtered.map(s =>
        h("div", {
          key: s.key,
          style: {
            background: "var(--bg-secondary)",
            border: "1px solid var(--border-color)",
            borderRadius: "8px",
            padding: "16px",
            display: "grid",
            gridTemplateColumns: "1.5fr 1fr 140px",
            gap: "16px",
            alignItems: "center",
          }
        },
          h("div", null,
            h("div", { style: { display: "flex", alignItems: "center", gap: "8px" } },
              h("span", { style: { fontWeight: "700", fontSize: "14px" } }, s.display_name),
              s.requires_restart && h("span", { className: "badge badge-warning", style: { fontSize: "10px" } }, "Requires Restart")
            ),
            h("div", { style: { fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--cyan-neon)", marginTop: "2px" } }, s.key),
            h("div", { style: { fontSize: "12px", color: "var(--text-muted)", marginTop: "4px" } }, s.description)
          ),
          h("div", null,
            s.value_type === "BOOLEAN" ?
              h("select", {
                value: editValues[s.key] !== undefined ? String(editValues[s.key]) : String(s.raw_value),
                onChange: e => setEditValues(prev => ({ ...prev, [s.key]: e.target.value })),
                className: "input-field",
                style: { width: "100%" },
              },
                h("option", { value: "true" }, "Enabled (true)"),
                h("option", { value: "false" }, "Disabled (false)")
              ) :
              h("input", {
                type: s.value_type === "INTEGER" || s.value_type === "FLOAT" ? "number" : "text",
                value: editValues[s.key] !== undefined ? editValues[s.key] : s.raw_value,
                onChange: e => setEditValues(prev => ({ ...prev, [s.key]: e.target.value })),
                className: "input-field",
                style: { width: "100%" },
              }),
            h("div", { style: { fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" } },
              `Default: ${s.default_value} | Updated by: ${s.updated_by}`
            )
          ),
          h("div", { style: { display: "flex", flexDirection: "column", gap: "6px" } },
            h("button", {
              className: "btn btn-primary btn-sm",
              onClick: () => handleSave(s.key),
              disabled: savingKey === s.key,
            }, savingKey === s.key ? "Saving..." : "💾 Save"),
            h("button", {
              className: "btn btn-secondary btn-sm",
              onClick: () => handleReset(s.key),
              disabled: savingKey === s.key,
            }, "↺ Reset Default")
          )
        )
      )
    )
  );
}

// System Health & Diagnostics View
function SystemHealthView({ currentUser }) {
  const [diag, setDiag] = useState(null);
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [creatingBackup, setCreatingBackup] = useState(false);
  const [backupNote, setBackupNote] = useState("Automated SOC Glass Cockpit Snapshot");

  const loadHealthData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [diagRes, bkRes] = await Promise.all([
        api.fetch("/api/health/diagnostics"),
        api.fetch("/api/health/backups"),
      ]);
      if (diagRes.ok) {
        const diagData = await diagRes.json();
        setDiag(diagData);
      } else {
        setError(`Failed to retrieve diagnostics: HTTP ${diagRes.status}`);
      }
      if (bkRes.ok) {
        const bkData = await bkRes.json();
        setBackups(bkData.backups || []);
      }
    } catch (e) {
      setError(`Network error fetching health telemetry: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHealthData();
    const interval = setInterval(loadHealthData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleCreateBackup = async () => {
    setCreatingBackup(true);
    try {
      const res = await api.fetch("/api/health/backups/create", {
        method: "POST",
        body: JSON.stringify({ note: backupNote }),
      });
      if (res.ok) {
        setVerifyResult({ type: "success", message: "Database point-in-time snapshot created and sealed in WORM ledger." });
        loadHealthData();
      } else {
        setVerifyResult({ type: "error", message: `Failed to create backup: HTTP ${res.status}` });
      }
    } catch (e) {
      setVerifyResult({ type: "error", message: `Error creating backup: ${e.message}` });
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleVerifyBackup = async (filename) => {
    try {
      const res = await api.fetch(`/api/health/backups/${filename}/verify`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setVerifyResult({
          type: data.verified ? "success" : "error",
          message: data.message,
          checksum: data.calculated_sha256,
        });
      } else {
        setVerifyResult({ type: "error", message: `Verification failed: HTTP ${res.status}` });
      }
    } catch (e) {
      setVerifyResult({ type: "error", message: `Network error verifying backup: ${e.message}` });
    }
  };

  const getStatusColor = (st) => {
    if (st === "HEALTHY") return "var(--green-neon, #00ffaa)";
    if (st === "DEGRADED") return "var(--amber-neon, #ffaa00)";
    return "var(--red-neon, #ff0055)";
  };

  if (loading && !diag) {
    return h("div", { className: "panel-box", style: { padding: "40px", textAlign: "center" } },
      h("div", { style: { fontSize: "36px", marginBottom: "16px" } }, "🩺"),
      h("h3", null, "Sampling System Diagnostics..."),
      h("p", { style: { color: "var(--text-secondary)" } }, "Benchmarking host resources, database pool, and subsystem health.")
    );
  }

  return h("div", { className: "health-container", style: { display: "flex", flexDirection: "column", gap: "20px" } },
    // Header Bar
    h("div", { className: "panel-box", style: { padding: "20px 24px", display: "flex", justifyContent: "space-between", alignItems: "center" } },
      h("div", { style: { display: "flex", alignItems: "center", gap: "16px" } },
        h("div", { style: { fontSize: "38px" } }, "🩺"),
        h("div", null,
          h("h2", { style: { margin: 0, fontSize: "22px", fontWeight: "800", letterSpacing: "0.5px" } }, "System Health & Operational Diagnostics"),
          h("div", { style: { fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" } },
            `Platform Version ${diag?.version || "1.0.0"} • Uptime: ${diag ? Math.floor(diag.uptime_seconds / 60) : 0} minutes (${diag?.uptime_seconds || 0}s) • Environment: ${diag?.environment || "production"}`
          )
        )
      ),
      h("div", { style: { display: "flex", alignItems: "center", gap: "12px" } },
        h("div", {
          style: {
            padding: "6px 14px",
            borderRadius: "6px",
            fontSize: "13px",
            fontWeight: "800",
            letterSpacing: "1px",
            background: "var(--bg-hover)",
            border: `1px solid ${getStatusColor(diag?.status)}`,
            color: getStatusColor(diag?.status),
            boxShadow: `0 0 10px ${getStatusColor(diag?.status)}33`,
          }
        }, `STATUS: ${diag?.status || "UNKNOWN"}`),
        h("button", { className: "btn btn-secondary", onClick: loadHealthData, disabled: loading }, loading ? "Refreshing..." : "🔄 Refresh Telemetry")
      )
    ),

    error && h("div", { className: "alert alert-danger", style: { padding: "12px 20px" } }, error),

    verifyResult && h("div", {
      className: `alert ${verifyResult.type === "success" ? "alert-success" : "alert-danger"}`,
      style: { padding: "12px 20px", display: "flex", justifyContent: "space-between", alignItems: "center" }
    },
      h("div", null,
        h("strong", null, verifyResult.type === "success" ? "✅ Integrity Validated: " : "⚠️ Integrity Alert: "),
        verifyResult.message,
        verifyResult.checksum && h("div", { style: { fontSize: "11px", fontFamily: "monospace", marginTop: "4px" } }, `SHA-256: ${verifyResult.checksum}`)
      ),
      h("button", { className: "btn btn-sm btn-secondary", onClick: () => setVerifyResult(null) }, "✕")
    ),

    // Hardware Telemetry KPI Cards
    diag?.hardware && h("div", { className: "kpi-grid", style: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" } },
      // Memory
      h("div", { className: "panel-box kpi-card", style: { padding: "18px" } },
        h("div", { className: "kpi-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
          h("span", { style: { fontSize: "12px", textTransform: "uppercase", color: "var(--text-secondary)" } }, "Host Memory (RAM)"),
          h("span", { style: { fontSize: "18px" } }, "🧠")
        ),
        h("div", { className: "kpi-value", style: { fontSize: "24px", fontWeight: "800", marginTop: "8px" } },
          `${diag.hardware.memory_used_mb.toFixed(0)} MB`
        ),
        h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" } },
          `of ${diag.hardware.memory_total_mb.toFixed(0)} MB total (${diag.hardware.memory_percent}%)`
        ),
        h("div", { style: { width: "100%", background: "var(--bg-hover)", height: "6px", borderRadius: "3px", marginTop: "10px", overflow: "hidden" } },
          h("div", {
            style: {
              width: `${Math.min(100, diag.hardware.memory_percent)}%`,
              height: "100%",
              background: diag.hardware.memory_percent > 85 ? "var(--red-neon)" : "var(--cyan-neon)",
              transition: "width 0.3s ease"
            }
          })
        )
      ),

      // Storage / Disk
      h("div", { className: "panel-box kpi-card", style: { padding: "18px" } },
        h("div", { className: "kpi-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
          h("span", { style: { fontSize: "12px", textTransform: "uppercase", color: "var(--text-secondary)" } }, "Storage Space"),
          h("span", { style: { fontSize: "18px" } }, "💾")
        ),
        h("div", { className: "kpi-value", style: { fontSize: "24px", fontWeight: "800", marginTop: "8px" } },
          `${diag.hardware.disk_used_gb.toFixed(1)} GB`
        ),
        h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" } },
          `of ${diag.hardware.disk_total_gb.toFixed(1)} GB (${diag.hardware.disk_percent}%) • ${diag.hardware.disk_free_gb.toFixed(1)} GB Free`
        ),
        h("div", { style: { width: "100%", background: "var(--bg-hover)", height: "6px", borderRadius: "3px", marginTop: "10px", overflow: "hidden" } },
          h("div", {
            style: {
              width: `${Math.min(100, diag.hardware.disk_percent)}%`,
              height: "100%",
              background: diag.hardware.disk_percent > 85 ? "var(--red-neon)" : "var(--green-neon)",
              transition: "width 0.3s ease"
            }
          })
        )
      ),

      // Compute & Runtime
      h("div", { className: "panel-box kpi-card", style: { padding: "18px" } },
        h("div", { className: "kpi-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
          h("span", { style: { fontSize: "12px", textTransform: "uppercase", color: "var(--text-secondary)" } }, "Host Compute & OS"),
          h("span", { style: { fontSize: "18px" } }, "⚡")
        ),
        h("div", { className: "kpi-value", style: { fontSize: "24px", fontWeight: "800", marginTop: "8px" } },
          `${diag.hardware.cpu_percent}% CPU`
        ),
        h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" } },
          `PID: ${diag.hardware.process_pid} • Python ${diag.hardware.python_version}`
        ),
        h("div", { style: { fontSize: "11px", color: "var(--cyan-neon)", marginTop: "8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" } },
          diag.hardware.platform
        )
      ),

      // Database Pool
      h("div", { className: "panel-box kpi-card", style: { padding: "18px" } },
        h("div", { className: "kpi-header", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
          h("span", { style: { fontSize: "12px", textTransform: "uppercase", color: "var(--text-secondary)" } }, "Database Core"),
          h("span", { style: { fontSize: "18px" } }, "🗄️")
        ),
        h("div", { className: "kpi-value", style: { fontSize: "24px", fontWeight: "800", marginTop: "8px", color: "var(--green-neon)" } },
          `${diag.database.latency_ms} ms`
        ),
        h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" } },
          `Engine: ${diag.database.engine_dialect.toUpperCase()} • ${diag.database.tables_count} Tables`
        ),
        h("div", { style: { fontSize: "11px", color: "var(--text-secondary)", marginTop: "8px" } },
          `Total Records Indexed: ${diag.database.total_records_count.toLocaleString()}`
        )
      )
    ),

    // Subsystem Health Matrix
    diag?.subsystems && h("div", { className: "panel-box", style: { padding: "24px" } },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "18px" } },
        h("h3", { style: { margin: 0, fontSize: "18px", fontWeight: "700" } }, "Platform Subsystem Operational Matrix"),
        h("span", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, "Continuous Autonomous Health Probing")
      ),
      h("div", { style: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "14px" } },
        Object.entries(diag.subsystems).map(([key, sub]) =>
          h("div", {
            key,
            style: {
              background: "var(--bg-hover)",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: "8px",
              padding: "16px",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }
          },
            h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center" } },
              h("span", { style: { fontWeight: "700", fontSize: "14px", textTransform: "capitalize" } }, key.replace(/_/g, " ")),
              h("span", {
                style: {
                  fontSize: "11px",
                  fontWeight: "700",
                  padding: "2px 8px",
                  borderRadius: "4px",
                  background: sub.status === "HEALTHY" ? "rgba(0,255,170,0.15)" : "rgba(255,0,85,0.15)",
                  color: getStatusColor(sub.status),
                  border: `1px solid ${getStatusColor(sub.status)}44`,
                }
              }, sub.status)
            ),
            h("div", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, sub.message),
            h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" } },
              h("span", null, `Latency: ${sub.latency_ms} ms`),
              sub.details && Object.keys(sub.details).length > 0 &&
                h("span", { style: { fontFamily: "monospace", color: "var(--cyan-neon)" } },
                  Object.entries(sub.details).slice(0, 2).map(([k, v]) => `${k}:${Array.isArray(v) ? v.length : v}`).join(" | ")
                )
            )
          )
        )
      )
    ),

    // Disaster Recovery & Point-in-Time Backups Panel
    h("div", { className: "panel-box", style: { padding: "24px" } },
      h("div", { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "18px" } },
        h("div", null,
          h("h3", { style: { margin: 0, fontSize: "18px", fontWeight: "700" } }, "Disaster Recovery & Database Snapshots"),
          h("div", { style: { fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" } },
            "Cryptographically sealed point-in-time database backups with SHA-256 tamper verification."
          )
        ),
        h("div", { style: { display: "flex", gap: "10px", alignItems: "center" } },
          h("input", {
            type: "text",
            className: "form-control",
            placeholder: "Snapshot note / reason...",
            value: backupNote,
            onChange: (e) => setBackupNote(e.target.value),
            style: { width: "240px", fontSize: "12px" }
          }),
          h("button", {
            className: "btn btn-primary",
            onClick: handleCreateBackup,
            disabled: creatingBackup,
          }, creatingBackup ? "Creating..." : "⚡ Create Backup Snapshot")
        )
      ),

      backups.length === 0 ?
        h("div", { style: { padding: "30px", textAlign: "center", color: "var(--text-secondary)" } },
          h("div", { style: { fontSize: "28px", marginBottom: "8px" } }, "📦"),
          h("p", null, "No database snapshots generated yet. Click 'Create Backup Snapshot' to generate a verified point-in-time archive.")
        ) :
        h("div", { className: "table-responsive" },
          h("table", { className: "table" },
            h("thead", null,
              h("tr", null,
                h("th", null, "Created At"),
                h("th", null, "Archive Filename"),
                h("th", null, "Size"),
                h("th", null, "SHA-256 Digest"),
                h("th", null, "Annotation"),
                h("th", { style: { textAlign: "right" } }, "Actions")
              )
            ),
            h("tbody", null,
              backups.map(bk =>
                h("tr", { key: bk.filename },
                  h("td", { style: { whiteSpace: "nowrap", fontSize: "12px" } },
                    new Date(bk.created_at).toLocaleString()
                  ),
                  h("td", { style: { fontWeight: "700", fontFamily: "monospace", fontSize: "12px" } }, bk.filename),
                  h("td", { style: { fontSize: "12px" } }, `${(bk.size_bytes / 1024).toFixed(1)} KB`),
                  h("td", { style: { fontFamily: "monospace", fontSize: "11px", color: "var(--cyan-neon)" } },
                    `${bk.checksum_sha256.substring(0, 16)}...`
                  ),
                  h("td", { style: { fontSize: "12px", color: "var(--text-secondary)" } }, bk.note || "Snapshot"),
                  h("td", { style: { textAlign: "right" } },
                    h("button", {
                      className: "btn btn-sm btn-secondary",
                      onClick: () => handleVerifyBackup(bk.filename),
                    }, "🛡️ Verify Integrity")
                  )
                )
              )
            )
          )
        )
    )
  );
}

// 13. Placeholder for other modules
function PlaceholderModuleView({ title }) {
  return h("div", { className: "panel-box" },
    h("div", { className: "panel-header" }, h("h3", null, `${title} Module`)),
    h("div", { style: { padding: "32px", textAlign: "center", color: "var(--text-secondary)" } },
      h("div", { style: { fontSize: "36px", marginBottom: "12px" } }, "🛡️"),
      h("h4", null, `${title} Subsystem Active`),
      h("p", { style: { marginTop: "6px" } }, "Service ready for continuous telemetry ingestion and analytics.")
    )
  );
}

// Mount React Root
window.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("react-root");
  if (container) {
    const root = ReactDOM.createRoot(container);
    root.render(h(CyberShieldApp));
  }
});
