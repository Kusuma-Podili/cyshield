/**
 * CyberShield Enterprise SOC Glass Cockpit - Real-Time Dashboard Controller
 * Pure vanilla JavaScript with zero external CDN dependencies.
 */

class CyberShieldSOCApp {
  constructor() {
    this.ws = null;
    this.alerts = [];
    this.events = [];
    this.incidents = [];
    this.playbooks = [];
    this.iocs = [];
    this.cves = [];
    this.activeTab = "command-center";
    
    this.init();
  }

  init() {
    this.setupTabs();
    this.setupClock();
    this.setupWebSocket();
    this.fetchInitialData();
    this.setupEventListeners();
  }

  // Clock in UTC format
  setupClock() {
    const updateTime = () => {
      const now = new Date();
      const el = document.getElementById("utc-clock");
      if (el) {
        el.textContent = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
      }
    };
    updateTime();
    setInterval(updateTime, 1000);
  }

  // Tab switching navigation
  setupTabs() {
    const buttons = document.querySelectorAll(".tab-button");
    buttons.forEach(btn => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-tab");
        this.switchTab(target);
      });
    });
  }

  switchTab(tabId) {
    this.activeTab = tabId;
    document.querySelectorAll(".tab-button").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-tab") === tabId);
    });
    document.querySelectorAll(".tab-content").forEach(c => {
      c.classList.toggle("active", c.id === `tab-${tabId}`);
    });

    if (tabId === "mitre-matrix") {
      this.fetchMitreHeatmap();
    } else if (tabId === "soar-control") {
      this.fetchPlaybooks();
      this.fetchExecutions();
      this.fetchContainment();
    } else if (tabId === "threat-intel") {
      this.fetchIntel();
    } else if (tabId === "evidence-locker") {
      this.fetchEvidence();
    }
  }

  // Resilient WebSocket Client
  setupWebSocket() {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${proto}//${host}/ws/soc`;

    console.log("Connecting to WebSocket:", wsUrl);
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log("Connected to CyberShield Real-Time SOC Bus");
      const dot = document.getElementById("ws-status-dot");
      const text = document.getElementById("ws-status-text");
      if (dot) dot.style.backgroundColor = "var(--green-neon)";
      if (text) text.textContent = "CONNECTED (LIVE STREAM)";
    };

    this.ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        this.handleWebSocketMessage(msg);
      } catch (err) {
        console.error("WS parse error:", err);
      }
    };

    this.ws.onclose = () => {
      console.warn("WebSocket closed. Attempting reconnect in 3s...");
      const dot = document.getElementById("ws-status-dot");
      const text = document.getElementById("ws-status-text");
      if (dot) dot.style.backgroundColor = "var(--red-critical)";
      if (text) text.textContent = "RECONNECTING...";
      setTimeout(() => this.setupWebSocket(), 3000);
    };

    this.ws.onerror = (err) => {
      console.error("WebSocket error:", err);
    };
  }

  handleWebSocketMessage(packet) {
    const { type, data } = packet;

    if (type === "alert.new") {
      this.addAlert(data);
      this.updateKPICounters();
    } else if (type === "telemetry.normalized") {
      this.addTerminalLine("NORM", `${data.log_source} | ${data.event_action} | Host: ${data.host_name || 'N/A'} | User: ${data.user_name || 'N/A'}`);
    } else if (type === "telemetry.flow") {
      this.addTerminalLine("FLOW", `${data.source_ip}:${data.source_port} -> ${data.destination_ip}:${data.destination_port} | Entropy: ${data.byte_entropy} | Bytes: ${data.bytes_sent}`);
    } else if (type === "incident.updated") {
      this.fetchIncidents();
      this.updateKPICounters();
    } else if (type === "soar.completed") {
      this.addTerminalLine("SOAR", `Playbook '${data.playbook_name}' [${data.status}] on ${data.target_entity}`);
      if (this.activeTab === "soar-control") {
        this.fetchExecutions();
        this.fetchContainment();
      }
      this.updateKPICounters();
    }
  }

  addTerminalLine(src, message) {
    const term = document.getElementById("telemetry-terminal");
    if (!term) return;

    const line = document.createElement("div");
    line.className = "terminal-line";
    const nowStr = new Date().toISOString().substring(11, 19);
    line.innerHTML = `<span class="terminal-time">[${nowStr}]</span> <span class="terminal-src">&lt;${src}&gt;</span> <span>${this.escapeHtml(message)}</span>`;

    term.appendChild(line);
    term.scrollTop = term.scrollHeight;

    // Cap terminal lines to 200
    while (term.children.length > 200) {
      term.removeChild(term.firstChild);
    }
  }

  addAlert(alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > 500) this.alerts.pop();
    this.renderAlertsTable();
  }

  // Fetch initial data
  async fetchInitialData() {
    try {
      const [alertsRes, eventsRes, metricsRes, incidentsRes] = await Promise.all([
        fetch("/api/v1/alerts?limit=50"),
        fetch("/api/v1/telemetry/recent?limit=30"),
        fetch("/api/v1/system/metrics"),
        fetch("/api/v1/incidents"),
      ]);

      if (alertsRes.ok) {
        this.alerts = await alertsRes.json();
        this.renderAlertsTable();
      }

      if (eventsRes.ok) {
        const events = await eventsRes.json();
        events.forEach(e => {
          this.addTerminalLine("HIST", `${e.log_source} | ${e.event_action} | ${e.host_name || e.source_ip || 'N/A'}`);
        });
      }

      if (metricsRes.ok) {
        const metrics = await metricsRes.json();
        this.applyMetrics(metrics);
      }

      if (incidentsRes.ok) {
        this.incidents = await incidentsRes.json();
        this.renderIncidentsTable();
      }
    } catch (err) {
      console.error("Failed fetching initial telemetry:", err);
    }
  }

  applyMetrics(metrics) {
    document.getElementById("kpi-events-count").textContent = (metrics.ingestion.total_ingested_events || 0).toLocaleString();
    document.getElementById("kpi-alerts-count").textContent = (metrics.ingestion.total_generated_alerts || this.alerts.length).toLocaleString();
    document.getElementById("kpi-incidents-count").textContent = (metrics.incidents.open_incidents || 0).toString();
    document.getElementById("kpi-mttr-val").textContent = `${metrics.incidents.avg_mttr_minutes || 14.5}m`;
  }

  updateKPICounters() {
    const critCount = this.alerts.filter(a => a.severity === "CRITICAL").length;
    const badge = document.getElementById("kpi-threat-level");
    if (badge) {
      if (critCount > 0) {
        badge.textContent = "DEFCON 1 (CRITICAL)";
        badge.style.color = "var(--red-critical)";
      } else if (this.alerts.some(a => a.severity === "HIGH")) {
        badge.textContent = "DEFCON 2 (ELEVATED)";
        badge.style.color = "var(--orange-warn)";
      } else {
        badge.textContent = "DEFCON 4 (GUARDED)";
        badge.style.color = "var(--green-neon)";
      }
    }
    document.getElementById("kpi-alerts-count").textContent = this.alerts.length.toLocaleString();
  }

  renderAlertsTable() {
    const tbody = document.getElementById("alerts-table-body");
    if (!tbody) return;

    tbody.innerHTML = "";
    if (this.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted);">No security alerts detected. System is clean.</td></tr>`;
      return;
    }

    this.alerts.slice(0, 50).forEach(alert => {
      const tr = document.createElement("tr");
      const sevClass = `badge-${alert.severity.toLowerCase()}`;
      const tactics = (alert.mitre_tactics || []).join(", ") || "Execution";
      const target = alert.impacted_host || alert.impacted_user || alert.primary_source_ip || "Internal Subnet";

      tr.innerHTML = `
        <td><span class="badge ${sevClass}">${alert.severity}</span></td>
        <td><strong>${this.escapeHtml(alert.title)}</strong></td>
        <td><span class="badge badge-info">${alert.detection_engine}</span></td>
        <td>${this.escapeHtml(tactics)}</td>
        <td><code>${this.escapeHtml(target)}</code></td>
        <td><span class="badge badge-low">${alert.status}</span></td>
        <td>
          <button class="btn btn-primary" style="padding: 2px 8px;" onclick="window.socApp.viewAlertDetail('${alert.alert_id}')">Inspect</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  viewAlertDetail(alertId) {
    const alert = this.alerts.find(a => a.alert_id === alertId);
    if (!alert) return;

    document.getElementById("modal-alert-title").textContent = alert.title;
    document.getElementById("modal-alert-id").textContent = alert.alert_id;
    document.getElementById("modal-alert-severity").className = `badge badge-${alert.severity.toLowerCase()}`;
    document.getElementById("modal-alert-severity").textContent = alert.severity;
    document.getElementById("modal-alert-desc").textContent = alert.description;
    document.getElementById("modal-alert-engine").textContent = alert.detection_engine;
    document.getElementById("modal-alert-rule").textContent = `${alert.rule_name || 'N/A'} (${alert.rule_id || 'N/A'})`;
    document.getElementById("modal-alert-tactics").textContent = (alert.mitre_tactics || []).join(", ") || "N/A";
    document.getElementById("modal-alert-techniques").textContent = (alert.mitre_techniques || []).join(", ") || "N/A";
    document.getElementById("modal-alert-target").textContent = alert.impacted_host || alert.impacted_user || alert.primary_source_ip || "N/A";
    document.getElementById("modal-alert-meta").textContent = JSON.stringify(alert.metadata || {}, null, 2);

    // One-click containment button setup
    const containBtn = document.getElementById("modal-contain-btn");
    if (containBtn) {
      containBtn.onclick = () => this.autoContainFromAlert(alert);
    }

    document.getElementById("alert-detail-modal").classList.add("active");
  }

  async autoContainFromAlert(alert) {
    const target = alert.impacted_host || alert.primary_source_ip || "ws-target.corp";
    let pbId = "PB-RANSOMWARE-01";
    if ((alert.mitre_techniques || []).includes("T1110")) {
      pbId = "PB-BRUTEFORCE-02";
    } else if ((alert.mitre_tactics || []).includes("Lateral Movement")) {
      pbId = "PB-LATERAL-04";
    } else if ((alert.mitre_tactics || []).includes("Exfiltration")) {
      pbId = "PB-EXFIL-03";
    }

    try {
      const res = await fetch("/api/v1/soar/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          playbook_id: pbId,
          target_entity: target,
          executed_by: "SOC Lead Analyst",
          context: {
            host: alert.impacted_host || target,
            user: alert.impacted_user || "admin",
            source_ip: alert.primary_source_ip || "192.168.1.100",
            dest_ip: alert.primary_dest_ip || "198.51.100.23",
          }
        })
      });
      if (res.ok) {
        const run = await res.json();
        alert.status = "CONTAINED";
        alert.containment_actions_taken.push(`SOAR Playbook ${pbId} executed`);
        this.renderAlertsTable();
        this.closeModal("alert-detail-modal");
        alert(`Containment playbook '${pbId}' successfully executed! Execution ID: ${run.execution_id}`);
      }
    } catch (err) {
      console.error("Containment failure:", err);
    }
  }

  closeModal(modalId) {
    document.getElementById(modalId).classList.remove("active");
  }

  // MITRE Heatmap
  async fetchMitreHeatmap() {
    try {
      const res = await fetch("/api/v1/intel/mitre/heatmap");
      if (!res.ok) return;
      const data = await res.json();
      this.renderMitreHeatmap(data);
    } catch (err) {
      console.error("MITRE heatmap fetch error:", err);
    }
  }

  renderMitreHeatmap(data) {
    const grid = document.getElementById("mitre-heatmap-container");
    if (!grid) return;

    grid.innerHTML = "";
    data.tactics.forEach(tactic => {
      const col = document.createElement("div");
      col.className = "mitre-col";

      const header = document.createElement("div");
      header.className = "mitre-col-header";
      header.innerHTML = `<strong>${tactic.tactic_name}</strong><br><span style="color: ${tactic.alert_count > 0 ? 'var(--red-critical)' : 'var(--text-muted)'};">${tactic.alert_count} Alerts</span>`;
      col.appendChild(header);

      // Find techniques under this tactic
      const matchingTechs = data.active_techniques.filter(tech => tech.tactic === tactic.tactic_name);
      if (matchingTechs.length === 0) {
        const emptyCard = document.createElement("div");
        emptyCard.className = "mitre-technique-card";
        emptyCard.style.color = "var(--text-muted)";
        emptyCard.textContent = "No detections active";
        col.appendChild(emptyCard);
      } else {
        matchingTechs.forEach(tech => {
          const card = document.createElement("div");
          card.className = "mitre-technique-card hot";
          card.innerHTML = `<strong>${tech.technique_id}</strong><br>${this.escapeHtml(tech.name)}<br><span class="badge badge-critical" style="margin-top:4px;">${tech.alert_count} hits</span>`;
          col.appendChild(card);
        });
      }

      grid.appendChild(col);
    });
  }

  // SOAR Control Tab
  async fetchPlaybooks() {
    try {
      const res = await fetch("/api/v1/soar/playbooks");
      if (!res.ok) return;
      const pbs = await res.json();
      this.playbooks = pbs;
      const select = document.getElementById("soar-playbook-select");
      if (select) {
        select.innerHTML = "";
        pbs.forEach(p => {
          const opt = document.createElement("option");
          opt.value = p.id;
          opt.textContent = `${p.name} (${p.steps_count} steps)`;
          select.appendChild(opt);
        });
      }
    } catch (err) {
      console.error("Fetch playbooks error:", err);
    }
  }

  async fetchExecutions() {
    try {
      const res = await fetch("/api/v1/soar/executions");
      if (!res.ok) return;
      const runs = await res.json();
      const tbody = document.getElementById("soar-executions-tbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      runs.forEach(run => {
        const tr = document.createElement("tr");
        const statusClass = run.status === "COMPLETED" ? "badge-low" : "badge-critical";
        tr.innerHTML = `
          <td><code>${run.execution_id}</code></td>
          <td><strong>${this.escapeHtml(run.playbook_name)}</strong></td>
          <td><code>${this.escapeHtml(run.target_entity)}</code></td>
          <td><span class="badge ${statusClass}">${run.status}</span></td>
          <td>${run.steps.length} steps</td>
          <td>${run.started_at ? run.started_at.substring(11, 19) : ''}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      console.error("Fetch executions error:", err);
    }
  }

  async fetchContainment() {
    try {
      const res = await fetch("/api/v1/soar/containment");
      if (!res.ok) return;
      const data = await res.json();

      const hostsList = document.getElementById("containment-hosts-list");
      if (hostsList) {
        hostsList.innerHTML = "";
        const hosts = Object.keys(data.isolated_hosts);
        if (hosts.length === 0) {
          hostsList.innerHTML = `<li style="color:var(--text-muted);">No hosts currently quarantined.</li>`;
        } else {
          hosts.forEach(h => {
            hostsList.innerHTML += `<li style="color:var(--red-critical); font-family:var(--font-mono);"><strong>${h}</strong> (Isolated at ${data.isolated_hosts[h].isolated_at.substring(11, 19)})</li>`;
          });
        }
      }

      const ipsList = document.getElementById("containment-ips-list");
      if (ipsList) {
        ipsList.innerHTML = "";
        const ips = Object.keys(data.blocked_ips);
        if (ips.length === 0) {
          ipsList.innerHTML = `<li style="color:var(--text-muted);">No external IPs currently blocked.</li>`;
        } else {
          ips.forEach(ip => {
            ipsList.innerHTML += `<li style="color:var(--orange-warn); font-family:var(--font-mono);"><strong>${ip}</strong> (Firewall Drop Active)</li>`;
          });
        }
      }
    } catch (err) {
      console.error("Fetch containment error:", err);
    }
  }

  async runManualPlaybook() {
    const pbSelect = document.getElementById("soar-playbook-select");
    const targetInput = document.getElementById("soar-target-input");
    if (!pbSelect || !targetInput) return;

    const pbId = pbSelect.value;
    const target = targetInput.value.trim() || "ws-finance-08.corp";

    try {
      const res = await fetch("/api/v1/soar/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          playbook_id: pbId,
          target_entity: target,
          executed_by: "SOC Dashboard Operator",
        })
      });
      if (res.ok) {
        const run = await res.json();
        this.fetchExecutions();
        this.fetchContainment();
        alert(`Playbook launched successfully! Execution ID: ${run.execution_id}`);
      }
    } catch (err) {
      console.error("Error executing playbook:", err);
    }
  }

  // CS-QL Threat Hunter Console
  async executeCSQL() {
    const input = document.getElementById("csql-query-input");
    const targetSelect = document.getElementById("csql-target-select");
    const resultsContainer = document.getElementById("csql-results-container");
    if (!input || !resultsContainer) return;

    const query = input.value.trim() || "*";
    const target = targetSelect ? targetSelect.value : "events";

    resultsContainer.innerHTML = `<div style="color:var(--cyan-neon); font-family:var(--font-mono);">Executing CS-QL query against in-memory telemetry buffer...</div>`;

    try {
      const res = await fetch("/api/v1/telemetry/csql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, target })
      });
      if (!res.ok) {
        resultsContainer.innerHTML = `<div style="color:var(--red-critical);">CS-QL Execution Failed! Check query syntax.</div>`;
        return;
      }

      const data = await res.json();
      let html = `<div style="margin-bottom:12px; font-family:var(--font-mono); color:var(--green-neon);">Query matched ${data.total_matched} records (returned: ${data.returned_count})</div>`;

      if (data.aggregation) {
        html += `<div class="panel" style="margin-bottom:16px; padding:12px;"><strong style="color:var(--cyan-neon);">Aggregation Statistics</strong><div style="display:flex; flex-wrap:wrap; gap:10px; margin-top:8px;">`;
        for (const [k, v] of Object.entries(data.aggregation)) {
          html += `<div style="background:var(--bg-secondary); border:1px solid var(--border-color); padding:4px 10px; border-radius:4px; font-family:var(--font-mono); font-size:12px;"><strong>${this.escapeHtml(k)}</strong>: <span style="color:var(--cyan-neon);">${v}</span></div>`;
        }
        html += `</div></div>`;
      }

      html += `<div class="table-container"><table><thead><tr>`;
      if (target === "alerts") {
        html += `<th>Severity</th><th>Title</th><th>Engine</th><th>Status</th><th>Target</th>`;
      } else {
        html += `<th>Time</th><th>Source</th><th>Action</th><th>Host / IP</th><th>Process / URL</th>`;
      }
      html += `</tr></thead><tbody>`;

      data.results.forEach(row => {
        html += `<tr>`;
        if (target === "alerts") {
          html += `<td><span class="badge badge-${(row.severity||'').toLowerCase()}">${row.severity}</span></td><td><strong>${this.escapeHtml(row.title)}</strong></td><td>${row.detection_engine}</td><td>${row.status}</td><td>${row.impacted_host || row.primary_source_ip || 'N/A'}</td>`;
        } else {
          html += `<td>${(row.timestamp||'').substring(11, 19)}</td><td><span class="badge badge-info">${row.log_source}</span></td><td>${row.event_action}</td><td><code>${row.host_name || row.source_ip || 'N/A'}</code></td><td>${this.escapeHtml(row.process_name || row.http_url || '')}</td>`;
        }
        html += `</tr>`;
      });

      html += `</tbody></table></div>`;
      resultsContainer.innerHTML = html;
    } catch (err) {
      resultsContainer.innerHTML = `<div style="color:var(--red-critical);">Execution Error: ${err.message}</div>`;
    }
  }

  // Threat Intel & CVE Tab
  async fetchIntel() {
    try {
      const [iocsRes, cvesRes] = await Promise.all([
        fetch("/api/v1/intel/ioc/all"),
        fetch("/api/v1/intel/cve")
      ]);

      if (iocsRes.ok) {
        const iocs = await iocsRes.json();
        const tbody = document.getElementById("intel-iocs-tbody");
        if (tbody) {
          tbody.innerHTML = "";
          iocs.forEach(ioc => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
              <td><span class="badge badge-info">${ioc.type}</span></td>
              <td><code>${this.escapeHtml(ioc.value)}</code></td>
              <td><strong>${this.escapeHtml(ioc.threat_name)}</strong></td>
              <td><span class="badge badge-${ioc.severity.toLowerCase()}">${ioc.severity}</span></td>
              <td>${ioc.source}</td>
            `;
            tbody.appendChild(tr);
          });
        }
      }

      if (cvesRes.ok) {
        const cves = await cvesRes.json();
        const tbody = document.getElementById("intel-cves-tbody");
        if (tbody) {
          tbody.innerHTML = "";
          cves.forEach(cve => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
              <td><strong>${cve.cve_id}</strong></td>
              <td>${this.escapeHtml(cve.title)}</td>
              <td><span class="badge badge-${cve.cvss.severity.toLowerCase()}">${cve.cvss.score} ${cve.cvss.severity}</span></td>
              <td><code>${cve.cvss.vector_string}</code></td>
              <td style="font-size:12px;">${this.escapeHtml(cve.mitigation_advice)}</td>
            `;
            tbody.appendChild(tr);
          });
        }
      }
    } catch (err) {
      console.error("Fetch intel error:", err);
    }
  }

  async searchIoC() {
    const input = document.getElementById("ioc-search-input");
    const resultBox = document.getElementById("ioc-search-result");
    if (!input || !resultBox) return;

    const val = input.value.trim();
    if (!val) return;

    try {
      const res = await fetch(`/api/v1/intel/ioc/lookup?value=${encodeURIComponent(val)}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.matched) {
        const e = data.entry;
        resultBox.innerHTML = `
          <div style="background:rgba(255, 0, 85, 0.15); border:1px solid var(--red-critical); border-radius:4px; padding:10px; margin-top:8px;">
            <strong style="color:var(--red-critical);">⚠️ MATCH CONFIRMED IN THREAT INTEL: ${e.threat_name}</strong><br>
            <span>Type: ${e.type} | Severity: ${e.severity} | Confidence: ${e.confidence * 100}% | Source: ${e.source}</span>
          </div>
        `;
      } else {
        resultBox.innerHTML = `
          <div style="background:rgba(0, 255, 136, 0.1); border:1px solid var(--green-neon); border-radius:4px; padding:10px; margin-top:8px; color:var(--green-neon);">
            ✓ Clean: Value '${this.escapeHtml(val)}' not present in local threat intelligence repository.
          </div>
        `;
      }
    } catch (err) {
      console.error("IoC search error:", err);
    }
  }

  // Evidence Locker
  async fetchEvidence() {
    try {
      const res = await fetch("/api/v1/incidents/evidence/all");
      if (!res.ok) return;
      const artifacts = await res.json();
      const tbody = document.getElementById("evidence-tbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      if (artifacts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No sealed evidence artifacts captured yet.</td></tr>`;
        return;
      }

      artifacts.forEach(art => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${art.artifact_id}</code></td>
          <td><strong>${this.escapeHtml(art.name)}</strong></td>
          <td><span class="badge badge-info">${art.artifact_type}</span></td>
          <td><code>${art.sha256_hash.substring(0, 24)}...</code></td>
          <td>${(art.file_size_bytes / 1024).toFixed(1)} KB</td>
          <td><span class="badge badge-low">SEALED (${art.chain_of_custody.length} STAMPS)</span></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      console.error("Fetch evidence error:", err);
    }
  }

  // Simulation Triggers
  async triggerSimulation(type) {
    console.log("Triggering cyber attack simulation:", type);
    this.addTerminalLine("SIM", `Injecting synthetic threat vector: ${type.toUpperCase()}`);

    try {
      const res = await fetch(`/api/v1/simulation/${type}`, { method: "POST" });
      if (res.ok) {
        const resJson = await res.json();
        console.log("Simulation started:", resJson);
      }
    } catch (err) {
      console.error("Simulation error:", err);
    }
  }

  setupEventListeners() {
    // Attack simulator buttons
    const simBtns = document.querySelectorAll("[data-sim]");
    simBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const simType = btn.getAttribute("data-sim");
        this.triggerSimulation(simType);
      });
    });

    // CS-QL Run Button
    const runCsqlBtn = document.getElementById("run-csql-btn");
    if (runCsqlBtn) {
      runCsqlBtn.addEventListener("click", () => this.executeCSQL());
    }

    // IoC Search Button
    const iocSearchBtn = document.getElementById("ioc-search-btn");
    if (iocSearchBtn) {
      iocSearchBtn.addEventListener("click", () => this.searchIoC());
    }

    // Run Playbook Button
    const runPbBtn = document.getElementById("run-playbook-btn");
    if (runPbBtn) {
      runPbBtn.addEventListener("click", () => this.runManualPlaybook());
    }

    // Modal Close
    document.querySelectorAll(".modal-close-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const modal = btn.closest(".modal-overlay");
        if (modal) modal.classList.remove("active");
      });
    });
  }

  escapeHtml(str) {
    if (!str) return "";
    return str.toString()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

// Instantiate singleton app once DOM is ready
window.addEventListener("DOMContentLoaded", () => {
  window.socApp = new CyberShieldSOCApp();
});
