/**
 * UniFi Blocker – Sidebar Panel v0.2.5
 *
 * Read-only by default. Action Mode toggle enables write operations.
 * Dynamic category sub-navigation when a category has 5+ devices.
 * Manual device identification tool for unknowns.
 */

const VERSION = "0.3.20";
const SIDEBAR_THRESHOLD = 5;

class UniFiBlockerPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._hass = null;
    this._view = "overview";
    this._viewArg = null;       // for category:<name> views
    this._actionMode = false;
    this._data = { clients: [] };
    this._overview = {};
    this._categories = {};
    this._pollTimer = null;
    this._sortCol = "category";
    this._sortAsc = true;
    this._filter = "";
    this._localnet = {};
    this._scanCache = {};
    this._recs = {};
    this._initialized = false;
  }

  set hass(h) {
    this._hass = h;
    if (!this._initialized) { this._initialized = true; this._render(); this._fetchAll(); this._startPolling(); }
  }
  setConfig(c) {}
  connectedCallback() { if (this._hass && !this._initialized) { this._initialized = true; this._render(); this._fetchAll(); this._startPolling(); } }
  disconnectedCallback() { this._stopPolling(); }

  // ── Data ──────────────────────────────────────────────────────────
  async _ws(type, extra = {}) { if (!this._hass) return null; try { return await this._hass.callWS({ type, ...extra }); } catch (e) { console.warn("[UB]", type, e); return null; } }

  async _fetchAll() {
    const [ov, cl, cats, ln, recs] = await Promise.all([
      this._ws("unifiblocker/overview"),
      this._ws("unifiblocker/clients"),
      this._ws("unifiblocker/categories"),
      this._ws("unifiblocker/localnet_status"),
      this._ws("unifiblocker/recommendations"),
    ]);
    if (ov) this._overview = ov;
    if (cl) this._data = cl;
    if (cats) this._categories = cats.categories || {};
    if (ln) this._localnet = ln;
    if (recs) this._recs = recs;
    this._render();
  }

  _startPolling() { this._stopPolling(); this._pollTimer = setInterval(() => this._fetchAll(), 30000); }
  _stopPolling() { if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; } }

  async _action(type, mac) { if (!this._actionMode) return; const r = await this._ws(type, { mac }); if (r && r.ok) setTimeout(() => this._fetchAll(), 800); }
  async _setCategory(mac, category, name) { const r = await this._ws("unifiblocker/set_category", { mac, category, name: name || undefined }); if (r && r.ok) setTimeout(() => this._fetchAll(), 800); }
  async _scanDevice(mac) {
    const el = this.shadowRoot.getElementById(`scan-${mac.replace(/:/g,"")}`);
    if (el) el.innerHTML = '<div class="scan-loading">Scanning ~90 ports... this takes a few seconds</div>';
    const r = await this._ws("unifiblocker/scan_device", { mac });
    if (r) { this._scanCache[mac.toLowerCase()] = r; this._updateMain(); }
  }

  async _assignLocal(mac, category, name) { if (!this._actionMode) { alert("Enable Action Mode first."); return; } const r = await this._ws("unifiblocker/localnet_assign", { mac, category, name: name||undefined }); if (r) { alert(r.ok ? `Assigned ${r.ip} to ${mac}` : `Error: ${r.error}`); setTimeout(() => this._fetchAll(), 800); } }
  async _removeLocal(mac) { if (!this._actionMode) { alert("Enable Action Mode first."); return; } const r = await this._ws("unifiblocker/localnet_remove", { mac }); if (r) setTimeout(() => this._fetchAll(), 800); }
  async _ensureRule() { if (!this._actionMode) { alert("Enable Action Mode first."); return; } const r = await this._ws("unifiblocker/localnet_ensure_rule"); if (r) alert(r.ok ? `Firewall rule ${r.status}: ${r.rule_id||"done"}` : `Error: ${r.error}`); setTimeout(() => this._fetchAll(), 800); }

  // ── Render ────────────────────────────────────────────────────────
  _render() {
    const catIcons = this._overview.category_icons || {};
    const catLabels = this._overview.category_labels || {};

    // Build dynamic category nav items
    let catNav = "";
    const sorted = Object.entries(this._categories).sort((a, b) => b[1].count - a[1].count);
    for (const [cat, info] of sorted) {
      if (info.count >= SIDEBAR_THRESHOLD) {
        const active = this._view === "category" && this._viewArg === cat ? "active" : "";
        catNav += `<div class="nav-item sub ${active}" data-view="category" data-arg="${cat}">
          <span class="nav-icon">${info.icon}</span>
          <span class="nav-label">${info.label} <span class="nav-count">${info.count}</span></span>
        </div>`;
      }
    }

    this.shadowRoot.innerHTML = `
      <style>${CSS}</style>
      <div class="shell">
        <nav class="sidebar">
          <div class="brand"><div class="brand-icon">🛡</div><div class="brand-text">UniFi Blocker</div><div class="brand-ver">v${VERSION}</div></div>
          <div class="nav-items">
            ${this._nav("overview", "Overview", "📊")}
            ${this._nav("new", "New Devices", "🆕")}
            ${this._nav("suspicious", "Suspicious", "⚠")}
            ${this._nav("clients", "All Clients", "📋")}
            ${this._nav("recommendations", "Security", "🛡")}
            ${this._nav("identify", "Identify", "🔍")}
            ${this._nav("nas", "Network Access", "🌐")}
            ${this._nav("localnet", "Local Only", "🔒")}
            ${catNav ? '<div class="nav-divider">Categories</div>' + catNav : ""}
            ${this._nav("quarantined", "Quarantined", "🚫")}
            ${this._nav("ports", "Port Guide", "🔌")}
          </div>
          <div class="action-toggle">
            <label class="toggle-label"><input type="checkbox" id="at" /><span class="toggle-switch"></span><span class="toggle-text">Action Mode</span></label>
            <div class="toggle-hint" id="ah">Read-only</div>
          </div>
        </nav>
        <main class="content" id="mc"></main>
      </div>`;

    // Nav click handlers
    this.shadowRoot.querySelectorAll(".nav-item").forEach(el => {
      el.addEventListener("click", () => {
        this._view = el.dataset.view;
        this._viewArg = el.dataset.arg || null;
        this._render();
      });
    });

    // Action mode toggle
    const at = this.shadowRoot.getElementById("at");
    if (at) {
      at.checked = this._actionMode;
      at.addEventListener("change", e => {
        this._actionMode = e.target.checked;
        this.shadowRoot.getElementById("ah").textContent = this._actionMode ? "Actions enabled" : "Read-only";
        this._updateMain();
      });
    }
    this._updateMain();
  }

  _nav(view, label, icon) {
    const a = this._view === view && !this._viewArg ? "active" : "";
    return `<div class="nav-item ${a}" data-view="${view}"><span class="nav-icon">${icon}</span><span class="nav-label">${label}</span></div>`;
  }

  _updateMain() {
    const mc = this.shadowRoot.getElementById("mc");
    if (!mc) return;
    switch (this._view) {
      case "overview": mc.innerHTML = this._vOverview(); break;
      case "detail_connected": mc.innerHTML = this._vDetailConnected(); break;
      case "detail_wireless": mc.innerHTML = this._vDetailWireless(); break;
      case "detail_wired": mc.innerHTML = this._vDetailWired(); break;
      case "detail_blocked": mc.innerHTML = this._vDetailBlocked(); break;
      case "detail_trusted": mc.innerHTML = this._vDetailTrusted(); break;
      case "detail_threats": mc.innerHTML = this._vDetailThreats(); break;
      case "new": mc.innerHTML = this._vDeviceList(this._overview.new_devices || [], "New / Unidentified Devices", "Devices that haven't been classified yet."); break;
      case "suspicious": mc.innerHTML = this._vDeviceList((this._overview.suspicious_devices || []).sort((a,b) => (b.suspicion_score||0)-(a.suspicion_score||0)), "Suspicious Traffic", "Devices scored 3+ on behavioral heuristics."); break;
      case "clients": mc.innerHTML = this._vClients(); break;
      case "recommendations": mc.innerHTML = this._vRecommendations(); break;
      case "identify": mc.innerHTML = this._vIdentify(); break;
      case "nas": mc.innerHTML = this._vNAS(); break;
      case "localnet": mc.innerHTML = this._vLocalNet(); break;
      case "category": mc.innerHTML = this._vCategory(); break;
      case "quarantined": mc.innerHTML = this._vDeviceList((this._data.clients||[]).filter(c=>c.state==="quarantined"||c.blocked), "Quarantined / Blocked", "Devices blocked on the controller."); break;
      case "ports": mc.innerHTML = this._vPorts(); break;
    }
    this._bindActions(mc);
  }

  _bindActions(mc) {
    mc.querySelectorAll("[data-statview]").forEach(el => {
      el.addEventListener("click", () => { this._view = el.dataset.statview; this._viewArg = null; this._render(); });
    });
    // Category grid items (in overview and detail views).
    mc.querySelectorAll("[data-view='category']").forEach(el => {
      el.addEventListener("click", () => { this._view = "category"; this._viewArg = el.dataset.arg; this._render(); });
    });
    mc.querySelectorAll("[data-action]").forEach(btn => {
      btn.addEventListener("click", () => {
        if (!this._actionMode) { alert("Enable Action Mode first."); return; }
        if (confirm(`${btn.dataset.action} device ${btn.dataset.mac}?`)) this._action(`unifiblocker/${btn.dataset.action}`, btn.dataset.mac);
      });
    });
    mc.querySelectorAll("[data-scanmac]").forEach(btn => {
      btn.addEventListener("click", () => this._scanDevice(btn.dataset.scanmac));
    });
    mc.querySelectorAll("[data-blockport]").forEach(btn => {
      btn.addEventListener("click", async () => {
        if (!this._actionMode) { alert("Enable Action Mode first."); return; }
        const port = parseInt(btn.dataset.blockport);
        const mac = btn.dataset.blockmac;
        if (confirm(`Block port ${port} for ${mac}? This creates a firewall rule on the UCG Max.`)) {
          const r = await this._ws("unifiblocker/block_port", { mac, port });
          if (r && r.ok) { alert(`Port ${port} blocked for ${mac}`); btn.textContent = "Blocked"; btn.disabled = true; }
          else alert(`Failed: ${r?.error || "unknown error"}`);
        }
      });
    });
    mc.querySelectorAll("[data-localassign]").forEach(btn => {
      btn.addEventListener("click", () => {
        const mac = btn.dataset.mac; const cat = btn.dataset.localassign;
        const nameInput = mc.querySelector(`#lname-${mac.replace(/:/g,"")}`);
        this._assignLocal(mac, cat, nameInput ? nameInput.value : "");
      });
    });
    mc.querySelectorAll("[data-localremove]").forEach(btn => {
      btn.addEventListener("click", () => { if(confirm(`Remove local-only assignment for ${btn.dataset.mac}?`)) this._removeLocal(btn.dataset.mac); });
    });
    mc.querySelectorAll("[data-ensureFw]").forEach(btn => {
      btn.addEventListener("click", () => this._ensureRule());
    });
    mc.querySelectorAll("[data-setcat]").forEach(btn => {
      btn.addEventListener("click", () => {
        const mac = btn.dataset.mac;
        const cat = btn.dataset.setcat;
        const nameInput = mc.querySelector(`#name-${mac.replace(/:/g,"")}`);
        const name = nameInput ? nameInput.value : "";
        this._setCategory(mac, cat, name);
      });
    });
    const fi = mc.querySelector("#clientFilter");
    if (fi) { fi.value = this._filter; fi.addEventListener("input", e => { this._filter = e.target.value.toLowerCase(); this._updateMain(); }); }
    mc.querySelectorAll("[data-sort]").forEach(th => {
      th.addEventListener("click", () => { const c = th.dataset.sort; if (this._sortCol===c) this._sortAsc=!this._sortAsc; else { this._sortCol=c; this._sortAsc=true; } this._updateMain(); });
    });
  }

  // ── Views ─────────────────────────────────────────────────────────

  _vOverview() {
    const o = this._overview; const h = o.health || {};
    // Category summary
    let catSummary = "";
    const sorted = Object.entries(this._categories).sort((a,b) => b[1].count - a[1].count);
    if (sorted.length) {
      catSummary = `<div class="card"><h2>Device Categories</h2><div class="cat-grid">
        ${sorted.map(([cat, info]) => `<div class="cat-item clickable" data-view="category" data-arg="${cat}"><span class="cat-icon">${info.icon}</span><span class="cat-count">${info.count}</span><span class="cat-label">${info.label}</span></div>`).join("")}
      </div></div>`;
    }
    return `
      <h1>Network Overview</h1>
      <div class="stat-grid">
        ${this._stat("Connected", o.total_clients||0, "📱", "", "detail_connected")}
        ${this._stat("Wireless", o.wireless_count||0, "📶", "", "detail_wireless")}
        ${this._stat("Wired", o.wired_count||0, "🔗", "", "detail_wired")}
        ${this._stat("New", o.new_count||0, "🆕", o.new_count>0?"warn":"", "new")}
        ${this._stat("Suspicious", o.suspicious_count||0, "⚠", o.suspicious_count>0?"danger":"", "suspicious")}
        ${this._stat("Blocked", o.blocked_count||0, "🚫", "", "detail_blocked")}
        ${this._stat("Trusted", o.trusted_count||0, "✅", "", "detail_trusted")}
        ${this._stat("Threats", o.threat_events||0, "🐛", o.threat_events>0?"danger":"", "detail_threats")}
      </div>
      ${catSummary}
      <div class="card"><h2>Controller</h2>
        <table class="info-table">
          <tr><td>Status</td><td>${h.connection_ok?'<span class="badge ok">Connected</span>':'<span class="badge danger">Disconnected</span>'}</td></tr>
          <tr><td>Hostname</td><td>${h.hostname||"—"}</td></tr>
          <tr><td>Firmware</td><td>${h.version||"—"}</td></tr>
          <tr><td>Uptime</td><td>${h.uptime?(h.uptime/3600).toFixed(1)+" hrs":"—"}</td></tr>
        </table>
      </div>
      ${this._actionMode?"":"<div class=\"ro-banner\">Read-only mode — enable Action Mode in the sidebar</div>"}`;
  }

  // ── Detail views (stat card click-through) ────────────────────────

  _vRecommendations() {
    const r = this._recs || {};
    const netRecs = r.network_recs || [];
    const devRecs = r.device_recs || {};
    const totalDev = r.total_device_recs || 0;
    const critical = r.critical_count || 0;
    const high = r.high_count || 0;

    // Get top device recommendations (flatten, sort by priority, take top 20).
    const allDevRecs = [];
    for (const [mac, recs] of Object.entries(devRecs)) {
      for (const rec of recs) {
        allDevRecs.push({ ...rec, mac });
      }
    }
    const priOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    allDevRecs.sort((a, b) => (priOrder[a.priority] || 5) - (priOrder[b.priority] || 5));

    // Find the device name for each MAC.
    const clients = this._data.clients || [];
    const nameMap = {};
    clients.forEach(c => { nameMap[c.mac.toLowerCase()] = c.name || c.hostname || c.vendor || c.mac; });

    return `
      <h1>🛡 Security Recommendations</h1>
      <p class="subtitle">Prioritized security advice based on device analysis, port scans, vendor CVE history, and community best practices.</p>

      <div class="stat-grid">
        ${this._stat("Total Issues", totalDev, "📋", totalDev > 0 ? "warn" : "")}
        ${this._stat("Critical", critical, "🔴", critical > 0 ? "danger" : "")}
        ${this._stat("High", high, "🟠", high > 0 ? "warn" : "")}
        ${this._stat("Devices Affected", Object.keys(devRecs).length, "📱")}
      </div>

      ${netRecs.length ? `
        <div class="card"><h2>Network-Wide Recommendations</h2>
          ${netRecs.map(r => this._recCard(r)).join("")}
        </div>
      ` : ""}

      <div class="card"><h2>Per-Device Recommendations (top 30)</h2>
        ${allDevRecs.length === 0 ? '<div class="empty">No device-specific recommendations. Run port scans to get detailed advice.</div>' : ""}
        ${allDevRecs.slice(0, 30).map(r => `
          <div class="rec-item rec-${r.priority}">
            <div class="rec-header">
              <span class="rec-priority">${r.priority_label}</span>
              <span class="rec-device mono">${r.mac}</span>
              <span class="rec-name">${nameMap[r.mac] || ""}</span>
            </div>
            <div class="rec-title">${r.title}</div>
            <div class="rec-detail">${(r.detail || "").replace(/\n/g, "<br>")}</div>
            ${r.action !== "info" && this._actionMode ? `
              <div class="rec-actions">
                ${r.action === "quarantine" ? `<button class="btn btn-quarantine" data-action="quarantine" data-mac="${r.mac}">🚫 Quarantine</button>` : ""}
                ${r.action === "local_only" ? `<button class="btn btn-trust" data-localassign="${r.action_data?.category || "iot"}" data-mac="${r.mac}">🔒 Move to Local-Only</button>` : ""}
                ${r.action === "block_port" && r.action_data?.ports ? r.action_data.ports.map(p => `<button class="btn-port-block" data-blockport="${p}" data-blockmac="${r.mac}">Block port ${p}</button>`).join(" ") : ""}
                ${r.action === "review" ? `<button class="btn btn-scan" data-scanmac="${r.mac}">🔍 Scan Ports</button>` : ""}
              </div>
            ` : ""}
          </div>
        `).join("")}
      </div>

      <div class="card"><h2>About These Recommendations</h2>
        <p>Recommendations are generated from:</p>
        <ul style="font-size:12px;padding-left:20px;line-height:2">
          <li><strong>Vendor CVE databases</strong> — known vulnerabilities in Hikvision, Dahua, XMEye, Reolink, EZVIZ, Imou, Foscam</li>
          <li><strong>Port scan results</strong> — open ports mapped to security risks (Telnet, backdoors, exposed databases)</li>
          <li><strong>Traffic analysis</strong> — suspicious behavior flags from the heuristic scoring engine</li>
          <li><strong>Network placement</strong> — cameras on the main network that should be isolated</li>
          <li><strong>Community best practices</strong> — consensus from r/homelab, r/unifi, r/homeassistant on IoT isolation</li>
        </ul>
        <p style="margin-top:8px">Run <strong>port scans</strong> on unknown devices to get the most detailed recommendations.</p>
      </div>`;
  }

  _recCard(r) {
    return `<div class="rec-item rec-${r.priority}">
      <span class="rec-priority">${r.priority_label}</span>
      <div class="rec-title">${r.title}</div>
      <div class="rec-detail">${(r.detail || "").replace(/\n/g, "<br>")}</div>
    </div>`;
  }

  _vDetailConnected() {
    const clients = this._data.clients || [];
    const o = this._overview;
    const catCounts = o.category_counts || {};
    const catLabels = o.category_labels || {};
    const catIcons = o.category_icons || {};
    const totalTx = clients.reduce((s,c) => s + (c.tx_bytes||0), 0);
    const totalRx = clients.reduce((s,c) => s + (c.rx_bytes||0), 0);
    const avgRssi = clients.filter(c=>c.rssi).reduce((s,c,_,a) => s + c.rssi/a.length, 0);

    // Top talkers
    const topTalkers = clients.slice().sort((a,b) => ((b.tx_bytes||0)+(b.rx_bytes||0)) - ((a.tx_bytes||0)+(a.rx_bytes||0))).slice(0, 10);

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>📱 Connected Clients <span class="count">${clients.length}</span></h1>
      <p class="subtitle">Every device currently on your network. Tap any column to sort.</p>

      <div class="stat-grid">
        ${this._stat("Total", clients.length, "📱")}
        ${this._stat("Wireless", o.wireless_count||0, "📶")}
        ${this._stat("Wired", o.wired_count||0, "🔗")}
        ${this._stat("Total Upload", this._fmtB(totalTx), "⬆")}
        ${this._stat("Total Download", this._fmtB(totalRx), "⬇")}
        ${this._stat("Avg Signal", avgRssi?Math.round(avgRssi)+" dBm":"—", "📡")}
      </div>

      <div class="card"><h2>Category Breakdown</h2>
        <div class="cat-grid">
          ${Object.entries(catCounts).sort((a,b)=>b[1]-a[1]).map(([cat,cnt]) =>
            `<div class="cat-item"><span class="cat-icon">${catIcons[cat]||"❓"}</span><span class="cat-count">${cnt}</span><span class="cat-label">${catLabels[cat]||cat}</span></div>`
          ).join("")}
        </div>
      </div>

      <div class="card"><h2>Top 10 Bandwidth Users</h2>
        <table class="data-table"><thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>Category</th><th>Upload</th><th>Download</th><th>Total</th></tr></thead><tbody>
          ${topTalkers.map(c => `<tr>
            <td class="mono">${c.mac}</td><td>${c.name||"—"}</td><td>${c.vendor||"?"}</td>
            <td>${c.category_icon||""} ${c.category_label||""}</td>
            <td>${this._fmtB(c.tx_bytes)}</td><td>${this._fmtB(c.rx_bytes)}</td>
            <td><strong>${this._fmtB((c.tx_bytes||0)+(c.rx_bytes||0))}</strong></td>
          </tr>`).join("")}
        </tbody></table>
      </div>

      <div class="card"><h2>All Connected (${clients.length})</h2>
        ${clients.map((d,i) => this._deviceCard(d, i+1)).join("")}
      </div>`;
  }

  _vDetailWireless() {
    const clients = (this._data.clients || []).filter(c => !c.wired);
    // Group by SSID
    const ssidMap = {};
    clients.forEach(c => { const s = c.essid||"Unknown"; ssidMap[s] = (ssidMap[s]||0)+1; });
    // Group by channel
    const chanMap = {};
    clients.forEach(c => { if(c.channel) chanMap[c.channel] = (chanMap[c.channel]||0)+1; });
    // Signal distribution
    const sigBuckets = {"Excellent (>-50)":0, "Good (-50 to -65)":0, "Fair (-65 to -75)":0, "Weak (-75 to -85)":0, "Very Weak (<-85)":0, "Unknown":0};
    clients.forEach(c => {
      const r = c.rssi;
      if(r==null) sigBuckets["Unknown"]++;
      else if(r>-50) sigBuckets["Excellent (>-50)"]++;
      else if(r>-65) sigBuckets["Good (-50 to -65)"]++;
      else if(r>-75) sigBuckets["Fair (-65 to -75)"]++;
      else if(r>-85) sigBuckets["Weak (-75 to -85)"]++;
      else sigBuckets["Very Weak (<-85)"]++;
    });

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>📶 Wireless Clients <span class="count">${clients.length}</span></h1>
      <p class="subtitle">All Wi-Fi connected devices with signal quality, SSID, channel, and radio band information.</p>

      <div class="card"><h2>By SSID</h2>
        <table class="data-table"><thead><tr><th>SSID</th><th>Clients</th></tr></thead><tbody>
          ${Object.entries(ssidMap).sort((a,b)=>b[1]-a[1]).map(([s,n]) => `<tr><td><strong>${s}</strong></td><td>${n}</td></tr>`).join("")}
        </tbody></table>
      </div>

      <div class="card"><h2>By Channel</h2>
        <table class="data-table"><thead><tr><th>Channel</th><th>Clients</th></tr></thead><tbody>
          ${Object.entries(chanMap).sort((a,b)=>a[0]-b[0]).map(([ch,n]) => `<tr><td>Channel ${ch}</td><td>${n}</td></tr>`).join("")}
        </tbody></table>
      </div>

      <div class="card"><h2>Signal Quality Distribution</h2>
        <table class="data-table"><thead><tr><th>Signal Level</th><th>Clients</th></tr></thead><tbody>
          ${Object.entries(sigBuckets).filter(([,n])=>n>0).map(([lbl,n]) => `<tr><td>${lbl}</td><td>${n}</td></tr>`).join("")}
        </tbody></table>
      </div>

      <div class="card"><h2>All Wireless Clients</h2>
        <table class="data-table"><thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>SSID</th><th>Ch</th><th>Radio</th><th>RSSI</th><th>TX/RX</th></tr></thead><tbody>
          ${clients.sort((a,b)=>(a.rssi||0)-(b.rssi||0)).map(c => `<tr class="${c.rssi&&c.rssi<-80?"row-warn":""}">
            <td class="mono">${c.mac}</td><td>${c.name||"—"}</td><td>${c.vendor||"?"}</td><td class="mono">${c.ip||"—"}</td>
            <td>${c.essid||"—"}</td><td>${c.channel||"—"}</td><td>${c.radio||"—"}</td>
            <td>${c.rssi!=null?c.rssi+" dBm":"—"}</td><td>${this._fmtB(c.tx_bytes)}/${this._fmtB(c.rx_bytes)}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>`;
  }

  _vDetailWired() {
    const clients = (this._data.clients || []).filter(c => c.wired);
    const totalTx = clients.reduce((s,c) => s + (c.tx_bytes||0), 0);
    const totalRx = clients.reduce((s,c) => s + (c.rx_bytes||0), 0);

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>🔗 Wired Clients <span class="count">${clients.length}</span></h1>
      <p class="subtitle">Devices connected via Ethernet. These have stable, high-speed connections and no signal concerns.</p>

      <div class="stat-grid">
        ${this._stat("Wired Clients", clients.length, "🔗")}
        ${this._stat("Total Upload", this._fmtB(totalTx), "⬆")}
        ${this._stat("Total Download", this._fmtB(totalRx), "⬇")}
      </div>

      <div class="card"><h2>All Wired Clients</h2>
        <table class="data-table"><thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>Category</th><th>State</th><th>Upload</th><th>Download</th></tr></thead><tbody>
          ${clients.map(c => `<tr>
            <td class="mono">${c.mac}</td><td>${c.name||"—"}</td><td>${c.vendor||"?"}</td><td class="mono">${c.ip||"—"}</td>
            <td>${c.category_icon||""} ${c.category_label||""}</td><td><span class="badge ${c.state}">${c.state}</span></td>
            <td>${this._fmtB(c.tx_bytes)}</td><td>${this._fmtB(c.rx_bytes)}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>`;
  }

  _vDetailBlocked() {
    const clients = (this._data.clients || []).filter(c => c.blocked);
    const quarantined = (this._data.clients || []).filter(c => c.state === "quarantined");
    const allBlocked = [...new Map([...clients, ...quarantined].map(c=>[c.mac,c])).values()];

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>🚫 Blocked Devices <span class="count">${allBlocked.length}</span></h1>
      <p class="subtitle">Devices currently blocked on the UniFi controller or quarantined by UniFi Blocker. These devices cannot access the network.</p>

      <div class="card">
        <h2>What "Blocked" Means</h2>
        <p>A blocked device has its MAC address added to the controller's block list. It can still see your Wi-Fi network and attempt to connect, but the controller will reject the association. The device gets no IP address and cannot send or receive any traffic.</p>
        <p style="margin-top:8px">To unblock a device, enable <strong>Action Mode</strong> and click the Trust button, or call <code>unifiblocker.unblock_device</code>.</p>
      </div>

      ${allBlocked.length === 0 ? '<div class="empty">No blocked devices. Your network is allowing all connected clients.</div>' : ''}
      ${allBlocked.map((d,i) => this._deviceCard(d, i+1)).join("")}`;
  }

  _vDetailTrusted() {
    const clients = (this._data.clients || []).filter(c => c.state === "trusted");

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>✅ Trusted Devices <span class="count">${clients.length}</span></h1>
      <p class="subtitle">Devices you have explicitly marked as trusted. They will not appear in the New Devices review queue and will be automatically unblocked if blocked.</p>

      <div class="card">
        <h2>What "Trusted" Means</h2>
        <p>A trusted device is one you recognize and want on your network. When you trust a device:</p>
        <ul style="font-size:12px;padding-left:20px;margin-top:6px;line-height:1.8">
          <li>It's removed from the New Devices review queue</li>
          <li>If it was blocked, it's automatically unblocked on the controller</li>
          <li>It stays in your trusted list across restarts</li>
          <li>It won't be flagged by suspicious traffic analysis (but still monitored)</li>
        </ul>
      </div>

      <div class="card"><h2>Category Breakdown</h2>
        <div class="cat-grid">
          ${(() => {
            const cats = {};
            clients.forEach(c => { const k = c.category_label||"Unknown"; cats[k] = (cats[k]||0)+1; });
            return Object.entries(cats).sort((a,b)=>b[1]-a[1]).map(([cat,n]) =>
              `<div class="cat-item"><span class="cat-count">${n}</span><span class="cat-label">${cat}</span></div>`
            ).join("");
          })()}
        </div>
      </div>

      <div class="card"><h2>All Trusted (${clients.length})</h2>
        <table class="data-table"><thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>Category</th><th>SSID</th><th>TX/RX</th></tr></thead><tbody>
          ${clients.map(c => `<tr>
            <td class="mono">${c.mac}</td><td>${c.name||"—"}</td><td>${c.vendor||"?"}</td><td class="mono">${c.ip||"—"}</td>
            <td>${c.category_icon||""} ${c.category_label||""}</td><td>${c.essid||"—"}</td>
            <td>${this._fmtB(c.tx_bytes)}/${this._fmtB(c.rx_bytes)}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>`;
  }

  _vDetailThreats() {
    const o = this._overview;
    const suspDevices = o.suspicious_devices || [];
    const evts = []; // We'd need threat events from WS — for now show suspicious devices
    const cameras = (this._data.clients||[]).filter(c => c.is_camera);
    const blocked = (this._data.clients||[]).filter(c => c.blocked);

    return `
      <button class="btn-back" data-statview="overview">← Back to Overview</button>
      <h1>🐛 Threat Overview <span class="count">${o.threat_events||0} events</span></h1>
      <p class="subtitle">Security events, suspicious devices, and potential threats detected on your network.</p>

      <div class="stat-grid">
        ${this._stat("IDS/IPS Events", o.threat_events||0, "🛡", o.threat_events>0?"danger":"")}
        ${this._stat("Suspicious", o.suspicious_count||0, "⚠", o.suspicious_count>0?"danger":"")}
        ${this._stat("Cameras", cameras.length, "📹", cameras.length>0?"warn":"")}
        ${this._stat("Blocked", blocked.length, "🚫")}
      </div>

      <div class="card">
        <h2>What to Watch For</h2>
        <ul style="font-size:12px;padding-left:20px;line-height:2">
          <li><strong>IDS/IPS Events</strong> — The UCG Max's built-in intrusion detection has flagged traffic patterns that match known attack signatures</li>
          <li><strong>Suspicious Devices</strong> — Scored 3+ on our heuristic analysis: randomized MAC, unknown vendor, no hostname, camera phoning home, high bandwidth on guest network</li>
          <li><strong>Cameras on Main Network</strong> — IP cameras that aren't isolated to an IoT VLAN can be used as a pivot point to reach other devices</li>
          <li><strong>Devices Phoning Home</strong> — Cameras or IoT devices making outbound connections to cloud servers (ports 34567, 6789, 32100, etc.)</li>
        </ul>
      </div>

      <div class="card danger-card"><h2>⚠ Suspicious Devices (${suspDevices.length})</h2>
        ${suspDevices.length === 0 ? '<div class="empty">No suspicious devices — your network looks clean.</div>' : ''}
        ${suspDevices.slice(0,10).map((d,i) => {
          const flags = d.suspicion_flags||[];
          return `<div style="padding:8px 0;border-bottom:1px solid var(--divider-color,#2a2a4a)">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span class="mono" style="font-weight:600">${d.mac}</span>
              <span>${d.name||"—"}</span>
              <span style="color:var(--secondary-text-color)">${d.vendor||"?"}</span>
              <span class="badge ${d.threat_level}">${d.threat_level} (${d.suspicion_score}pts)</span>
              ${d.is_camera?'<span class="badge camera">📹</span>':""}
            </div>
            ${flags.length?`<div style="margin-top:4px;font-size:11px">${flags.map(f=>`<div>⚠ ${f}</div>`).join("")}</div>`:""}
          </div>`;
        }).join("")}
      </div>

      ${cameras.length?`<div class="card warn-card"><h2>📹 Cameras on Network (${cameras.length})</h2>
        <p class="subtitle">Every detected camera. Consider isolating these to a local-only subnet (192.168.2.x) to prevent phone-home traffic.</p>
        <table class="data-table"><thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>State</th><th>Blocked</th><th>TX/RX</th></tr></thead><tbody>
          ${cameras.map(c=>`<tr>
            <td class="mono">${c.mac}</td><td>${c.name||"—"}</td><td>${c.vendor||"?"}</td><td class="mono">${c.ip||"—"}</td>
            <td><span class="badge ${c.state}">${c.state}</span></td><td>${c.blocked?"🚫":""}</td>
            <td>${this._fmtB(c.tx_bytes)}/${this._fmtB(c.rx_bytes)}</td>
          </tr>`).join("")}
        </tbody></table>
      </div>`:""}

      <div class="card">
        <h2>Recommended Actions</h2>
        <ol style="font-size:12px;padding-left:20px;line-height:2">
          <li>Review all <strong>Suspicious</strong> devices — quarantine anything you don't recognize</li>
          <li>Move cameras to the <strong>Local-Only</strong> subnet (🔒 in sidebar) to block internet access</li>
          <li>Check the <strong>Port Guide</strong> (🔌 in sidebar) for phone-home port reference</li>
          <li>Enable IDS/IPS on the UCG Max if not already active (Network → Security → Threat Management)</li>
        </ol>
      </div>`;
  }

  _vDeviceList(devices, title, subtitle) {
    return `<h1>${title} <span class="count">${devices.length}</span></h1>
      <p class="subtitle">${subtitle}</p>
      ${devices.length===0?'<div class="empty">None.</div>':""}
      ${devices.map((d,i) => this._deviceCard(d, i+1)).join("")}`;
  }

  _vClients() {
    let clients = (this._data.clients || []).slice();
    if (this._filter) clients = clients.filter(c => [c.mac,c.name,c.hostname,c.vendor,c.ip,c.essid,c.state,c.category,c.category_label].filter(Boolean).join(" ").toLowerCase().includes(this._filter));
    const s = (col) => col===this._sortCol ? (this._sortAsc?" ▲":" ▼") : "";
    clients.sort((a,b) => { let va=a[this._sortCol]||"", vb=b[this._sortCol]||""; if(typeof va==="number"&&typeof vb==="number") return this._sortAsc?va-vb:vb-va; return this._sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va)); });

    return `<h1>All Clients <span class="count">${clients.length}</span></h1>
      <input type="text" id="clientFilter" class="filter-input" placeholder="Filter..." />
      <div class="table-wrap"><table class="data-table"><thead><tr>
        <th data-sort="category">Cat${s("category")}</th>
        <th data-sort="mac">MAC${s("mac")}</th>
        <th data-sort="name">Name${s("name")}</th>
        <th data-sort="vendor">Vendor${s("vendor")}</th>
        <th data-sort="ip">IP${s("ip")}</th>
        <th data-sort="state">State${s("state")}</th>
        <th data-sort="essid">SSID${s("essid")}</th>
        <th data-sort="threat_level">Threat${s("threat_level")}</th>
        ${this._actionMode?"<th>Actions</th>":""}
      </tr></thead><tbody>
        ${clients.map(c => `<tr class="${c.suspicious?"row-suspicious":""} ${c.is_camera?"row-camera":""}">
          <td>${c.category_icon||"❓"}</td>
          <td class="mono">${c.mac}</td>
          <td>${c.name||"—"}</td>
          <td>${c.vendor||"?"}</td>
          <td class="mono">${c.ip||"—"}</td>
          <td><span class="badge ${c.state}">${c.state}</span></td>
          <td>${c.essid||"—"}</td>
          <td>${c.threat_level!=="none"?`<span class="badge ${c.threat_level}">${c.threat_level}</span>`:""}</td>
          ${this._actionMode?`<td class="actions">${this._actBtns(c.mac)}</td>`:""}
        </tr>`).join("")}
      </tbody></table></div>`;
  }

  _vIdentify() {
    // Show devices that are "unknown" category or low confidence
    const clients = (this._data.clients || []).filter(c => c.category === "unknown" || c.confidence === "low");
    const catLabels = this._overview.category_labels || {};
    const catOptions = Object.entries(catLabels).map(([k,v]) => `<option value="${k}">${v}</option>`).join("");

    return `<h1>Identify Devices <span class="count">${clients.length}</span></h1>
      <p class="subtitle">Devices that need manual identification. Set their category and optionally rename them.</p>
      ${clients.length===0?'<div class="empty">All devices identified!</div>':""}
      ${clients.map((d, i) => {
        const mid = d.mac.replace(/:/g,"");
        return `<div class="device-card ${d.suspicious?"device-suspicious":""}">
          <div class="device-header">
            <span class="device-num">#${i+1}</span>
            <span class="device-mac mono">${d.mac}</span>
            <span class="badge ${d.category}">${d.category_icon||"❓"} ${d.category_label||"Unknown"}</span>
            ${d.confidence?`<span class="conf">${d.confidence} confidence</span>`:""}
          </div>
          <div class="device-body">
            <div class="device-info">
              <div class="info-row"><span class="info-label">Name</span><span>${d.name||"—"}</span></div>
              <div class="info-row"><span class="info-label">Hostname</span><span>${d.hostname||"—"}</span></div>
              <div class="info-row"><span class="info-label">Vendor</span><span>${d.vendor||"Unknown"}</span></div>
              <div class="info-row"><span class="info-label">IP</span><span class="mono">${d.ip||"—"}</span></div>
              <div class="info-row"><span class="info-label">SSID</span><span>${d.essid||"—"}</span></div>
              <div class="info-row"><span class="info-label">Wired</span><span>${d.wired?"Yes":"No"}</span></div>
              <div class="info-row"><span class="info-label">Signal</span><span>${d.rssi!=null?d.rssi+" dBm":"—"}</span></div>
              <div class="info-row"><span class="info-label">TX/RX</span><span>${this._fmtB(d.tx_bytes)} / ${this._fmtB(d.rx_bytes)}</span></div>
            </div>
            <div class="id-tool">
              <div class="id-title">Set Category:</div>
              <input type="text" id="name-${mid}" class="id-name" placeholder="Device name (optional)" value="${d.name||""}" />
              <div class="id-buttons">
                ${Object.entries(catLabels).map(([k,v]) => `<button class="btn btn-cat" data-setcat="${k}" data-mac="${d.mac}">${(this._overview.category_icons||{})[k]||""} ${v}</button>`).join("")}
              </div>
            </div>
          </div>
        </div>`;
      }).join("")}`;
  }

  _vCategory() {
    const cat = this._viewArg;
    const info = this._categories[cat] || {};

    // Try filtering from clients list first.
    let clients = (this._data.clients || []).filter(c => c.category === cat);

    // If no matches but category says it has items, the clients WS
    // might have failed or categories don't match. Fall back to
    // fetching from the category-specific endpoint.
    if (clients.length === 0 && info.count > 0) {
      // Show loading and fetch directly.
      if (!this._catCache) this._catCache = {};
      if (this._catCache[cat]) {
        clients = this._catCache[cat];
      } else {
        // Trigger async fetch.
        this._ws("unifiblocker/category_clients", { category: cat }).then(r => {
          if (r && r.clients) {
            this._catCache[cat] = r.clients;
            this._updateMain();
          }
        });
        return `<h1>${info.icon||""} ${info.label||cat} <span class="count">${info.count}</span></h1>
          <div class="loading">Loading ${info.label || cat} devices...</div>`;
      }
    }

    return `<h1>${info.icon||""} ${info.label||cat} <span class="count">${clients.length}</span></h1>
      ${clients.map((d,i) => this._deviceCard(d, i+1)).join("")}
      ${clients.length===0?'<div class="empty">No devices in this category.</div>':""}`;
  }

  _vNAS() {
    const clients = this._data.clients || [];
    const o = this._overview || {};
    const ln = this._localnet || {};
    const fw = ln.firewall || {};
    const assignments = ln.assignments || {};
    const assignedMacs = new Set(Object.keys(assignments));

    // Group devices by access level.
    const internetAccess = [];    // Normal DHCP, has internet
    const localOnly = [];         // On 192.168.2.x, no internet
    const blocked = [];           // Quarantined / blocked on controller
    const unreviewed = [];        // State=new, no decision yet

    clients.forEach(c => {
      if (c.blocked || c.state === "quarantined") blocked.push(c);
      else if (assignedMacs.has(c.mac.toLowerCase())) localOnly.push(c);
      else if (c.state === "new") unreviewed.push(c);
      else internetAccess.push(c);
    });

    // Cameras on main network (not local-only, not blocked).
    const camerasExposed = clients.filter(c =>
      c.is_camera && !assignedMacs.has(c.mac.toLowerCase()) && !c.blocked && c.state !== "quarantined"
    );

    // Risk summary.
    const risks = [];
    if (!fw.exists) risks.push({icon:"🔴", text:"Firewall rule for local-only subnet not created"});
    if (camerasExposed.length) risks.push({icon:"🟠", text:`${camerasExposed.length} camera(s) have unrestricted internet access`});
    if (unreviewed.length > 20) risks.push({icon:"🟡", text:`${unreviewed.length} devices haven't been reviewed yet`});
    const suspCount = clients.filter(c => c.suspicious).length;
    if (suspCount) risks.push({icon:"🟠", text:`${suspCount} device(s) flagged as suspicious`});

    return `
      <h1>🌐 Network Access Security</h1>
      <p class="subtitle">Complete view of which devices can reach the internet, which are local-only, and which are blocked.</p>

      ${risks.length ? `
        <div class="card danger-card">
          <h2>Action Required</h2>
          ${risks.map(r => `<div style="padding:4px 0;font-size:13px">${r.icon} ${r.text}</div>`).join("")}
        </div>
      ` : '<div class="card" style="border-color:#4caf50"><h2 style="color:#4caf50">✅ Network looks good</h2><p>No immediate access control issues found.</p></div>'}

      <div class="stat-grid">
        ${this._stat("Internet Access", internetAccess.length, "🌍", "", "detail_connected")}
        ${this._stat("Local Only", localOnly.length, "🔒")}
        ${this._stat("Blocked", blocked.length, "🚫")}
        ${this._stat("Unreviewed", unreviewed.length, "🆕", unreviewed.length > 10 ? "warn" : "", "new")}
        ${this._stat("Cameras Exposed", camerasExposed.length, "📹", camerasExposed.length > 0 ? "danger" : "")}
      </div>

      <div class="card">
        <h2>Firewall Status</h2>
        <table class="info-table">
          <tr><td>Local-Only Rule</td><td>${fw.exists ? (fw.enabled ? '<span class="badge ok">Active — 192.168.2.0/24 blocked from WAN</span>' : '<span class="badge warn">Exists but disabled</span>') : '<span class="badge danger">Not created</span>'}</td></tr>
        </table>
        ${!fw.exists && this._actionMode ? '<button class="btn btn-trust" data-ensureFw="1" style="margin-top:8px">Create Firewall Rule</button>' : ''}
        ${!fw.exists && !this._actionMode ? '<p style="margin-top:6px;font-size:11px;color:#f0a500">Enable Action Mode to create the rule</p>' : ''}
      </div>

      <div class="card">
        <h2>Access Level Summary</h2>
        <table class="data-table">
          <thead><tr><th>Level</th><th>Description</th><th>Devices</th><th>Risk</th></tr></thead>
          <tbody>
            <tr><td>🌍 Internet</td><td>Full network + internet access (normal DHCP)</td><td>${internetAccess.length}</td><td>${camerasExposed.length ? '<span class="badge warn">Cameras exposed</span>' : '<span class="badge ok">OK</span>'}</td></tr>
            <tr><td>🔒 Local Only</td><td>Network access but no internet (192.168.2.x)</td><td>${localOnly.length}</td><td><span class="badge ok">Isolated</span></td></tr>
            <tr><td>🚫 Blocked</td><td>Quarantined — no network access at all</td><td>${blocked.length}</td><td><span class="badge ok">Contained</span></td></tr>
            <tr><td>🆕 Unreviewed</td><td>Not yet classified — needs your decision</td><td>${unreviewed.length}</td><td>${unreviewed.length > 10 ? '<span class="badge warn">Review needed</span>' : '<span class="badge ok">OK</span>'}</td></tr>
          </tbody>
        </table>
      </div>

      ${camerasExposed.length ? `
        <div class="card warn-card">
          <h2>📹 Cameras With Internet Access (${camerasExposed.length})</h2>
          <p class="subtitle">These cameras can phone home to cloud servers. Move them to Local Only to block internet while keeping local streaming.</p>
          <table class="data-table">
            <thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>Threat</th>${this._actionMode ? '<th>Action</th>' : ''}</tr></thead>
            <tbody>
              ${camerasExposed.map(c => `<tr>
                <td class="mono">${c.mac}</td>
                <td>${c.name||"—"}</td>
                <td>${c.vendor||"?"}</td>
                <td class="mono">${c.ip||"—"}</td>
                <td>${c.threat_level !== "none" ? `<span class="badge ${c.threat_level}">${c.threat_level}</span>` : ""}</td>
                ${this._actionMode ? `<td>
                  <button class="btn btn-trust" data-localassign="${c.category||'camera'}" data-mac="${c.mac}" style="font-size:10px">🔒 Local Only</button>
                  <button class="btn btn-quarantine" data-action="quarantine" data-mac="${c.mac}" style="font-size:10px">🚫 Block</button>
                </td>` : ''}
              </tr>`).join("")}
            </tbody>
          </table>
        </div>
      ` : ''}

      <div class="card">
        <h2>🔒 Local Only Devices (${localOnly.length})</h2>
        ${localOnly.length === 0 ? '<div class="empty">No devices assigned to local-only yet. Use the Local Only view to assign devices.</div>' : `
          <table class="data-table">
            <thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>Category</th></tr></thead>
            <tbody>
              ${localOnly.map(c => {
                const a = assignments[c.mac.toLowerCase()] || {};
                return `<tr>
                  <td class="mono">${c.mac}</td>
                  <td>${c.name||"—"}</td>
                  <td>${c.vendor||"?"}</td>
                  <td class="mono">${a.ip || c.ip||"—"}</td>
                  <td>${c.category_icon||""} ${c.category_label||""}</td>
                </tr>`;
              }).join("")}
            </tbody>
          </table>
        `}
      </div>

      <div class="card">
        <h2>🚫 Blocked / Quarantined (${blocked.length})</h2>
        ${blocked.length === 0 ? '<div class="empty">No blocked devices.</div>' : `
          <table class="data-table">
            <thead><tr><th>MAC</th><th>Name</th><th>Vendor</th><th>IP</th><th>State</th>${this._actionMode ? '<th>Action</th>' : ''}</tr></thead>
            <tbody>
              ${blocked.map(c => `<tr>
                <td class="mono">${c.mac}</td>
                <td>${c.name||"—"}</td>
                <td>${c.vendor||"?"}</td>
                <td class="mono">${c.ip||"—"}</td>
                <td><span class="badge danger">${c.blocked ? "blocked" : c.state}</span></td>
                ${this._actionMode ? `<td>
                  <button class="btn btn-trust" data-action="trust" data-mac="${c.mac}" style="font-size:10px">✅ Trust</button>
                  <button class="btn btn-ignore" data-action="unblock" data-mac="${c.mac}" style="font-size:10px">Unblock</button>
                </td>` : ''}
              </tr>`).join("")}
            </tbody>
          </table>
        `}
      </div>

      <div class="card">
        <h2>How Network Access Levels Work</h2>
        <table class="data-table" style="font-size:12px">
          <thead><tr><th>Level</th><th>Internet</th><th>Local Network</th><th>How to Assign</th></tr></thead>
          <tbody>
            <tr><td>🌍 Internet (default)</td><td>✅ Yes</td><td>✅ Yes</td><td>Default for all DHCP devices (192.168.3.x)</td></tr>
            <tr><td>🔒 Local Only</td><td>🚫 No</td><td>✅ Yes</td><td>Assign in Local Only view → gets 192.168.2.x + firewall block</td></tr>
            <tr><td>🚫 Blocked</td><td>🚫 No</td><td>🚫 No</td><td>Quarantine or Block → controller rejects all connections</td></tr>
            <tr><td>✅ Trusted (reserved)</td><td>✅ Yes</td><td>✅ Yes</td><td>Trust + DHCP reservation in 192.168.1.x</td></tr>
          </tbody>
        </table>
        <p style="margin-top:10px;font-size:12px">
          <strong>Recommended workflow for cameras:</strong> Scan ports → review vendor/model → if it's a camera, move to <strong>Local Only</strong>.
          The camera keeps working for local RTSP/ONVIF streaming but can't phone home to Chinese cloud servers.
          If a device is actively malicious (backdoor ports, rogue DHCP), <strong>Block</strong> it entirely.
        </p>
      </div>

      ${!this._actionMode ? '<div class="ro-banner">Read-only mode — enable Action Mode in the sidebar to change device access levels</div>' : ''}`;
  }

  _vLocalNet() {
    const ln = this._localnet || {};
    const assignments = ln.assignments || {};
    const ranges = ln.ranges || [];
    const fw = ln.firewall || {};
    const assignArr = Object.entries(assignments);
    const catLabels = this._overview.category_labels || {};
    const catIcons = this._overview.category_icons || {};

    // Find devices that could be assigned (cameras, IoT, etc. that aren't already assigned)
    const assignedMacs = new Set(Object.keys(assignments));
    const candidates = (this._data.clients || []).filter(c => {
      const cat = c.category || "unknown";
      return !assignedMacs.has(c.mac.toLowerCase()) && cat !== "unknown" && c.state !== "quarantined";
    });

    return `<h1>🔒 Local-Only Network</h1>
      <p class="subtitle">Devices on 192.168.2.x have no internet access. They work locally only.</p>

      <div class="card ${fw.exists && fw.enabled ? '' : 'danger-card'}">
        <h2>Firewall Rule</h2>
        <table class="info-table">
          <tr><td>Status</td><td>${fw.exists ? (fw.enabled ? '<span class="badge ok">Active</span>' : '<span class="badge warn">Disabled</span>') : '<span class="badge danger">Not Created</span>'}</td></tr>
          <tr><td>Rule</td><td>${fw.name || FIREWALL_RULE_NAME || 'Block 192.168.2.0/24 → WAN'}</td></tr>
          ${fw.rule_id ? `<tr><td>Rule ID</td><td class="mono">${fw.rule_id}</td></tr>` : ''}
          ${fw.error ? `<tr><td>Error</td><td>${fw.error}</td></tr>` : ''}
        </table>
        ${!fw.exists && this._actionMode ? '<button class="btn btn-trust" data-ensureFw="1" style="margin-top:10px">Create Firewall Rule</button>' : ''}
        ${!fw.exists && !this._actionMode ? '<p style="margin-top:8px;font-size:11px;color:#f0a500">Enable Action Mode to create the firewall rule.</p>' : ''}
      </div>

      <div class="card">
        <h2>IP Range Allocation</h2>
        <table class="data-table"><thead><tr><th>Category</th><th>Range</th><th>Used</th><th>Available</th></tr></thead><tbody>
          ${ranges.map(r => `<tr>
            <td>${catIcons[r.category]||''} ${catLabels[r.category]||r.category}</td>
            <td class="mono">${r.range}</td>
            <td>${r.used}</td>
            <td>${r.available}</td>
          </tr>`).join('')}
        </tbody></table>
      </div>

      <div class="card">
        <h2>Current Assignments <span class="count">${assignArr.length}</span></h2>
        ${assignArr.length === 0 ? '<div class="empty">No local-only assignments yet.</div>' : `
          <table class="data-table"><thead><tr><th>MAC</th><th>IP</th><th>Category</th><th>Name</th>${this._actionMode?'<th>Remove</th>':''}</tr></thead><tbody>
            ${assignArr.map(([mac, info]) => `<tr>
              <td class="mono">${mac}</td>
              <td class="mono">${info.ip}</td>
              <td>${catIcons[info.category]||''} ${catLabels[info.category]||info.category}</td>
              <td>${info.name||'—'}</td>
              ${this._actionMode?`<td><button class="btn btn-quarantine" data-localremove="1" data-mac="${mac}">Remove</button></td>`:''}
            </tr>`).join('')}
          </tbody></table>
        `}
      </div>

      <div class="card">
        <h2>Assign Device to Local-Only</h2>
        <p class="subtitle">Pick a device and its category. An IP will be auto-assigned from the category range.</p>
        ${candidates.length === 0 ? '<div class="empty">No unassigned devices available.</div>' : `
          ${candidates.slice(0, 30).map(d => {
            const mid = d.mac.replace(/:/g,'');
            return `<div class="device-card" style="padding:10px;margin-bottom:6px">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                <span class="mono" style="font-weight:600">${d.mac}</span>
                <span>${d.name||d.hostname||'—'}</span>
                <span style="color:var(--secondary-text-color)">${d.vendor||'?'}</span>
                <span class="badge ${d.category}">${d.category_icon||''} ${d.category_label||''}</span>
                <span class="mono" style="color:var(--secondary-text-color)">${d.ip||''}</span>
              </div>
              ${this._actionMode ? `<div style="display:flex;gap:4px;margin-top:6px;flex-wrap:wrap;align-items:center">
                <input type="text" id="lname-${mid}" class="id-name" placeholder="Name (optional)" value="${d.name||''}" style="width:160px;padding:4px 6px;font-size:11px" />
                <button class="btn btn-trust" data-localassign="${d.category||'iot'}" data-mac="${d.mac}">Assign as ${d.category_label||'IoT'}</button>
              </div>` : '<div style="font-size:10px;color:var(--secondary-text-color);margin-top:4px">Enable Action Mode to assign</div>'}
            </div>`;
          }).join('')}
        `}
      </div>

      <div class="card">
        <h2>Setup Guide</h2>
        <p>This system manages the <strong>192.168.2.0/24</strong> subnet on your flat network.<br/>
        Devices assigned here get a DHCP reservation in the 192.168.2.x range and are blocked from WAN access by a firewall rule on the UCG Max.</p>
        <p style="margin-top:8px"><strong>How it works:</strong></p>
        <ol style="font-size:12px;padding-left:20px;margin-top:4px;line-height:1.8">
          <li>Click <strong>"Create Firewall Rule"</strong> to block 192.168.2.0/24 from internet</li>
          <li>Find a device in the list above and click <strong>"Assign"</strong></li>
          <li>The device gets a reserved IP in its category range (e.g. cameras → .30-.50)</li>
          <li>After the device renews its DHCP lease, it moves to the new IP</li>
          <li>The firewall rule ensures it can only talk locally — no internet</li>
        </ol>
        <p style="margin-top:8px;font-size:11px;color:var(--secondary-text-color)">
          IP ranges are configurable. Default layout: cameras .30-.50, ESPHome .51-.70, lights .71-.90, speakers .91-.100, IoT .101-.120, streaming .121-.130, printers .131-.140, gaming .141-.150, crypto .151-.160, NAS .161-.170, HA .171-.180, networking .181-.190, computers .191-.210, phones .211-.220, tablets .221-.230.
        </p>
      </div>`;
  }

  _vPorts() {
    return `<h1>Port & Protocol Guide</h1>
      <div class="card danger-card"><h2>📹 Camera Phone-Home (RED FLAG)</h2><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>Meaning</th></tr></thead><tbody>
        <tr class="row-danger"><td>34567</td><td>XMEye</td><td>Chinese DVR phoning home</td></tr>
        <tr class="row-danger"><td>34568</td><td>XMEye Media</td><td>DVR sending video to China</td></tr>
        <tr class="row-danger"><td>9530</td><td>Dahua</td><td>Dahua debug/backdoor</td></tr>
        <tr class="row-danger"><td>6789</td><td>P2P Cloud</td><td>Camera calling home</td></tr>
        <tr class="row-danger"><td>32100</td><td>Reolink P2P</td><td>Reolink cloud</td></tr>
        <tr class="row-danger"><td>19000</td><td>EZVIZ</td><td>EZVIZ/Hikvision cloud</td></tr>
      </tbody></table></div>
      <div class="card"><h2>📹 Camera Ports</h2><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>Meaning</th></tr></thead><tbody>
        <tr><td>554</td><td>RTSP</td><td>Live video stream</td></tr><tr><td>8000</td><td>Hikvision</td><td>SDK management</td></tr><tr><td>37777</td><td>Dahua</td><td>DVR connection</td></tr>
      </tbody></table></div>
      <div class="card warn-card"><h2>⚠ Risky</h2><table class="data-table"><thead><tr><th>Port</th><th>Protocol</th><th>Meaning</th></tr></thead><tbody>
        <tr class="row-warn"><td>23</td><td>Telnet</td><td>Insecure access — backdoor</td></tr><tr class="row-warn"><td>21</td><td>FTP</td><td>Insecure file transfer</td></tr><tr class="row-warn"><td>445</td><td>SMB</td><td>File sharing — lateral movement</td></tr><tr class="row-warn"><td>1900</td><td>UPnP</td><td>Auto-open firewall</td></tr>
      </tbody></table></div>`;
  }

  // ── Components ────────────────────────────────────────────────────
  _stat(l,v,i,t="",click="") { return `<div class="stat-card ${t} ${click?"clickable":""}" ${click?`data-statview="${click}"`:``}><div class="stat-icon">${i}</div><div class="stat-value">${v}</div><div class="stat-label">${l}</div></div>`; }

  _deviceCard(d, num) {
    const flags = d.suspicion_flags||[]; const dpi = d.dpi||{}; const cats = dpi.top_categories||[];
    const scan = this._scanCache[d.mac.toLowerCase()] || null;
    const mid = d.mac.replace(/:/g,"");

    let scanHtml = "";
    if (scan && scan.status === "complete") {
      const op = scan.open_ports || [];
      const pd = scan.port_details || [];
      const w = scan.warnings || [];
      const rec = scan.recommendations || [];
      scanHtml = `
        <div class="scan-result">
          <div class="scan-header">
            <span class="scan-title">🔍 Port Scan Results</span>
            <span class="badge ${scan.guess_risk==="critical"?"danger":scan.guess_risk==="high"?"danger":scan.guess_risk==="medium"?"medium":"ok"}">${scan.guess_risk} risk</span>
            <span class="badge ${scan.guess_category}">${scan.guess_category}</span>
            <span class="conf">${scan.guess_confidence} confidence</span>
          </div>
          <div class="scan-guess">${scan.guess_description}</div>
          <div class="scan-ports">
            <div class="scan-subtitle">${op.length} open port${op.length!==1?"s":""}</div>
            ${pd.length?`<table class="dpi-table">
              <tr><th>Port</th><th>Service</th><th>Type</th>${this._actionMode?"<th></th>":""}</tr>
              ${pd.map(p => `<tr class="${p.group.includes("insecure")||p.group.includes("backdoor")||p.group.includes("xmeye")?"row-danger":p.group.includes("cloud")?"row-warn":""}">
                <td>${p.port}</td><td>${p.name}</td><td>${p.group}</td>
                ${this._actionMode?`<td><button class="btn-port-block" data-blockport="${p.port}" data-blockmac="${d.mac}">Block</button></td>`:""}
              </tr>`).join("")}
            </table>`:"<div>No ports responded.</div>"}
          </div>
          ${w.length?`<div class="scan-warnings"><div class="flags-title">⚠ Warnings:</div>${w.map(x=>`<div class="flag-item" style="color:#e94560">🔴 ${x}</div>`).join("")}</div>`:""}
          ${rec.length?`<div class="scan-recs"><div class="scan-subtitle">Recommendations:</div>${rec.map(x=>`<div class="flag-item">💡 ${x}</div>`).join("")}</div>`:""}
        </div>`;
    }

    return `<div class="device-card ${d.suspicious?"device-suspicious":""} ${d.is_camera?"device-camera":""}">
      <div class="device-header">
        <span class="device-num">#${num}</span>
        <span class="device-mac mono">${d.mac}</span>
        <span class="badge ${d.category}">${d.category_icon||"❓"} ${d.category_label||""}</span>
        ${d.is_camera?'<span class="badge camera">📹 CAM</span>':""}
        ${d.suspicious?`<span class="badge ${d.threat_level}">${d.threat_level.toUpperCase()}</span>`:""}
        <span class="badge ${d.state}">${d.state}</span>
      </div>
      <div class="device-body">
        <div class="device-info">
          <div class="info-row"><span class="info-label">Name</span><span>${d.name||"—"}</span></div>
          <div class="info-row"><span class="info-label">Vendor</span><span>${d.vendor||"Unknown"}</span></div>
          <div class="info-row"><span class="info-label">IP</span><span class="mono">${d.ip||"—"}</span></div>
          <div class="info-row"><span class="info-label">SSID</span><span>${d.essid||"—"}</span></div>
          <div class="info-row"><span class="info-label">Signal</span><span>${d.rssi!=null?d.rssi+" dBm":"—"}</span></div>
          <div class="info-row"><span class="info-label">TX/RX</span><span>${this._fmtB(d.tx_bytes)} / ${this._fmtB(d.rx_bytes)}</span></div>
          ${d.onvif_manufacturer?`<div class="info-row"><span class="info-label">Make</span><span><strong>${d.onvif_manufacturer}</strong></span></div>`:""}
          ${d.onvif_model?`<div class="info-row"><span class="info-label">Model</span><span><strong>${d.onvif_model}</strong></span></div>`:""}
          ${d.onvif_firmware?`<div class="info-row"><span class="info-label">Firmware</span><span>${d.onvif_firmware}</span></div>`:""}
          ${d.onvif_serial?`<div class="info-row"><span class="info-label">Serial</span><span class="mono">${d.onvif_serial}</span></div>`:""}
        </div>
        ${d.onvif && d.onvif.onvif ? `<div class="onvif-badge"><span class="badge ok">ONVIF Confirmed</span> ${d.onvif.manufacturer||""} ${d.onvif.model||""}</div>` : ""}
        ${flags.length?`<div class="flags"><div class="flags-title">Flags:</div>${flags.map(f=>`<div class="flag-item">⚠ ${f}</div>`).join("")}</div>`:""}
        ${cats.length?`<div class="dpi"><div class="dpi-title">Traffic (DPI):</div><table class="dpi-table"><tr><th>Category</th><th>↓</th><th>↑</th></tr>${cats.map(c=>`<tr><td>${c.category}</td><td>${c.rx_mb}MB</td><td>${c.tx_mb}MB</td></tr>`).join("")}</table></div>`:""}
        <div id="scan-${mid}" class="scan-section">
          ${scanHtml || `<button class="btn btn-scan" data-scanmac="${d.mac}">🔍 Scan Ports</button>`}
        </div>
      </div>
      ${this._actionMode?`<div class="device-actions">${this._actBtns(d.mac, d.category)}</div>`:""}
    </div>`;
  }

  _actBtns(mac, cat) {
    const localBtn = `<button class="btn btn-local" data-localassign="${cat||'iot'}" data-mac="${mac}">🔒Local Only</button>`;
    return `<button class="btn btn-trust" data-action="trust" data-mac="${mac}">✅Trust</button><button class="btn btn-ignore" data-action="ignore" data-mac="${mac}">👁Ignore</button>${localBtn}<button class="btn btn-quarantine" data-action="quarantine" data-mac="${mac}">🚫Block</button>`;
  }
  _fmtB(b) { if(!b)return"0"; if(b>1e9)return(b/1e9).toFixed(1)+"GB"; if(b>1e6)return(b/1e6).toFixed(1)+"MB"; if(b>1e3)return(b/1e3).toFixed(1)+"KB"; return b+"B"; }
}

// ── CSS ─────────────────────────────────────────────────────────────
const CSS = `
:host{display:block;height:100%;font-family:var(--ha-card-header-font-family,"Segoe UI",Roboto,sans-serif)}
*{box-sizing:border-box;margin:0;padding:0}
.shell{display:flex;height:100%;background:var(--primary-background-color,#1a1a2e);color:var(--primary-text-color,#e0e0e0)}
.sidebar{width:230px;min-width:230px;background:var(--card-background-color,#16213e);border-right:1px solid var(--divider-color,#2a2a4a);display:flex;flex-direction:column}
.brand{padding:16px;text-align:center;border-bottom:1px solid var(--divider-color,#2a2a4a)}
.brand-icon{font-size:32px}.brand-text{font-size:15px;font-weight:700;margin-top:4px;color:var(--primary-color,#0f9b8e)}.brand-ver{font-size:10px;color:var(--secondary-text-color,#888)}
.nav-items{flex:1;padding:8px 0;overflow-y:auto}
.nav-item{display:flex;align-items:center;padding:9px 14px;cursor:pointer;transition:background .15s;border-left:3px solid transparent}
.nav-item:hover{background:rgba(255,255,255,.05)}.nav-item.active{background:rgba(15,155,142,.15);border-left-color:var(--primary-color,#0f9b8e)}
.nav-item.sub{padding-left:22px;font-size:12px}.nav-icon{font-size:16px;margin-right:8px;width:22px;text-align:center}.nav-label{font-size:13px;flex:1}
.nav-count{background:rgba(255,255,255,.1);padding:1px 6px;border-radius:8px;font-size:10px;margin-left:4px}
.nav-divider{padding:10px 14px 4px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--secondary-text-color,#666);border-top:1px solid var(--divider-color,#2a2a4a);margin-top:4px}
.action-toggle{padding:14px;border-top:1px solid var(--divider-color,#2a2a4a)}
.toggle-label{display:flex;align-items:center;cursor:pointer;gap:8px}.toggle-label input{display:none}
.toggle-switch{width:34px;height:18px;background:#444;border-radius:9px;position:relative;transition:background .2s}
.toggle-switch::after{content:"";width:14px;height:14px;background:#fff;border-radius:50%;position:absolute;top:2px;left:2px;transition:transform .2s}
.toggle-label input:checked+.toggle-switch{background:#e94560}.toggle-label input:checked+.toggle-switch::after{transform:translateX(16px)}
.toggle-text{font-size:11px;font-weight:600}.toggle-hint{font-size:10px;color:var(--secondary-text-color,#888);margin-top:3px;padding-left:42px}
.content{flex:1;padding:20px;overflow-y:auto}
h1{font-size:20px;font-weight:700;margin-bottom:6px}h1 .count{font-size:13px;background:var(--primary-color,#0f9b8e);color:#fff;padding:2px 7px;border-radius:9px;vertical-align:middle}
h2{font-size:15px;font-weight:600;margin-bottom:10px}.subtitle{color:var(--secondary-text-color,#888);font-size:12px;margin-bottom:14px}
.empty{padding:30px;text-align:center;color:var(--secondary-text-color,#888);font-size:13px}
.ro-banner{background:rgba(15,155,142,.1);border:1px solid var(--primary-color,#0f9b8e);border-radius:8px;padding:10px;margin-top:16px;font-size:12px;text-align:center}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.stat-card{background:var(--card-background-color,#16213e);border-radius:8px;padding:14px;text-align:center;border:1px solid var(--divider-color,#2a2a4a);transition:transform .15s,border-color .15s}
.stat-card.clickable{cursor:pointer}.stat-card.clickable:hover{transform:translateY(-2px);border-color:var(--primary-color,#0f9b8e)}
.btn-back{background:none;border:1px solid var(--divider-color,#2a2a4a);color:var(--primary-color,#0f9b8e);padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;margin-bottom:12px;transition:background .15s}.btn-back:hover{background:rgba(15,155,142,.1)}
.stat-card.warn{border-color:#f0a500}.stat-card.danger{border-color:#e94560}
.stat-icon{font-size:22px}.stat-value{font-size:26px;font-weight:700;margin:3px 0}.stat-card.warn .stat-value{color:#f0a500}.stat-card.danger .stat-value{color:#e94560}
.stat-label{font-size:11px;color:var(--secondary-text-color,#888);text-transform:uppercase;letter-spacing:.5px}
.card{background:var(--card-background-color,#16213e);border-radius:8px;padding:16px;margin-bottom:14px;border:1px solid var(--divider-color,#2a2a4a)}
.card p{font-size:12px;line-height:1.5;color:var(--secondary-text-color,#ccc)}.danger-card{border-color:#e94560}.warn-card{border-color:#f0a500}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px}
.cat-item{display:flex;flex-direction:column;align-items:center;padding:10px;background:rgba(255,255,255,.03);border-radius:6px;transition:transform .15s,border-color .15s;border:1px solid transparent}
.cat-item.clickable{cursor:pointer}.cat-item.clickable:hover{transform:translateY(-2px);border-color:var(--primary-color,#0f9b8e)}
.cat-icon{font-size:22px}.cat-count{font-size:18px;font-weight:700;margin:2px 0}.cat-label{font-size:10px;color:var(--secondary-text-color,#888);text-transform:uppercase}
.table-wrap{overflow-x:auto}
.data-table{width:100%;border-collapse:collapse;font-size:11px}
.data-table th{text-align:left;padding:7px 8px;background:rgba(255,255,255,.05);border-bottom:2px solid var(--divider-color,#2a2a4a);cursor:pointer;user-select:none;white-space:nowrap}
.data-table td{padding:6px 8px;border-bottom:1px solid var(--divider-color,#2a2a4a)}.data-table tbody tr:hover{background:rgba(255,255,255,.03)}
.row-suspicious{background:rgba(233,69,96,.08)!important}.row-camera{border-left:3px solid #f0a500}.row-danger td{color:#e94560}.row-warn td{color:#f0a500}
.info-table{width:100%}.info-table td{padding:5px 0;font-size:12px}.info-table td:first-child{color:var(--secondary-text-color,#888);width:100px}
.filter-input{width:100%;padding:7px 10px;margin-bottom:10px;border-radius:6px;border:1px solid var(--divider-color,#2a2a4a);background:var(--card-background-color,#16213e);color:var(--primary-text-color,#e0e0e0);font-size:12px;outline:none}
.filter-input:focus{border-color:var(--primary-color,#0f9b8e)}
.device-card{background:var(--card-background-color,#16213e);border-radius:8px;padding:14px;margin-bottom:10px;border:1px solid var(--divider-color,#2a2a4a)}
.device-suspicious{border-color:#e94560}.device-camera{border-left:4px solid #f0a500}
.device-header{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.device-num{font-weight:700;color:var(--secondary-text-color,#888);font-size:12px}.device-mac{font-size:13px;font-weight:600}
.device-body{display:grid;grid-template-columns:1fr 1fr;gap:12px}.device-info{display:flex;flex-direction:column;gap:3px}
.info-row{display:flex;font-size:11px}.info-label{color:var(--secondary-text-color,#888);width:60px;flex-shrink:0}
.flags{grid-column:1/-1}.flags-title{font-size:11px;font-weight:600;color:#f0a500;margin-bottom:3px}.flag-item{font-size:11px;padding:1px 0}
.dpi{grid-column:1/-1}.dpi-title{font-size:11px;font-weight:600;margin-bottom:3px}.dpi-table{width:100%;font-size:10px}.dpi-table th,.dpi-table td{padding:2px 5px}.dpi-table th{text-align:left}
.device-actions{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
.id-tool{grid-column:1/-1;background:rgba(255,255,255,.03);border-radius:6px;padding:10px;margin-top:6px}
.id-title{font-size:11px;font-weight:600;margin-bottom:6px;color:var(--primary-color,#0f9b8e)}
.id-name{width:100%;padding:6px 8px;margin-bottom:8px;border-radius:4px;border:1px solid var(--divider-color,#2a2a4a);background:var(--primary-background-color,#1a1a2e);color:var(--primary-text-color,#e0e0e0);font-size:12px}
.id-buttons{display:flex;flex-wrap:wrap;gap:4px}
.btn{padding:5px 10px;border-radius:5px;border:none;cursor:pointer;font-size:11px;font-weight:600;transition:opacity .15s}.btn:hover{opacity:.85}
.btn-trust{background:#4caf50;color:#fff}.btn-ignore{background:#607d8b;color:#fff}.btn-local{background:#0f9b8e;color:#fff}.btn-quarantine{background:#e94560;color:#fff}
.btn-cat{background:rgba(255,255,255,.1);color:var(--primary-text-color,#e0e0e0);font-size:10px;padding:4px 8px}
.btn-cat:hover{background:rgba(15,155,142,.3)}
.conf{font-size:10px;color:var(--secondary-text-color,#888);font-style:italic}
.badge{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase}
.badge.new{background:#0f9b8e33;color:#0f9b8e}.badge.trusted{background:#4caf5033;color:#4caf50}.badge.ignored{background:#9e9e9e33;color:#9e9e9e}
.badge.quarantined{background:#e9456033;color:#e94560}.badge.ok{background:#4caf5033;color:#4caf50}.badge.low{background:#f0a50033;color:#f0a500}
.badge.medium{background:#ff980033;color:#ff9800}.badge.high,.badge.danger{background:#e9456033;color:#e94560}.badge.camera{background:#f0a50033;color:#f0a500}
.badge.computer{background:#42a5f533;color:#42a5f5}.badge.phone{background:#ab47bc33;color:#ab47bc}.badge.esphome{background:#66bb6a33;color:#66bb6a}
.badge.led{background:#ffee5833;color:#fdd835}.badge.ha_device{background:#29b6f633;color:#29b6f6}.badge.smart_speaker{background:#ef535033;color:#ef5350}
.badge.streaming{background:#7e57c233;color:#7e57c2}.badge.gaming{background:#26a69a33;color:#26a69a}.badge.networking{background:#78909c33;color:#78909c}
.badge.crypto{background:#ff702033;color:#ff7020}.badge.iot{background:#8d6e6333;color:#8d6e63}.badge.nas{background:#5c6bc033;color:#5c6bc0}
.badge.printer{background:#a1887f33;color:#a1887f}.badge.tablet{background:#ce93d833;color:#ce93d8}.badge.unknown{background:#ffffff1a;color:#999}
.rec-item{padding:10px;margin-bottom:8px;border-radius:6px;border-left:4px solid var(--divider-color,#2a2a4a);background:rgba(255,255,255,.02)}
.rec-critical{border-left-color:#e94560;background:rgba(233,69,96,.05)}.rec-high{border-left-color:#ff9800;background:rgba(255,152,0,.05)}
.rec-medium{border-left-color:#f0a500;background:rgba(240,165,0,.03)}.rec-low{border-left-color:#4caf50}.rec-info{border-left-color:#42a5f5}
.rec-header{display:flex;gap:8px;align-items:center;margin-bottom:4px;flex-wrap:wrap}
.rec-priority{font-size:11px;font-weight:700}.rec-device{font-size:11px;color:var(--secondary-text-color,#888)}
.rec-name{font-size:11px;color:var(--secondary-text-color,#aaa)}.rec-title{font-size:13px;font-weight:600;margin-bottom:4px}
.rec-detail{font-size:11px;line-height:1.6;color:var(--secondary-text-color,#ccc)}.rec-actions{margin-top:6px;display:flex;gap:4px;flex-wrap:wrap}
.onvif-badge{grid-column:1/-1;font-size:11px;margin-top:4px}
.scan-section{grid-column:1/-1;margin-top:4px}
.scan-result{background:rgba(255,255,255,.03);border-radius:6px;padding:10px;border:1px solid var(--divider-color,#2a2a4a)}
.scan-header{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px}
.scan-title{font-size:12px;font-weight:700;color:var(--primary-color,#0f9b8e)}
.scan-guess{font-size:12px;margin-bottom:8px;padding:6px 8px;background:rgba(15,155,142,.08);border-radius:4px;line-height:1.5}
.scan-ports{margin-bottom:6px}.scan-subtitle{font-size:11px;font-weight:600;margin-bottom:4px}
.scan-warnings{margin-top:6px}.scan-recs{margin-top:6px}
.scan-loading{font-size:11px;color:var(--primary-color,#0f9b8e);padding:8px;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.btn-scan{background:rgba(15,155,142,.15);color:var(--primary-color,#0f9b8e);border:1px solid var(--primary-color,#0f9b8e);padding:5px 12px;border-radius:5px;cursor:pointer;font-size:11px;font-weight:600;transition:background .15s}
.btn-scan:hover{background:rgba(15,155,142,.3)}
.btn-port-block{background:rgba(233,69,96,.15);color:#e94560;border:1px solid #e9456066;padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;transition:background .15s}
.btn-port-block:hover{background:rgba(233,69,96,.3)}.btn-port-block:disabled{opacity:.5;cursor:default}
.mono{font-family:"Consolas","Monaco",monospace;font-size:11px}
@media(max-width:768px){.shell{flex-direction:column}.sidebar{width:100%;min-width:100%;flex-direction:row;border-right:none;border-bottom:1px solid var(--divider-color,#2a2a4a)}.brand{display:none}.nav-items{display:flex;overflow-x:auto;padding:0}.nav-item{padding:8px 12px;border-left:none;border-bottom:3px solid transparent;white-space:nowrap}.nav-item.active{border-bottom-color:var(--primary-color,#0f9b8e)}.nav-item.sub{padding-left:12px}.nav-divider{display:none}.action-toggle{padding:6px 10px;display:flex;align-items:center;gap:6px}.toggle-hint{display:none}.device-body{grid-template-columns:1fr}.stat-grid{grid-template-columns:repeat(3,1fr)}}
`;

// Guard against double-registration (HA can load the script multiple times).
if (!customElements.get("unifiblocker-panel")) {
  customElements.define("unifiblocker-panel", UniFiBlockerPanel);
}
