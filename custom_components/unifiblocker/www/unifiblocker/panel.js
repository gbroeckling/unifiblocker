/**
 * UniFi Blocker – Sidebar Panel
 *
 * A custom Home Assistant panel for network device security.
 * Starts in READ-ONLY mode. Enable "Action Mode" to trust/block/quarantine.
 *
 * Architecture: vanilla Web Component, no framework dependencies.
 * Uses HA WebSocket API for real-time data.
 */

const VERSION = "0.1.0";

class UniFiBlockerPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._hass = null;
    this._config = {};
    this._view = "overview";
    this._actionMode = false;
    this._data = { clients: [] };
    this._overview = {};
    this._pollTimer = null;
    this._sortCol = "name";
    this._sortAsc = true;
    this._filter = "";
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._initialized) {
      this._initialized = true;
      this._render();
      this._fetchAll();
      this._startPolling();
    }
  }

  setConfig(config) {
    this._config = config || {};
  }

  connectedCallback() {
    if (this._hass) {
      this._render();
      this._fetchAll();
      this._startPolling();
    }
  }

  disconnectedCallback() {
    this._stopPolling();
  }

  // ── Data fetching ─────────────────────────────────────────────────

  async _ws(type, extra = {}) {
    if (!this._hass) return null;
    try {
      return await this._hass.callWS({ type, ...extra });
    } catch (e) {
      console.warn(`[UniFi Blocker] WS error (${type}):`, e);
      return null;
    }
  }

  async _fetchAll() {
    const [overview, clients] = await Promise.all([
      this._ws("unifiblocker/overview"),
      this._ws("unifiblocker/clients"),
    ]);
    if (overview) this._overview = overview;
    if (clients) this._data = clients;
    this._updateContent();
  }

  _startPolling() {
    this._stopPolling();
    this._pollTimer = setInterval(() => this._fetchAll(), 30000);
  }

  _stopPolling() {
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  }

  // ── Actions ───────────────────────────────────────────────────────

  async _action(type, mac) {
    if (!this._actionMode) return;
    const result = await this._ws(type, { mac });
    if (result && result.ok) {
      setTimeout(() => this._fetchAll(), 1000);
    }
  }

  // ── Rendering ─────────────────────────────────────────────────────

  _render() {
    this.shadowRoot.innerHTML = `
      <style>${this._css()}</style>
      <div class="shell">
        <nav class="sidebar">
          <div class="brand">
            <div class="brand-icon">🛡</div>
            <div class="brand-text">UniFi Blocker</div>
            <div class="brand-version">v${VERSION}</div>
          </div>
          <div class="nav-items">
            ${this._navItem("overview", "Overview", "📊")}
            ${this._navItem("new", "New Devices", "🆕")}
            ${this._navItem("suspicious", "Suspicious", "⚠")}
            ${this._navItem("clients", "All Clients", "📋")}
            ${this._navItem("quarantined", "Quarantined", "🚫")}
            ${this._navItem("ports", "Port Guide", "🔌")}
          </div>
          <div class="action-toggle">
            <label class="toggle-label">
              <input type="checkbox" id="actionToggle" />
              <span class="toggle-switch"></span>
              <span class="toggle-text">Action Mode</span>
            </label>
            <div class="toggle-hint" id="actionHint">Read-only</div>
          </div>
        </nav>
        <main class="content" id="mainContent">
          <div class="loading">Loading...</div>
        </main>
      </div>
    `;

    // Event listeners
    this.shadowRoot.querySelectorAll(".nav-item").forEach((el) => {
      el.addEventListener("click", () => {
        this._view = el.dataset.view;
        this._render();
        this._updateContent();
      });
    });

    const toggle = this.shadowRoot.getElementById("actionToggle");
    if (toggle) {
      toggle.checked = this._actionMode;
      toggle.addEventListener("change", (e) => {
        this._actionMode = e.target.checked;
        const hint = this.shadowRoot.getElementById("actionHint");
        if (hint) hint.textContent = this._actionMode ? "Actions enabled" : "Read-only";
        this._updateContent();
      });
    }

    this._updateContent();
  }

  _navItem(view, label, icon) {
    const active = this._view === view ? "active" : "";
    return `<div class="nav-item ${active}" data-view="${view}">
      <span class="nav-icon">${icon}</span>
      <span class="nav-label">${label}</span>
    </div>`;
  }

  _updateContent() {
    const main = this.shadowRoot.getElementById("mainContent");
    if (!main) return;

    switch (this._view) {
      case "overview":
        main.innerHTML = this._viewOverview();
        break;
      case "new":
        main.innerHTML = this._viewNew();
        break;
      case "suspicious":
        main.innerHTML = this._viewSuspicious();
        break;
      case "clients":
        main.innerHTML = this._viewClients();
        break;
      case "quarantined":
        main.innerHTML = this._viewQuarantined();
        break;
      case "ports":
        main.innerHTML = this._viewPorts();
        break;
    }

    // Bind action buttons
    main.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const action = btn.dataset.action;
        const mac = btn.dataset.mac;
        if (!this._actionMode) {
          alert("Enable Action Mode first (toggle in sidebar).");
          return;
        }
        if (confirm(`${action} device ${mac}?`)) {
          this._action(`unifiblocker/${action}`, mac);
        }
      });
    });

    // Bind filter
    const filterInput = main.querySelector("#clientFilter");
    if (filterInput) {
      filterInput.value = this._filter;
      filterInput.addEventListener("input", (e) => {
        this._filter = e.target.value.toLowerCase();
        this._updateContent();
      });
    }

    // Bind column sorting
    main.querySelectorAll("[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.dataset.sort;
        if (this._sortCol === col) this._sortAsc = !this._sortAsc;
        else { this._sortCol = col; this._sortAsc = true; }
        this._updateContent();
      });
    });
  }

  // ── Views ─────────────────────────────────────────────────────────

  _viewOverview() {
    const o = this._overview;
    const h = o.health || {};
    return `
      <h1>Network Overview</h1>
      <div class="stat-grid">
        ${this._statCard("Connected", o.total_clients || 0, "📱")}
        ${this._statCard("Wireless", o.wireless_count || 0, "📶")}
        ${this._statCard("Wired", o.wired_count || 0, "🔗")}
        ${this._statCard("New", o.new_count || 0, "🆕", o.new_count > 0 ? "warn" : "")}
        ${this._statCard("Suspicious", o.suspicious_count || 0, "⚠", o.suspicious_count > 0 ? "danger" : "")}
        ${this._statCard("Blocked", o.blocked_count || 0, "🚫")}
        ${this._statCard("Quarantined", o.quarantined_count || 0, "🛡")}
        ${this._statCard("Trusted", o.trusted_count || 0, "✅")}
        ${this._statCard("Threats", o.threat_events || 0, "🐛", o.threat_events > 0 ? "danger" : "")}
      </div>
      <div class="card">
        <h2>Controller</h2>
        <table class="info-table">
          <tr><td>Status</td><td>${h.connection_ok ? '<span class="badge ok">Connected</span>' : '<span class="badge danger">Disconnected</span>'}</td></tr>
          <tr><td>Hostname</td><td>${h.hostname || "—"}</td></tr>
          <tr><td>Firmware</td><td>${h.version || "—"}</td></tr>
          <tr><td>Uptime</td><td>${h.uptime ? (h.uptime / 3600).toFixed(1) + " hours" : "—"}</td></tr>
        </table>
      </div>
      ${this._actionMode ? "" : '<div class="read-only-banner">Read-only mode — enable Action Mode in the sidebar to manage devices</div>'}
    `;
  }

  _viewNew() {
    const devices = (this._overview.new_devices || []);
    return `
      <h1>New / Unidentified Devices <span class="count">${devices.length}</span></h1>
      <p class="subtitle">Devices that have connected but haven't been classified yet.</p>
      ${devices.length === 0 ? '<div class="empty">No new devices — all clients reviewed.</div>' : ""}
      ${devices.map((d, i) => this._deviceCard(d, i + 1, true)).join("")}
    `;
  }

  _viewSuspicious() {
    const devices = (this._overview.suspicious_devices || [])
      .sort((a, b) => (b.suspicion_score || 0) - (a.suspicion_score || 0));
    return `
      <h1>Suspicious Traffic <span class="count">${devices.length}</span></h1>
      <p class="subtitle">Devices scored 3+ on behavioral heuristics. Camera vendors, randomized MACs, high bandwidth, and phone-home traffic are flagged.</p>
      ${devices.length === 0 ? '<div class="empty">No suspicious devices detected.</div>' : ""}
      ${devices.map((d, i) => this._deviceCard(d, i + 1, true)).join("")}
    `;
  }

  _viewClients() {
    let clients = (this._data.clients || []).slice();

    // Filter
    if (this._filter) {
      clients = clients.filter((c) => {
        const text = [c.mac, c.name, c.hostname, c.vendor, c.ip, c.essid, c.state, c.threat_level]
          .filter(Boolean).join(" ").toLowerCase();
        return text.includes(this._filter);
      });
    }

    // Sort
    clients.sort((a, b) => {
      let va = a[this._sortCol] || "";
      let vb = b[this._sortCol] || "";
      if (typeof va === "number" && typeof vb === "number")
        return this._sortAsc ? va - vb : vb - va;
      va = String(va).toLowerCase();
      vb = String(vb).toLowerCase();
      return this._sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    });

    const arrow = this._sortAsc ? " ▲" : " ▼";
    const sh = (col) => col === this._sortCol ? arrow : "";

    return `
      <h1>All Connected Clients <span class="count">${clients.length}</span></h1>
      <input type="text" id="clientFilter" class="filter-input" placeholder="Filter by name, MAC, vendor, IP..." />
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th data-sort="mac">MAC${sh("mac")}</th>
              <th data-sort="name">Name${sh("name")}</th>
              <th data-sort="vendor">Vendor${sh("vendor")}</th>
              <th data-sort="ip">IP${sh("ip")}</th>
              <th data-sort="state">State${sh("state")}</th>
              <th data-sort="essid">SSID${sh("essid")}</th>
              <th data-sort="rssi">RSSI${sh("rssi")}</th>
              <th>Cam</th>
              <th data-sort="threat_level">Threat${sh("threat_level")}</th>
              ${this._actionMode ? "<th>Actions</th>" : ""}
            </tr>
          </thead>
          <tbody>
            ${clients.map((c) => `
              <tr class="${c.suspicious ? "row-suspicious" : ""} ${c.is_camera ? "row-camera" : ""}">
                <td class="mono">${c.mac}</td>
                <td>${c.name || "—"}</td>
                <td>${c.vendor || "?"}</td>
                <td class="mono">${c.ip || "—"}</td>
                <td><span class="badge ${c.state}">${c.state}</span></td>
                <td>${c.essid || "—"}</td>
                <td>${c.rssi != null ? c.rssi : "—"}</td>
                <td>${c.is_camera ? "📹" : ""}</td>
                <td>${c.threat_level !== "none" ? `<span class="badge ${c.threat_level}">${c.threat_level}</span>` : ""}</td>
                ${this._actionMode ? `<td class="actions">${this._actionButtons(c.mac)}</td>` : ""}
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  _viewQuarantined() {
    const clients = (this._data.clients || []).filter(
      (c) => c.state === "quarantined" || c.blocked
    );
    return `
      <h1>Quarantined / Blocked <span class="count">${clients.length}</span></h1>
      ${clients.length === 0 ? '<div class="empty">No quarantined devices.</div>' : ""}
      ${clients.map((d, i) => this._deviceCard(d, i + 1, false)).join("")}
    `;
  }

  _viewPorts() {
    return `
      <h1>Port & Protocol Guide</h1>
      <p class="subtitle">What common ports mean when you see a device using them.</p>

      <div class="card danger-card">
        <h2>📹 Camera Phone-Home Ports (RED FLAG)</h2>
        <table class="data-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>What It Means</th></tr></thead>
          <tbody>
            <tr class="row-danger"><td>34567</td><td>XMEye</td><td>Chinese DVR phoning home to cloud servers</td></tr>
            <tr class="row-danger"><td>34568</td><td>XMEye Media</td><td>DVR sending video data to China</td></tr>
            <tr class="row-danger"><td>9530</td><td>Dahua Debug</td><td>Dahua debug/backdoor port</td></tr>
            <tr class="row-danger"><td>6789</td><td>P2P Cloud</td><td>P2P cloud relay — camera calling home</td></tr>
            <tr class="row-danger"><td>32100</td><td>Reolink P2P</td><td>Reolink P2P cloud connection</td></tr>
            <tr class="row-danger"><td>19000</td><td>EZVIZ P2P</td><td>EZVIZ/Hikvision cloud relay</td></tr>
            <tr class="row-danger"><td>8800</td><td>Cloud Relay</td><td>Generic cloud callback service</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>📹 Normal Camera Ports</h2>
        <table class="data-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>What It Means</th></tr></thead>
          <tbody>
            <tr><td>554</td><td>RTSP</td><td>Live video stream (local viewing — normal)</td></tr>
            <tr><td>1935</td><td>RTMP</td><td>Live video push (often to cloud)</td></tr>
            <tr><td>8000</td><td>Hikvision</td><td>Hikvision SDK management</td></tr>
            <tr><td>37777</td><td>Dahua TCP</td><td>Dahua DVR/NVR connection</td></tr>
            <tr><td>9527</td><td>Hikvision SDK</td><td>Camera control port</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card warn-card">
        <h2>⚠ Risky Ports</h2>
        <table class="data-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>What It Means</th></tr></thead>
          <tbody>
            <tr class="row-warn"><td>23</td><td>Telnet</td><td>Insecure remote access — often a backdoor</td></tr>
            <tr class="row-warn"><td>2323</td><td>Telnet-alt</td><td>Alternate telnet — IoT malware target</td></tr>
            <tr class="row-warn"><td>21</td><td>FTP</td><td>Insecure file transfer — data exfiltration</td></tr>
            <tr class="row-warn"><td>25</td><td>SMTP</td><td>Email sending — could be spam relay</td></tr>
            <tr class="row-warn"><td>445</td><td>SMB</td><td>Windows file sharing — lateral movement</td></tr>
            <tr class="row-warn"><td>1900</td><td>UPnP</td><td>Can auto-open firewall holes</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>✅ Normal Ports</h2>
        <table class="data-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>What It Means</th></tr></thead>
          <tbody>
            <tr><td>53</td><td>DNS</td><td>Name resolution</td></tr>
            <tr><td>80</td><td>HTTP</td><td>Web traffic</td></tr>
            <tr><td>443</td><td>HTTPS</td><td>Encrypted web traffic</td></tr>
            <tr><td>123</td><td>NTP</td><td>Time sync</td></tr>
            <tr><td>5353</td><td>mDNS</td><td>Local device discovery</td></tr>
            <tr><td>22</td><td>SSH</td><td>Secure remote management</td></tr>
            <tr><td>1883</td><td>MQTT</td><td>IoT messaging</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>💡 Recommendation</h2>
        <p>If you see cameras hitting ports <strong>34567, 34568, 6789, 9530, 32100, or 19000</strong> — they're phoning home. <strong>Quarantine them</strong> and isolate all cameras to a dedicated VLAN with no WAN access.</p>
      </div>
    `;
  }

  // ── Components ────────────────────────────────────────────────────

  _statCard(label, value, icon, type = "") {
    return `<div class="stat-card ${type}">
      <div class="stat-icon">${icon}</div>
      <div class="stat-value">${value}</div>
      <div class="stat-label">${label}</div>
    </div>`;
  }

  _deviceCard(d, num, showActions) {
    const flags = (d.suspicion_flags || []);
    const dpi = d.dpi || {};
    const cats = dpi.top_categories || [];
    const dpiFlags = dpi.flags || [];

    return `
      <div class="device-card ${d.suspicious ? "device-suspicious" : ""} ${d.is_camera ? "device-camera" : ""}">
        <div class="device-header">
          <span class="device-num">#${num}</span>
          <span class="device-mac mono">${d.mac}</span>
          ${d.is_camera ? '<span class="badge camera">📹 CAMERA</span>' : ""}
          ${d.suspicious ? `<span class="badge ${d.threat_level}">${d.threat_level.toUpperCase()}</span>` : ""}
          <span class="badge ${d.state}">${d.state}</span>
        </div>
        <div class="device-body">
          <div class="device-info">
            <div class="info-row"><span class="info-label">Name</span><span>${d.name || "—"}</span></div>
            <div class="info-row"><span class="info-label">Vendor</span><span>${d.vendor || "Unknown"}</span></div>
            <div class="info-row"><span class="info-label">IP</span><span class="mono">${d.ip || "—"}</span></div>
            <div class="info-row"><span class="info-label">SSID</span><span>${d.essid || "—"}</span></div>
            <div class="info-row"><span class="info-label">Signal</span><span>${d.rssi != null ? d.rssi + " dBm" : "—"}</span></div>
            <div class="info-row"><span class="info-label">Wired</span><span>${d.wired ? "Yes" : "No"}</span></div>
            <div class="info-row"><span class="info-label">TX/RX</span><span>${this._fmtBytes(d.tx_bytes)} / ${this._fmtBytes(d.rx_bytes)}</span></div>
          </div>
          ${flags.length > 0 ? `
            <div class="flags">
              <div class="flags-title">Suspicion flags:</div>
              ${flags.map((f) => `<div class="flag-item">⚠ ${f}</div>`).join("")}
            </div>
          ` : ""}
          ${cats.length > 0 ? `
            <div class="dpi">
              <div class="dpi-title">Traffic (DPI):</div>
              <table class="dpi-table">
                <tr><th>Category</th><th>Down</th><th>Up</th></tr>
                ${cats.map((c) => `<tr><td>${c.category}</td><td>${c.rx_mb} MB</td><td>${c.tx_mb} MB</td></tr>`).join("")}
              </table>
            </div>
          ` : ""}
          ${dpiFlags.length > 0 ? `
            <div class="flags">
              <div class="flags-title">DPI warnings:</div>
              ${dpiFlags.map((f) => `<div class="flag-item">🔴 ${f}</div>`).join("")}
            </div>
          ` : ""}
        </div>
        ${showActions && this._actionMode ? `
          <div class="device-actions">
            ${this._actionButtons(d.mac)}
          </div>
        ` : ""}
      </div>
    `;
  }

  _actionButtons(mac) {
    return `
      <button class="btn btn-trust" data-action="trust" data-mac="${mac}">✅ Trust</button>
      <button class="btn btn-ignore" data-action="ignore" data-mac="${mac}">👁 Ignore</button>
      <button class="btn btn-quarantine" data-action="quarantine" data-mac="${mac}">🚫 Quarantine</button>
    `;
  }

  _fmtBytes(b) {
    if (!b) return "0";
    if (b > 1_000_000_000) return (b / 1_000_000_000).toFixed(1) + " GB";
    if (b > 1_000_000) return (b / 1_000_000).toFixed(1) + " MB";
    if (b > 1_000) return (b / 1_000).toFixed(1) + " KB";
    return b + " B";
  }

  // ── CSS ───────────────────────────────────────────────────────────

  _css() {
    return `
      :host { display: block; height: 100%; font-family: var(--ha-card-header-font-family, "Segoe UI", Roboto, sans-serif); }

      * { box-sizing: border-box; margin: 0; padding: 0; }

      .shell { display: flex; height: 100%; background: var(--primary-background-color, #1a1a2e); color: var(--primary-text-color, #e0e0e0); }

      /* ── Sidebar nav ──────────────────────────────────────────── */
      .sidebar { width: 220px; min-width: 220px; background: var(--card-background-color, #16213e); border-right: 1px solid var(--divider-color, #2a2a4a); display: flex; flex-direction: column; }

      .brand { padding: 20px 16px; text-align: center; border-bottom: 1px solid var(--divider-color, #2a2a4a); }
      .brand-icon { font-size: 36px; }
      .brand-text { font-size: 16px; font-weight: 700; margin-top: 6px; color: var(--primary-color, #0f9b8e); }
      .brand-version { font-size: 11px; color: var(--secondary-text-color, #888); margin-top: 2px; }

      .nav-items { flex: 1; padding: 12px 0; overflow-y: auto; }
      .nav-item { display: flex; align-items: center; padding: 10px 16px; cursor: pointer; transition: background 0.15s; border-left: 3px solid transparent; }
      .nav-item:hover { background: rgba(255,255,255,0.05); }
      .nav-item.active { background: rgba(15,155,142,0.15); border-left-color: var(--primary-color, #0f9b8e); }
      .nav-icon { font-size: 18px; margin-right: 10px; width: 24px; text-align: center; }
      .nav-label { font-size: 13px; }

      .action-toggle { padding: 16px; border-top: 1px solid var(--divider-color, #2a2a4a); }
      .toggle-label { display: flex; align-items: center; cursor: pointer; gap: 8px; }
      .toggle-label input { display: none; }
      .toggle-switch { width: 36px; height: 20px; background: #444; border-radius: 10px; position: relative; transition: background 0.2s; }
      .toggle-switch::after { content: ""; width: 16px; height: 16px; background: #fff; border-radius: 50%; position: absolute; top: 2px; left: 2px; transition: transform 0.2s; }
      .toggle-label input:checked + .toggle-switch { background: #e94560; }
      .toggle-label input:checked + .toggle-switch::after { transform: translateX(16px); }
      .toggle-text { font-size: 12px; font-weight: 600; }
      .toggle-hint { font-size: 11px; color: var(--secondary-text-color, #888); margin-top: 4px; padding-left: 44px; }

      /* ── Main content ─────────────────────────────────────────── */
      .content { flex: 1; padding: 24px; overflow-y: auto; }

      h1 { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
      h1 .count { font-size: 14px; background: var(--primary-color, #0f9b8e); color: #fff; padding: 2px 8px; border-radius: 10px; vertical-align: middle; }
      h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; }
      .subtitle { color: var(--secondary-text-color, #888); font-size: 13px; margin-bottom: 16px; }
      .empty { padding: 40px; text-align: center; color: var(--secondary-text-color, #888); font-size: 14px; }

      .read-only-banner { background: rgba(15,155,142,0.1); border: 1px solid var(--primary-color, #0f9b8e); border-radius: 8px; padding: 12px 16px; margin-top: 20px; font-size: 13px; text-align: center; }

      /* ── Stat cards ────────────────────────────────────────────── */
      .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 12px; margin-bottom: 20px; }
      .stat-card { background: var(--card-background-color, #16213e); border-radius: 10px; padding: 16px; text-align: center; border: 1px solid var(--divider-color, #2a2a4a); }
      .stat-card.warn { border-color: #f0a500; }
      .stat-card.danger { border-color: #e94560; }
      .stat-icon { font-size: 24px; }
      .stat-value { font-size: 28px; font-weight: 700; margin: 4px 0; }
      .stat-card.warn .stat-value { color: #f0a500; }
      .stat-card.danger .stat-value { color: #e94560; }
      .stat-label { font-size: 12px; color: var(--secondary-text-color, #888); text-transform: uppercase; letter-spacing: 0.5px; }

      /* ── Cards ─────────────────────────────────────────────────── */
      .card { background: var(--card-background-color, #16213e); border-radius: 10px; padding: 20px; margin-bottom: 16px; border: 1px solid var(--divider-color, #2a2a4a); }
      .card p { font-size: 13px; line-height: 1.6; color: var(--secondary-text-color, #ccc); }
      .danger-card { border-color: #e94560; }
      .warn-card { border-color: #f0a500; }

      /* ── Tables ────────────────────────────────────────────────── */
      .table-wrap { overflow-x: auto; }
      .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
      .data-table th { text-align: left; padding: 8px 10px; background: rgba(255,255,255,0.05); border-bottom: 2px solid var(--divider-color, #2a2a4a); cursor: pointer; user-select: none; white-space: nowrap; }
      .data-table td { padding: 7px 10px; border-bottom: 1px solid var(--divider-color, #2a2a4a); }
      .data-table tbody tr:hover { background: rgba(255,255,255,0.03); }
      .row-suspicious { background: rgba(233,69,96,0.08) !important; }
      .row-camera { border-left: 3px solid #f0a500; }
      .row-danger td { color: #e94560; }
      .row-warn td { color: #f0a500; }

      .info-table { width: 100%; }
      .info-table td { padding: 6px 0; font-size: 13px; }
      .info-table td:first-child { color: var(--secondary-text-color, #888); width: 120px; }

      .filter-input { width: 100%; padding: 8px 12px; margin-bottom: 12px; border-radius: 6px; border: 1px solid var(--divider-color, #2a2a4a); background: var(--card-background-color, #16213e); color: var(--primary-text-color, #e0e0e0); font-size: 13px; outline: none; }
      .filter-input:focus { border-color: var(--primary-color, #0f9b8e); }

      /* ── Device cards ──────────────────────────────────────────── */
      .device-card { background: var(--card-background-color, #16213e); border-radius: 10px; padding: 16px; margin-bottom: 12px; border: 1px solid var(--divider-color, #2a2a4a); }
      .device-suspicious { border-color: #e94560; }
      .device-camera { border-left: 4px solid #f0a500; }
      .device-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
      .device-num { font-weight: 700; color: var(--secondary-text-color, #888); }
      .device-mac { font-size: 14px; font-weight: 600; }
      .device-body { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
      .device-info { display: flex; flex-direction: column; gap: 4px; }
      .info-row { display: flex; font-size: 12px; }
      .info-label { color: var(--secondary-text-color, #888); width: 70px; flex-shrink: 0; }
      .flags { grid-column: 1 / -1; }
      .flags-title { font-size: 12px; font-weight: 600; color: #f0a500; margin-bottom: 4px; }
      .flag-item { font-size: 12px; padding: 2px 0; }
      .dpi { grid-column: 1 / -1; }
      .dpi-title { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
      .dpi-table { width: 100%; font-size: 11px; }
      .dpi-table th, .dpi-table td { padding: 3px 6px; }
      .dpi-table th { text-align: left; }

      .device-actions { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }

      /* ── Badges ────────────────────────────────────────────────── */
      .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
      .badge.new { background: #0f9b8e33; color: #0f9b8e; }
      .badge.trusted { background: #4caf5033; color: #4caf50; }
      .badge.ignored { background: #9e9e9e33; color: #9e9e9e; }
      .badge.quarantined { background: #e9456033; color: #e94560; }
      .badge.ok { background: #4caf5033; color: #4caf50; }
      .badge.low { background: #f0a50033; color: #f0a500; }
      .badge.medium { background: #ff980033; color: #ff9800; }
      .badge.high { background: #e9456033; color: #e94560; }
      .badge.danger { background: #e9456033; color: #e94560; }
      .badge.camera { background: #f0a50033; color: #f0a500; }

      /* ── Buttons ───────────────────────────────────────────────── */
      .btn { padding: 6px 14px; border-radius: 6px; border: none; cursor: pointer; font-size: 12px; font-weight: 600; transition: opacity 0.15s; }
      .btn:hover { opacity: 0.85; }
      .btn-trust { background: #4caf50; color: #fff; }
      .btn-ignore { background: #607d8b; color: #fff; }
      .btn-quarantine { background: #e94560; color: #fff; }

      .mono { font-family: "Consolas", "Monaco", monospace; font-size: 12px; }

      .loading { padding: 60px; text-align: center; color: var(--secondary-text-color, #888); }

      /* ── Responsive ────────────────────────────────────────────── */
      @media (max-width: 768px) {
        .shell { flex-direction: column; }
        .sidebar { width: 100%; min-width: 100%; flex-direction: row; border-right: none; border-bottom: 1px solid var(--divider-color, #2a2a4a); }
        .brand { display: none; }
        .nav-items { display: flex; overflow-x: auto; padding: 0; }
        .nav-item { padding: 10px 14px; border-left: none; border-bottom: 3px solid transparent; white-space: nowrap; }
        .nav-item.active { border-bottom-color: var(--primary-color, #0f9b8e); }
        .action-toggle { padding: 8px 12px; display: flex; align-items: center; gap: 8px; }
        .toggle-hint { display: none; }
        .device-body { grid-template-columns: 1fr; }
        .stat-grid { grid-template-columns: repeat(3, 1fr); }
      }
    `;
  }
}

customElements.define("unifiblocker-panel", UniFiBlockerPanel);
