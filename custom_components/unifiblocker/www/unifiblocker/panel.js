/**
 * UniFi Blocker – Sidebar Panel v0.2.5
 *
 * Read-only by default. Action Mode toggle enables write operations.
 * Dynamic category sub-navigation when a category has 5+ devices.
 * Manual device identification tool for unknowns.
 */

const VERSION = "0.2.5";
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
    const [ov, cl, cats] = await Promise.all([
      this._ws("unifiblocker/overview"),
      this._ws("unifiblocker/clients"),
      this._ws("unifiblocker/categories"),
    ]);
    if (ov) this._overview = ov;
    if (cl) this._data = cl;
    if (cats) this._categories = cats.categories || {};
    this._render();
  }

  _startPolling() { this._stopPolling(); this._pollTimer = setInterval(() => this._fetchAll(), 30000); }
  _stopPolling() { if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; } }

  async _action(type, mac) { if (!this._actionMode) return; const r = await this._ws(type, { mac }); if (r && r.ok) setTimeout(() => this._fetchAll(), 800); }
  async _setCategory(mac, category, name) { const r = await this._ws("unifiblocker/set_category", { mac, category, name: name || undefined }); if (r && r.ok) setTimeout(() => this._fetchAll(), 800); }

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
            ${this._nav("identify", "Identify", "🔍")}
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
      case "new": mc.innerHTML = this._vDeviceList(this._overview.new_devices || [], "New / Unidentified Devices", "Devices that haven't been classified yet."); break;
      case "suspicious": mc.innerHTML = this._vDeviceList((this._overview.suspicious_devices || []).sort((a,b) => (b.suspicion_score||0)-(a.suspicion_score||0)), "Suspicious Traffic", "Devices scored 3+ on behavioral heuristics."); break;
      case "clients": mc.innerHTML = this._vClients(); break;
      case "identify": mc.innerHTML = this._vIdentify(); break;
      case "category": mc.innerHTML = this._vCategory(); break;
      case "quarantined": mc.innerHTML = this._vDeviceList((this._data.clients||[]).filter(c=>c.state==="quarantined"||c.blocked), "Quarantined / Blocked", "Devices blocked on the controller."); break;
      case "ports": mc.innerHTML = this._vPorts(); break;
    }
    this._bindActions(mc);
  }

  _bindActions(mc) {
    mc.querySelectorAll("[data-action]").forEach(btn => {
      btn.addEventListener("click", () => {
        if (!this._actionMode) { alert("Enable Action Mode first."); return; }
        if (confirm(`${btn.dataset.action} device ${btn.dataset.mac}?`)) this._action(`unifiblocker/${btn.dataset.action}`, btn.dataset.mac);
      });
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
        ${sorted.map(([cat, info]) => `<div class="cat-item"><span class="cat-icon">${info.icon}</span><span class="cat-count">${info.count}</span><span class="cat-label">${info.label}</span></div>`).join("")}
      </div></div>`;
    }
    return `
      <h1>Network Overview</h1>
      <div class="stat-grid">
        ${this._stat("Connected", o.total_clients||0, "📱")}
        ${this._stat("Wireless", o.wireless_count||0, "📶")}
        ${this._stat("Wired", o.wired_count||0, "🔗")}
        ${this._stat("New", o.new_count||0, "🆕", o.new_count>0?"warn":"")}
        ${this._stat("Suspicious", o.suspicious_count||0, "⚠", o.suspicious_count>0?"danger":"")}
        ${this._stat("Blocked", o.blocked_count||0, "🚫")}
        ${this._stat("Trusted", o.trusted_count||0, "✅")}
        ${this._stat("Threats", o.threat_events||0, "🐛", o.threat_events>0?"danger":"")}
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
    const clients = (this._data.clients || []).filter(c => c.category === cat);
    return `<h1>${info.icon||""} ${info.label||cat} <span class="count">${clients.length}</span></h1>
      ${clients.map((d,i) => this._deviceCard(d, i+1)).join("")}
      ${clients.length===0?'<div class="empty">No devices in this category.</div>':""}`;
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
  _stat(l,v,i,t="") { return `<div class="stat-card ${t}"><div class="stat-icon">${i}</div><div class="stat-value">${v}</div><div class="stat-label">${l}</div></div>`; }

  _deviceCard(d, num) {
    const flags = d.suspicion_flags||[]; const dpi = d.dpi||{}; const cats = dpi.top_categories||[];
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
        </div>
        ${flags.length?`<div class="flags"><div class="flags-title">Flags:</div>${flags.map(f=>`<div class="flag-item">⚠ ${f}</div>`).join("")}</div>`:""}
        ${cats.length?`<div class="dpi"><div class="dpi-title">Traffic (DPI):</div><table class="dpi-table"><tr><th>Category</th><th>↓</th><th>↑</th></tr>${cats.map(c=>`<tr><td>${c.category}</td><td>${c.rx_mb}MB</td><td>${c.tx_mb}MB</td></tr>`).join("")}</table></div>`:""}
      </div>
      ${this._actionMode?`<div class="device-actions">${this._actBtns(d.mac)}</div>`:""}
    </div>`;
  }

  _actBtns(mac) { return `<button class="btn btn-trust" data-action="trust" data-mac="${mac}">✅Trust</button><button class="btn btn-ignore" data-action="ignore" data-mac="${mac}">👁Ignore</button><button class="btn btn-quarantine" data-action="quarantine" data-mac="${mac}">🚫Block</button>`; }
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
.stat-card{background:var(--card-background-color,#16213e);border-radius:8px;padding:14px;text-align:center;border:1px solid var(--divider-color,#2a2a4a)}
.stat-card.warn{border-color:#f0a500}.stat-card.danger{border-color:#e94560}
.stat-icon{font-size:22px}.stat-value{font-size:26px;font-weight:700;margin:3px 0}.stat-card.warn .stat-value{color:#f0a500}.stat-card.danger .stat-value{color:#e94560}
.stat-label{font-size:11px;color:var(--secondary-text-color,#888);text-transform:uppercase;letter-spacing:.5px}
.card{background:var(--card-background-color,#16213e);border-radius:8px;padding:16px;margin-bottom:14px;border:1px solid var(--divider-color,#2a2a4a)}
.card p{font-size:12px;line-height:1.5;color:var(--secondary-text-color,#ccc)}.danger-card{border-color:#e94560}.warn-card{border-color:#f0a500}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px}
.cat-item{display:flex;flex-direction:column;align-items:center;padding:10px;background:rgba(255,255,255,.03);border-radius:6px}
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
.btn-trust{background:#4caf50;color:#fff}.btn-ignore{background:#607d8b;color:#fff}.btn-quarantine{background:#e94560;color:#fff}
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
.mono{font-family:"Consolas","Monaco",monospace;font-size:11px}
@media(max-width:768px){.shell{flex-direction:column}.sidebar{width:100%;min-width:100%;flex-direction:row;border-right:none;border-bottom:1px solid var(--divider-color,#2a2a4a)}.brand{display:none}.nav-items{display:flex;overflow-x:auto;padding:0}.nav-item{padding:8px 12px;border-left:none;border-bottom:3px solid transparent;white-space:nowrap}.nav-item.active{border-bottom-color:var(--primary-color,#0f9b8e)}.nav-item.sub{padding-left:12px}.nav-divider{display:none}.action-toggle{padding:6px 10px;display:flex;align-items:center;gap:6px}.toggle-hint{display:none}.device-body{grid-template-columns:1fr}.stat-grid{grid-template-columns:repeat(3,1fr)}}
`;

customElements.define("unifiblocker-panel", UniFiBlockerPanel);
