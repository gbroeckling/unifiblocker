import { LitElement, css, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { bytes, duration, name, plural } from "../format";
import { byPriority, categoryOptions, containmentBadge, recCard, sparkline, stateBadge, vulnBadge, type Ctx } from "../ui";
import type { Client } from "../types";

/** Slide-in drawer with everything about one device. */
@customElement("ub-device-detail")
export class UbDeviceDetail extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @property({ attribute: false }) client!: Client;
  @state() private scanning = false;
  @state() private newName = "";

  connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener("keydown", this.onKey);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    window.removeEventListener("keydown", this.onKey);
  }

  private onKey = (e: KeyboardEvent) => e.key === "Escape" && this.close();
  private close = () => this.dispatchEvent(new CustomEvent("close"));

  protected firstUpdated() {
    (this.renderRoot.querySelector(".close") as HTMLElement | null)?.focus();
  }

  private async scan() {
    this.scanning = true;
    await this.ctx.act("scan_device", { mac: this.client.mac }, { done: "Port scan finished" });
    this.scanning = false;
  }

  render() {
    const c = this.client;
    const { act, snap } = this.ctx;
    const n = name(c);
    const assigned = !!snap.localnet.assignments?.[c.mac.toLowerCase()];
    const recs = [...(snap.recs.device_recs?.[c.mac.toLowerCase()] || [])].sort(byPriority);
    return html`
      <div class="scrim" @click=${this.close}></div>
      <aside role="dialog" aria-modal="true" aria-label="Device ${n}">
        <header>
          <div style="flex:1;min-width:0">
            <h1>${c.category_icon} ${n}</h1>
            <div class="row small">${stateBadge(c)} ${containmentBadge(c)} ${vulnBadge(c)}
              ${c.suspicious ? html`<span class="badge warn">suspicious · ${c.suspicion_score}</span>` : nothing}
              <span class="mono muted">${c.mac}</span></div>
          </div>
          <button class="close btn" aria-label="Close" @click=${this.close}>✕</button>
        </header>

        <div class="actions row">
          ${c.state !== "trusted" ? html`<button class="btn" @click=${() => act("trust", { mac: c.mac }, { done: `${n} trusted` })}>Trust</button>` : nothing}
          ${c.state === "new" ? html`<button class="btn" @click=${() => act("ignore", { mac: c.mac }, { done: `${n} ignored` })}>Ignore</button>` : nothing}
          ${c.internet_blocked
            ? html`<button class="btn" @click=${() => act("allow_internet", { mac: c.mac }, { confirm: `Let ${n} reach the internet again?`, done: `${n} can reach the internet again` })}>Allow internet again</button>`
            : html`<button class="btn primary" @click=${() => act("block_internet", { mac: c.mac }, { confirm: `Block ${n} from the internet? It keeps its address and keeps working on your network.`, done: `${n} blocked from the internet` })}>Block internet</button>`}
          ${assigned
            ? html`<button class="btn" @click=${() => act("localnet_remove", { mac: c.mac }, { confirm: `Take ${n} off local-only? It gets internet access again.`, done: `${n} is no longer local-only` })}>Remove local-only</button>`
            : html`<button class="btn" @click=${() => act("localnet_assign", { mac: c.mac, category: c.category === "unknown" ? "iot" : c.category },
                { confirm: `Put ${n} on local-only? It gets a ${snap.localnet.prefix || "192.168.2"}.x address and is blocked from the internet, but keeps working on your network. It reconnects to pick up the new address.`, done: `${n} is now local-only` })}>Make local-only</button>`}
          ${c.state === "quarantined" || c.blocked
            ? html`<button class="btn" @click=${() => act("unblock", { mac: c.mac }, { done: `${n} unblocked` })}>Unblock</button>`
            : html`<button class="btn danger" @click=${() => act("quarantine", { mac: c.mac }, { confirm: `Quarantine ${n}? It's blocked on the controller and can't use the network at all.`, danger: true, done: `${n} quarantined` })}>Quarantine</button>`}
          <button class="btn" @click=${() => act("reconnect", { mac: c.mac }, { confirm: `Disconnect ${n} so it reconnects?`, done: "Reconnect sent" })}>Reconnect</button>
        </div>

        ${recs.length ? html`<section><h2>Recommendations</h2>${recs.map((r) => recCard(this.ctx, r, c.mac))}</section>` : nothing}

        <section>
          <h2>Internet</h2>
          ${this.internet(c)}
        </section>

        <section>
          <h2>Summary</h2>
          <div class="kv">
            <span>IP</span><span class="mono">${c.ip ? html`<a href="http://${c.ip}" target="_blank" rel="noopener noreferrer">${c.ip}</a>` : "—"}</span>
            <span>Maker</span><span>${c.vendor || "—"}</span>
            ${c.hostname && c.hostname !== c.name ? html`<span>Hostname</span><span>${c.hostname}</span>` : nothing}
            <span>Connection</span><span>${c.wired ? "wired" : `Wi-Fi${c.essid ? ` · ${c.essid}` : ""}${c.channel ? ` · ch ${c.channel}` : ""}${c.rssi != null ? ` · ${c.rssi} dBm` : ""}`}</span>
            <span>Uptime</span><span>${duration(c.uptime_seconds)}</span>
            <span>Total traffic</span><span>${bytes(c.tx_bytes)} / ${bytes(c.rx_bytes)}</span>
            ${c.unifi_fingerprint ? html`<span>UniFi ID</span><span>category ${c.unifi_fingerprint.dev_cat ?? "?"}${c.unifi_fingerprint.os_name ? `, ${c.unifi_fingerprint.os_name}` : ""}${c.unifi_fingerprint.camera ? html` <span class="badge info">camera</span>` : nothing}</span>` : nothing}
            ${c.home_automation ? html`<span>Home</span><span>${c.home_automation.brand || "unknown brand"} · ${c.home_automation.tier_label}</span>` : nothing}
          </div>
          ${c.home_automation?.local_option ? html`<p class="small" style="margin-top:8px">${c.home_automation.local_option}</p>` : nothing}
        </section>

        <section>
          <h2>Category</h2>
          <p class="small muted">${c.category_label} · ${c.confidence} confidence · from ${c.source}${c.manual_category ? " (set by hand)" : ""}</p>
          ${c.suggested_category && !c.manual_category ? html`<p class="small">Quantify suggests <strong>${c.suggested_category.category}</strong> (${c.suggested_category.confidence}).
            <button class="btn" @click=${() => act("set_category", { mac: c.mac, category: c.suggested_category!.category }, { done: "Category set" })}>Accept</button></p>` : nothing}
          <div class="row">
            <select aria-label="Category" id="cat">
              ${categoryOptions(snap).map(([k, v]) => html`<option value=${k} ?selected=${k === c.category}>${v}</option>`)}
            </select>
            <input type="text" placeholder="Rename (optional)" aria-label="New name" .value=${this.newName} @input=${(e: Event) => (this.newName = (e.target as HTMLInputElement).value)}>
            <button class="btn primary" @click=${() => act("set_category", { mac: c.mac, category: (this.renderRoot.querySelector("#cat") as HTMLSelectElement).value, ...(this.newName ? { name: this.newName } : {}) }, { done: "Saved" })}>Save</button>
            ${c.manual_category ? html`<button class="btn" @click=${() => act("clear_category", { mac: c.mac }, { done: "Back to automatic" })}>Clear override</button>` : nothing}
          </div>
        </section>

        ${c.vulns || c.onvif?.onvif || c.onvif_manufacturer ? html`<section>
          <h2>Firmware &amp; ONVIF</h2>
          ${c.onvif?.onvif ? html`<p class="small"><span class="badge ok">ONVIF</span> ${c.onvif.manufacturer} ${c.onvif.model}${c.onvif.auth_required ? html` <span class="badge">login needed</span>` : nothing}</p>` : nothing}
          <div class="kv">
            ${c.vulns?.family ? html`<span>Firmware by</span><span>${c.vulns.family}</span>` : nothing}
            <span>Firmware</span><span class="mono">${c.vulns?.firmware || c.onvif_firmware || "not reported"}</span>
            <span>Built</span><span>${c.vulns?.firmware_date ? `${c.vulns.firmware_date} (${c.vulns.firmware_age_years} years ago)` : "unknown"}</span>
            ${c.onvif_serial ? html`<span>Serial</span><span class="mono">${c.onvif_serial}</span>` : nothing}
          </div>
          ${(c.vulns?.findings || []).map((f) => html`<div class="rec ${f.status === "check" ? "high" : "critical"}">
            <div class="row"><span class="badge ${f.status === "check" ? "warn" : "bad"}">${f.status === "affected" ? "affected" : f.status === "likely" ? "probably affected" : "couldn't check"}</span>
              <span class="t">${f.cve}</span>${f.kev ? html`<span class="badge">exploited (CISA)</span>` : nothing}</div>
            <div class="d">${f.detail}</div><div class="small muted">${f.source}</div></div>`)}
        </section>` : nothing}

        <section>
          <div class="row"><h2 style="margin:0">Open ports</h2><span class="spacer"></span>
            <button class="btn" ?disabled=${this.scanning || !c.ip} @click=${() => this.scan()}>${this.scanning ? "Scanning…" : snap.scans[c.mac.toLowerCase()] ? "Scan again" : "Scan ports"}</button></div>
          ${this.ports(c)}
        </section>

        ${c.ip_history && c.ip_history.length > 1 ? html`<section><h2>IP history</h2>
          ${c.ip_history.map((h) => html`<div class="mono">${h.ip} <span class="muted">${h.type === "current" ? "now" : `until ${h.until} (${h.type})`}</span></div>`)}</section>` : nothing}

        ${c.suspicion_flags?.length ? html`<section><h2>Why it's flagged</h2><ul class="small">${c.suspicion_flags.map((f) => html`<li>${f}</li>`)}</ul></section>` : nothing}
      </aside>
    `;
  }

  private internet(c: Client) {
    const ph = c.phone_home;
    const span = ph?.window_minutes ? (ph.window_minutes < 120 ? `${ph.window_minutes} min` : `${Math.round(ph.window_minutes / 60)} h`) : "";
    return html`
      <div class="row small" style="margin-bottom:8px">
        ${sparkline(c.traffic_24h, 5, 32)}
        <span>${c.traffic_24h ? `${bytes(c.traffic_24h.reduce((a, b) => a + b, 0))} in the last 24 h` : "No traffic history yet"}</span>
        ${c.traffic_spike ? html`<span class="badge bad">spike: ${bytes(c.traffic_spike.last_hour_bytes)} last hour</span>` : nothing}
      </div>
      ${ph ? html`
        <p>${containmentBadge(c)} ${plural(ph.attempts, "connection attempt")}${span ? ` in ${span}` : ""}, ${ph.allowed ? html`<strong>${ph.allowed} let through</strong>` : "all blocked"}${ph.blocked_by_our_rule ? ` (${ph.blocked_by_our_rule} by its local-only rule)` : ""}.</p>
        ${Object.keys(ph.clouds).length ? html`<p class="small">Calls home to: <strong>${Object.keys(ph.clouds).join(", ")}</strong></p>` : nothing}
        ${ph.port_sweep ? html`<p class="small"><span class="badge warn">probing</span> tried ${ph.port_sweep.ports} ports on ${ph.port_sweep.host}</p>` : nothing}
        ${Object.keys(ph.dns_bypass).length ? html`<p class="small"><span class="badge warn">own DNS</span> ${Object.keys(ph.dns_bypass).join(", ")}</p>` : nothing}
        <div class="scroll"><table class="small"><thead><tr><th>Tries to reach</th><th>Port</th><th>Country</th><th>Times</th></tr></thead>
          <tbody>${ph.top_destinations.map((t) => html`<tr><td class="mono">${t.host}</td><td>${t.port ?? t.protocol}</td><td>${t.region || "—"}</td><td>${t.count}</td></tr>`)}</tbody></table></div>`
      : c.containment ? html`<p>${containmentBadge(c)} No connection attempts logged.</p>`
      : c.is_camera || c.home_automation?.tier === "cloud" || c.home_automation?.tier === "cloud_local"
        ? html`<p class="small muted">UniFi only logs blocked connections, so what this device reaches on the internet isn't visible. Block its internet to see what it tries.</p>`
        : nothing}
      ${c.security_events_24h ? html`<p class="small"><span class="badge warn">${plural(c.security_events_24h, "security event")}</span> in UniFi's log today.</p>` : nothing}
    `;
  }

  private ports(c: Client) {
    const s = this.ctx.snap.scans[c.mac.toLowerCase()];
    if (!s || s.status !== "complete") return html`<p class="small muted">Not scanned yet.</p>`;
    return html`
      <p class="small">${s.guess_description || ""} <span class="muted">(${s.guess_category}, ${s.guess_confidence} confidence${s.scan_time ? `, ${new Date(s.scan_time * 1000).toLocaleDateString()}` : ""})</span></p>
      ${s.port_details?.length ? html`<div class="row">${s.port_details.map((p) => html`<span class="badge ${/insecure|backdoor|xmeye/.test(p.group) ? "bad" : /cloud/.test(p.group) ? "warn" : ""}" title=${p.group}>${p.port} ${p.name}</span>`)}</div>` : html`<p class="small muted">No open ports.</p>`}
      ${(s.warnings || []).map((w) => html`<p class="small"><span class="badge bad">!</span> ${w}</p>`)}
    `;
  }

  static styles = [shared, css`
    .scrim { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.35); z-index: 5; }
    aside {
      position: fixed; z-index: 6; top: 0; right: 0; bottom: 0; width: min(640px, 100vw); overflow-y: auto;
      background: var(--primary-background-color); box-shadow: -8px 0 30px rgba(0, 0, 0, 0.25); padding: 20px; box-sizing: border-box;
    }
    header { display: flex; gap: 12px; align-items: flex-start; margin-bottom: 12px; }
    h1 { font-size: 20px; word-break: break-word; }
    .actions { margin-bottom: 16px; }
    section { background: var(--ub-card); border: 1px solid var(--ha-card-border-color, var(--ub-line)); border-radius: var(--ub-radius); padding: 14px; margin-bottom: 12px; }
    a { color: var(--primary-color); }
  `];
}
