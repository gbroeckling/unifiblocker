import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { bytes, name } from "../format";
import { categoryOptions, containmentBadge, sparkline, stateBadge, vulnBadge, type Ctx } from "../ui";
import type { Client } from "../types";

const FILTERS: [string, string, (c: Client) => boolean][] = [
  ["all", "All", () => true],
  ["new", "To review", (c) => c.state === "new"],
  ["unknown", "Not identified", (c) => c.category === "unknown" || c.confidence === "low"],
  ["suspicious", "Suspicious", (c) => c.suspicious],
  ["cameras", "Cameras", (c) => c.is_camera],
  ["home", "Home automation", (c) => !!c.home_automation],
  ["contained", "Off the internet", (c) => !!c.containment],
  ["blocked", "Blocked", (c) => c.blocked || c.state === "quarantined"],
  ["trusted", "Trusted", (c) => c.state === "trusted"],
  ["wireless", "Wi-Fi", (c) => !c.wired],
  ["wired", "Wired", (c) => c.wired],
];

type Col = "name" | "category" | "ip" | "vendor" | "state" | "traffic" | "signal";
const traffic = (c: Client) => (c.traffic_24h || []).reduce((a, b) => a + b, 0) || (c.tx_bytes || 0) + (c.rx_bytes || 0);

@customElement("ub-devices")
export class UbDevices extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @property() filter = "all";
  @state() private q = "";
  @state() private category = "";
  @state() private sort: Col = "name";
  @state() private asc = true;

  private setFilter(f: string) {
    this.dispatchEvent(new CustomEvent("filter", { detail: f }));
  }

  private sortBy(col: Col) {
    if (this.sort === col) this.asc = !this.asc;
    else { this.sort = col; this.asc = col !== "traffic"; }
  }

  private rows(): Client[] {
    const f = FILTERS.find((x) => x[0] === this.filter)?.[2] ?? (() => true);
    const q = this.q.trim().toLowerCase();
    const key = (c: Client): string | number => {
      switch (this.sort) {
        case "name": return name(c).toLowerCase();
        case "category": return c.category_label || c.category;
        case "ip": return (c.ip || "").split(".").map((x) => x.padStart(3, "0")).join(".");
        case "vendor": return (c.vendor || "").toLowerCase();
        case "state": return c.state;
        case "traffic": return traffic(c);
        case "signal": return c.rssi ?? -999;
      }
    };
    return this.ctx.snap.clients
      .filter(f)
      .filter((c) => !this.category || c.category === this.category)
      .filter((c) => !q || [c.mac, c.name, c.hostname, c.ip, c.vendor, c.essid, c.category_label, c.state,
        c.home_automation?.brand, c.onvif_manufacturer].some((v) => (v || "").toLowerCase().includes(q)))
      .sort((a, b) => {
        const x = key(a), y = key(b);
        const r = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
        return this.asc ? r : -r;
      });
  }

  private th(col: Col, label: string) {
    const sorted = this.sort === col;
    return html`<th aria-sort=${sorted ? (this.asc ? "ascending" : "descending") : "none"}>
      <button @click=${() => this.sortBy(col)}>${label}${sorted ? (this.asc ? " ▲" : " ▼") : ""}</button></th>`;
  }

  render() {
    const { snap } = this.ctx;
    const rows = this.rows();
    const all = snap.clients;
    return html`
      <h1>Devices</h1>
      <p class="sub">Everything the controller sees right now. Select a device for details and actions.</p>
      <div class="chips" role="group" aria-label="Filter devices">
        ${FILTERS.map(([id, label, f]) => html`<button class="chip" aria-pressed=${this.filter === id ? "true" : "false"} @click=${() => this.setFilter(id)}>${label} ${all.filter(f).length}</button>`)}
      </div>
      <div class="row" style="margin-bottom:12px">
        <input type="search" placeholder="Search name, IP, MAC, maker…" aria-label="Search devices" .value=${this.q} @input=${(e: Event) => (this.q = (e.target as HTMLInputElement).value)} style="flex:1;min-width:200px">
        <select aria-label="Category" @change=${(e: Event) => (this.category = (e.target as HTMLSelectElement).value)}>
          <option value="">All categories</option>
          ${categoryOptions(snap).map(([k, v]) => html`<option value=${k} ?selected=${this.category === k}>${v} (${all.filter((c) => c.category === k).length})</option>`)}
        </select>
      </div>
      ${this.filter === "wireless" ? this.wifiSummary(rows) : this.filter === "wired" ? this.wiredSummary(rows) : nothing}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr>
            ${this.th("name", "Device")}${this.th("category", "Category")}${this.th("ip", "IP")}${this.th("vendor", "Maker")}
            ${this.th("state", "Status")}<th>Internet</th>${this.th("traffic", "24 h")}${this.filter === "wireless" ? this.th("signal", "Signal") : nothing}
          </tr></thead>
          <tbody>
            ${rows.map((c) => html`<tr class="click" tabindex="0" @click=${() => this.ctx.open(c.mac)} @keydown=${(e: KeyboardEvent) => e.key === "Enter" && this.ctx.open(c.mac)}>
              <td><strong>${name(c)}</strong>${c.suspicious ? html` <span class="badge warn">suspicious</span>` : nothing}<div class="mono muted">${c.mac}</div></td>
              <td>${c.category_icon} ${c.category_label}${c.confidence === "low" ? html` <span class="muted small">(guess)</span>` : nothing}</td>
              <td class="mono">${c.ip || "—"}</td>
              <td class="small">${c.home_automation?.brand || c.onvif_manufacturer || c.vendor || "—"}</td>
              <td>${stateBadge(c)}</td>
              <td>${containmentBadge(c)} ${vulnBadge(c)}</td>
              <td>${sparkline(c.traffic_24h)}${c.traffic_spike ? html` <span class="badge bad">spike</span>` : nothing}</td>
              ${this.filter === "wireless" ? html`<td class=${(c.rssi ?? 0) < -80 ? "bad" : ""}>${c.rssi != null ? `${c.rssi} dBm` : "—"}</td>` : nothing}
            </tr>`)}
          </tbody>
        </table>
        ${rows.length ? nothing : html`<div class="empty">No devices match.</div>`}
      </div>
    `;
  }

  private wifiSummary(rows: Client[]) {
    const count = (f: (c: Client) => string) => Object.entries(rows.reduce((m, c) => ({ ...m, [f(c)]: (m[f(c)] || 0) + 1 }), {} as Record<string, number>)).sort((a, b) => b[1] - a[1]);
    const bucket = (r: number | null | undefined) => r == null ? "unknown" : r > -50 ? "excellent" : r > -65 ? "good" : r > -75 ? "fair" : r > -85 ? "weak" : "very weak";
    return html`<div class="grid two">
      <div class="card"><h3>By network</h3>${count((c) => c.essid || "unknown").map(([k, n]) => html`<div class="row small"><span>${k}</span><span class="spacer"></span><span>${n}</span></div>`)}</div>
      <div class="card"><h3>Signal</h3>${count((c) => bucket(c.rssi)).map(([k, n]) => html`<div class="row small"><span>${k}</span><span class="spacer"></span><span>${n}</span></div>`)}
        <h3>By channel</h3><div class="small">${count((c) => String(c.channel ?? "?")).sort((a, b) => Number(a[0]) - Number(b[0])).map(([k, n]) => html`<span class="badge" style="margin:2px">ch ${k}: ${n}</span>`)}</div></div>
    </div>`;
  }

  private wiredSummary(rows: Client[]) {
    return html`<div class="tiles">
      <div class="tile"><div class="n">${rows.length}</div><div class="l">wired devices</div></div>
      <div class="tile"><div class="n">${bytes(rows.reduce((a, c) => a + traffic(c), 0))}</div><div class="l">moved in 24 h</div></div>
    </div>`;
  }

  static styles = [shared];
}
