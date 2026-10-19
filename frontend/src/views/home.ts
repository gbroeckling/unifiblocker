import { LitElement, html, nothing } from "lit";
import { customElement, property } from "lit/decorators.js";
import { shared } from "../styles";
import { name } from "../format";
import { containmentBadge, sparkline, type Ctx } from "../ui";
import type { Client } from "../types";

const TIERS: { id: string; title: string; text: string }[] = [
  { id: "cloud", title: "Cloud only", text: "Only work through the maker's servers. Cutting them off breaks them, so local-only isn't an option; if that worries you, look for a local alternative." },
  { id: "cloud_local", title: "Cloud, with a local option", text: "Ship talking to a cloud but can be controlled locally. Switch Home Assistant to the local route first, then they can go on local-only without breaking." },
  { id: "unknown", title: "Not sure", text: "Home automation devices we can't place yet. Set their category or brand by hand from the device's page." },
  { id: "local", title: "Local", text: "Firmware you control or no cloud at all (ESPHome, WLED, Tasmota, Zigbee coordinators). Nothing to do." },
];

@customElement("ub-home")
export class UbHome extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;

  render() {
    const ha = this.ctx.snap.clients.filter((c) => c.home_automation);
    const by = (t: string) => ha.filter((c) => c.home_automation!.tier === t).sort((a, b) => (a.home_automation!.brand || "~").localeCompare(b.home_automation!.brand || "~") || name(a).localeCompare(name(b)));
    return html`
      <h1>Home automation</h1>
      <p class="sub">Smart home devices, sorted by how much they depend on someone else's cloud. Cheap cloud-tied gear has the same problems as cheap cameras.</p>
      <div class="tiles">${TIERS.map((t) => html`<div class="tile ${t.id === "cloud" && by(t.id).length ? "warn" : ""}"><div class="n">${by(t.id).length}</div><div class="l">${t.title.toLowerCase()}</div></div>`)}</div>
      ${TIERS.map((t) => {
        const rows = by(t.id);
        if (!rows.length) return nothing;
        return html`<div class="card"><h2>${t.title} (${rows.length})</h2><p class="sub">${t.text}</p>
          <div class="scroll"><table><thead><tr><th>Device</th><th>Brand</th><th>Internet</th><th>24 h</th>${t.id === "cloud_local" ? html`<th>Local option</th>` : nothing}</tr></thead>
          <tbody>${rows.map((c) => this.row(c, t.id === "cloud_local"))}</tbody></table></div></div>`;
      })}
      ${ha.length ? nothing : html`<div class="empty">No home automation devices found.</div>`}
    `;
  }

  private row(c: Client, showHint: boolean) {
    const ph = c.phone_home;
    return html`<tr class="click" tabindex="0" @click=${() => this.ctx.open(c.mac)} @keydown=${(e: KeyboardEvent) => e.key === "Enter" && this.ctx.open(c.mac)}>
      <td><strong>${name(c)}</strong><div class="muted small">${c.ip}</div></td>
      <td>${c.home_automation!.brand || html`<span class="muted">—</span>`}</td>
      <td>${containmentBadge(c)}${ph ? html`<div class="small muted">${ph.attempts} attempts${Object.keys(ph.clouds).length ? ` to ${Object.keys(ph.clouds).join(", ")}` : ""}</div>` : nothing}</td>
      <td>${sparkline(c.traffic_24h)}</td>
      ${showHint ? html`<td class="small">${c.home_automation!.local_option}</td>` : nothing}
    </tr>`;
  }

  static styles = [shared];
}
