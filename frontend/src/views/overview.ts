import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { duration, name, plural } from "../format";
import { byPriority, containmentBadge, recCard, vulnBadge, type Ctx } from "../ui";
import type { Rec } from "../types";

@customElement("ub-overview")
export class UbOverview extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @state() private quantify: any = null;
  @state() private running = false;

  private async runQuantify() {
    this.running = true;
    const r = await this.ctx.act("deep_scan_unknowns", {}, { confirm: "Deep-scan every device that's still unknown? It probes each one (web, TLS, SSH, mDNS, NetBIOS) and takes a few minutes." });
    this.running = false;
    if (r) this.quantify = r;
  }

  render() {
    const { snap } = this.ctx;
    if (!snap.loaded) return html`<div class="empty">Loading…</div>`;
    const o = snap.overview;
    const cams = snap.clients.filter((c) => c.is_camera);
    const contained = cams.filter((c) => c.containment === "holding" || c.containment === "quiet").length;
    const leaking = snap.clients.filter((c) => c.containment === "leaking");
    const vulnerable = snap.clients.filter((c) => c.vulns?.worst === "affected" || c.vulns?.worst === "likely").length;
    const unknown = snap.clients.filter((c) => c.category === "unknown").length;
    const attention: { r: Rec; mac?: string }[] = [
      ...(snap.recs.network_recs || []).map((r) => ({ r })),
      ...Object.entries(snap.recs.device_recs || {}).flatMap(([mac, rs]) => rs.map((r) => ({ r, mac }))),
    ].filter((x) => x.r.priority === "critical" || x.r.priority === "high").sort((a, b) => byPriority(a.r, b.r));

    return html`
      <h1>Overview</h1>
      <p class="sub">${o.health?.connection_ok === false ? "Can't reach the controller." : `Connected to ${o.health?.hostname || "the controller"}${o.health?.version ? ` (UniFi Network ${o.health.version})` : ""}.`}</p>

      <div class="tiles">
        <button class="tile" @click=${() => this.ctx.go("devices", "all")}><div class="n">${o.total_clients ?? 0}</div><div class="l">devices online</div></button>
        <button class="tile ${(o.new_count || 0) ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${o.new_count ?? 0}</div><div class="l">waiting for review</div></button>
        <button class="tile ${cams.length && contained < cams.length ? "warn" : "ok"}" @click=${() => this.ctx.go("cameras")}><div class="n">${contained}/${cams.length}</div><div class="l">cameras contained</div></button>
        <button class="tile ${leaking.length ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${leaking.length}</div><div class="l">not contained</div></button>
        <button class="tile ${vulnerable ? "bad" : ""}" @click=${() => this.ctx.go("cameras")}><div class="n">${vulnerable}</div><div class="l">with exploited bugs</div></button>
        <button class="tile ${(o.threat_events || 0) ? "warn" : ""}" @click=${() => this.ctx.go("security")}><div class="n">${o.threat_events ?? 0}</div><div class="l">security events (24 h)</div></button>
        <button class="tile ${(o.suspicious_count || 0) ? "warn" : ""}" @click=${() => this.ctx.go("devices", "suspicious")}><div class="n">${o.suspicious_count ?? 0}</div><div class="l">suspicious</div></button>
        <button class="tile" @click=${() => this.ctx.go("devices", "unknown")}><div class="n">${unknown}</div><div class="l">not identified</div></button>
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Needs attention</h2>
          ${attention.length ? attention.slice(0, 6).map((x) => recCard(this.ctx, x.r, x.mac)) : html`<div class="empty">Nothing critical or high right now.</div>`}
          ${attention.length > 6 ? html`<button class="btn" @click=${() => this.ctx.go("security")}>All ${attention.length} on the Security page</button>` : nothing}
        </div>

        <div>
          <div class="card">
            <h2>Cameras</h2>
            ${cams.length ? html`<div class="scroll"><table>
              <tbody>${cams.map((c) => html`<tr class="click" tabindex="0" @click=${() => this.ctx.open(c.mac)} @keydown=${(e: KeyboardEvent) => e.key === "Enter" && this.ctx.open(c.mac)}>
                <td>${name(c)}<div class="muted small">${c.ip}</div></td>
                <td>${containmentBadge(c)} ${vulnBadge(c)}</td>
                <td class="small muted">${c.phone_home ? `${plural(c.phone_home.attempts, "attempt")} blocked${c.phone_home.window_minutes ? ` in ${c.phone_home.window_minutes < 120 ? `${c.phone_home.window_minutes} min` : `${Math.round(c.phone_home.window_minutes / 60)} h`}` : ""}` : ""}</td>
              </tr>`)}</tbody></table></div>` : html`<div class="empty">No cameras found.</div>`}
          </div>
          <div class="card">
            <h2>Controller</h2>
            <div class="kv">
              <span>Status</span><span>${o.health?.connection_ok === false ? html`<span class="badge bad">unreachable</span>` : html`<span class="badge ok">connected</span>`}</span>
              <span>Host</span><span>${o.health?.hostname || "—"}</span>
              <span>Version</span><span>${o.health?.version || "—"}</span>
              <span>Uptime</span><span>${duration(o.health?.uptime as number | undefined)}</span>
              <span>Wi-Fi / wired</span><span>${o.wireless_count ?? 0} / ${o.wired_count ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row"><h2 style="margin:0">Quantify unknown devices</h2><span class="spacer"></span>
          <button class="btn primary" ?disabled=${this.running} @click=${() => this.runQuantify()}>${this.running ? "Scanning… (a few minutes)" : `Scan ${plural(unknown, "unknown device")}`}</button>
        </div>
        <p class="sub" style="margin:8px 0 0">Probes each unknown device to work out what it is. High-confidence results are applied; the rest become suggestions you can accept.</p>
        ${this.quantify ? this.renderQuantify() : nothing}
      </div>
    `;
  }

  private renderQuantify() {
    const q = this.quantify;
    const rows = Object.entries(q.results || {}) as [string, any][];
    return html`<p class="small">${q.scanned} scanned · ${q.identified} applied · ${q.suggested} suggested</p>
      <div class="scroll"><table>
        <thead><tr><th>Device</th><th>Best guess</th><th>Confidence</th><th>Based on</th><th></th></tr></thead>
        <tbody>${rows.map(([mac, r]) => html`<tr>
          <td>${r.name || html`<span class="mono">${mac}</span>`}<div class="muted small">${r.ip}</div></td>
          <td>${r.best_guess === "unknown" ? html`<span class="muted">still unknown</span>` : html`${r.best_guess}<div class="muted small">${r.best_description}</div>`}</td>
          <td>${r.best_guess === "unknown" ? "—" : r.best_confidence}</td>
          <td class="small">${(r.techniques_used || []).join(", ") || "—"}</td>
          <td>${r.best_guess === "unknown" ? nothing : r.applied
            ? html`<span class="badge ok">applied</span> <button class="btn" @click=${() => this.ctx.act("clear_category", { mac }, { done: "Undone" })}>Undo</button>`
            : html`<button class="btn" @click=${() => this.ctx.act("set_category", { mac, category: r.best_guess }, { done: `Set to ${r.best_guess}` })}>Accept</button>`}</td>
        </tr>`)}</tbody>
      </table></div>`;
  }

  static styles = [shared];
}
