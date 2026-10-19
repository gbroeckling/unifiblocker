import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { name } from "../format";
import { byPriority, recCard, type Ctx } from "../ui";
import type { Rec } from "../types";

const LEVELS = ["critical", "high", "medium", "low", "info"] as const;

@customElement("ub-security")
export class UbSecurity extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @state() private show = new Set<string>(["critical", "high", "medium"]);

  private toggle(level: string) {
    const s = new Set(this.show);
    s.has(level) ? s.delete(level) : s.add(level);
    this.show = s;
  }

  render() {
    const { snap } = this.ctx;
    const all: { r: Rec; mac?: string }[] = [
      ...(snap.recs.network_recs || []).map((r) => ({ r })),
      ...Object.entries(snap.recs.device_recs || {}).flatMap(([mac, rs]) => rs.map((r) => ({ r, mac }))),
    ].sort((a, b) => byPriority(a.r, b.r));
    const shown = all.filter((x) => this.show.has(x.r.priority));
    const events = snap.overview.security_events || [];
    const susp = snap.clients.filter((c) => c.suspicious).sort((a, b) => b.suspicion_score - a.suspicion_score);
    return html`
      <h1>Security</h1>
      <p class="sub">What to fix, most urgent first, plus UniFi's security log and devices that behave oddly.</p>
      <div class="chips" role="group" aria-label="Show priorities">
        ${LEVELS.map((l) => html`<button class="chip" aria-pressed=${this.show.has(l) ? "true" : "false"} @click=${() => this.toggle(l)}>${l} ${all.filter((x) => x.r.priority === l).length}</button>`)}
      </div>
      <div class="card">
        <h2>Recommendations (${shown.length})</h2>
        ${shown.length ? shown.slice(0, 80).map((x) => recCard(this.ctx, x.r, x.mac)) : html`<div class="empty">Nothing at these levels.</div>`}
        ${shown.length > 80 ? html`<p class="small muted">Showing the first 80.</p>` : nothing}
      </div>
      <div class="grid two">
        <div class="card"><h2>UniFi security log, last 24 h (${events.length})</h2>
          <p class="sub">Blocks made by UniFi Blocker's own local-only rules aren't listed here; they show on each camera as proof the rule works (${snap.overview.contained_blocks_24h ?? 0} today).</p>
          ${events.length ? html`<div class="scroll"><table class="small"><thead><tr><th>When</th><th>What</th><th>Rule</th></tr></thead>
            <tbody>${events.map((e) => html`<tr><td class="mono">${e.time ? new Date(e.time).toLocaleString() : "—"}</td><td>${e.msg || e.title || e.key}</td><td>${e.rule || e.catname || "—"}</td></tr>`)}</tbody></table></div>`
            : html`<div class="empty">Nothing in UniFi's security log.</div>`}
        </div>
        <div class="card"><h2>Suspicious devices (${susp.length})</h2>
          ${susp.length ? susp.slice(0, 20).map((c) => html`<div style="padding:6px 0;border-bottom:1px solid var(--ub-line)">
            <div class="row"><button class="linkish" @click=${() => this.ctx.open(c.mac)}>${name(c)}</button>
              <span class="badge ${c.threat_level === "high" ? "bad" : "warn"}">${c.threat_level} · ${c.suspicion_score}</span><span class="muted small">${c.vendor}</span></div>
            <ul class="small" style="margin:4px 0 0 0;padding-left:18px">${c.suspicion_flags.map((f) => html`<li>${f}</li>`)}</ul></div>`)
            : html`<div class="empty">No device is acting suspiciously.</div>`}
        </div>
      </div>
    `;
  }

  static styles = [shared];
}
