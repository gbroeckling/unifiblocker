import { LitElement, html, nothing } from "lit";
import { customElement, property } from "lit/decorators.js";
import { shared } from "../styles";
import { hashrate, money } from "../format";
import type { Ctx } from "../ui";

@customElement("ub-mining")
export class UbMining extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;

  render() {
    const { rigs, summary: s } = this.ctx.snap.miners;
    const profit = s.profit_usd_day ?? 0;
    return html`
      <h1>Mining</h1>
      <p class="sub">Crypto miners found on the network, with live profitability at $${(s.electricity_usd_per_kwh ?? 0.08).toFixed(3)}/kWh.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${s.rig_count ?? 0}</div><div class="l">rigs</div></div>
        <div class="tile"><div class="n">${s.reachable ?? 0}/${s.rig_count ?? 0}</div><div class="l">answering</div></div>
        <div class="tile"><div class="n">${hashrate(s.total_hashrate_hs)}</div><div class="l">hashrate</div></div>
        <div class="tile"><div class="n">${Math.round(s.total_power_w ?? 0)} W</div><div class="l">power</div></div>
        <div class="tile"><div class="n">${money(s.revenue_usd_day)}</div><div class="l">revenue / day</div></div>
        <div class="tile"><div class="n">${money(s.cost_usd_day)}</div><div class="l">power cost / day</div></div>
        <div class="tile ${profit > 0 ? "ok" : profit < 0 ? "bad" : ""}"><div class="n">${money(profit)}</div><div class="l">profit / day</div></div>
      </div>
      ${rigs.length ? html`<div class="card scroll" style="padding:0"><table>
        <thead><tr><th>Rig</th><th>Model</th><th>Coin</th><th>Hashrate</th><th>Temp</th><th>Power</th><th>Revenue</th><th>Cost</th><th>Profit</th></tr></thead>
        <tbody>${rigs.map((r) => html`<tr>
          <td class="mono"><a href="http://${r.ip}" target="_blank" rel="noopener noreferrer" style="color:var(--primary-color)">${r.ip}</a></td>
          <td>${r.model || "—"}${r.reachable ? html` <span class="badge info">${r.source || "api"}</span>` : html` <span class="badge warn">no API</span>`}</td>
          <td>${r.coin || "—"}</td><td>${r.hashrate_display || hashrate(r.hashrate_hs)}</td>
          <td>${r.extras?.temp_c != null ? `${r.extras.temp_c} °C` : "—"}</td>
          <td>${r.power_w != null ? `${Math.round(r.power_w)} W${r.power_source === "rated" ? " (rated)" : ""}` : "—"}</td>
          <td>${money(r.revenue_usd_day)}</td><td>${money(r.cost_usd_day)}</td>
          <td class=${(r.profit_usd_day ?? 0) < 0 ? "bad" : ""}>${money(r.profit_usd_day)}</td>
        </tr>`)}</tbody></table></div>`
        : html`<div class="card empty">No miners found. They're picked up from port scans (CGMiner API on 4028) and known miner makers' MAC addresses.</div>`}
      ${(s.revenue_usd_day ?? 0) === 0 && rigs.length ? html`<p class="small muted">Revenue shows $0 when coin prices can't be fetched (minerstat.com now needs an API key).</p>` : nothing}
    `;
  }

  static styles = [shared];
}
