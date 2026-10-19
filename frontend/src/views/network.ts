import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { name, plural } from "../format";
import { categoryOptions, stateBadge, type Ctx } from "../ui";
import type { Client } from "../types";

function inCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  const n = Number(bits);
  const toInt = (a: string) => a.split(".").reduce((x, o) => x * 256 + Number(o), 0);
  if (!base || !(n >= 0 && n <= 32) || base.split(".").length !== 4) return false;
  const mask = n === 0 ? 0 : 2 ** 32 - 2 ** (32 - n);
  return (toInt(ip) & mask) >>> 0 === (toInt(base) & mask) >>> 0;
}

@customElement("ub-network")
export class UbNetwork extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @state() private ipResult: any = null;
  @state() private ip = "";
  @state() private showCandidates = false;
  @state() private cidr = "";

  private async checkIp() {
    if (!this.ip.trim()) return;
    this.ipResult = await this.ctx.act("check_ip", { ip: this.ip.trim() }, { refresh: false });
  }

  private rangeCard(prefix: string) {
    const { snap, act } = this.ctx;
    const rb = snap.localnet.range_block;
    if (!rb) return nothing;
    const cidr = this.cidr || rb.cidr || `${prefix}.0/24`;
    const inside = snap.clients.filter((c) => c.ip && inCidr(c.ip, cidr));
    const flagged = inside.filter((c) => !c.is_camera && ["nas", "computer", "phone", "tablet", "networking", "crypto", "streaming", "gaming"].includes(c.category));
    return html`<div class="card">
      <h2>Block the whole range</h2>
      <p>Two firewall rules on the gateway cut every address in a range off from the internet, including devices added later. Time sync (NTP) stays allowed so camera timestamps and light schedules stay right. Nothing on your own network is affected.</p>
      ${!rb.supported ? html`<p><span class="badge warn">not available</span> ${rb.reason}</p>` : rb.enabled
        ? html`<div class="row"><span class="badge ok">on</span><span class="mono">${rb.cidr}</span>
            <span class="small muted">${plural(inside.length, "device")} online in it${rb.ntp_allowed ? ", time sync allowed" : ""}</span><span class="spacer"></span>
            <button class="btn" @click=${() => act("localnet_range_block", { enabled: false }, { confirm: `Remove the block on ${rb.cidr}? Devices in it get internet access again unless they have their own rule.`, done: "Range block removed" })}>Turn off</button></div>`
        : html`<div class="row">
            <label class="small" for="cidr">Range</label>
            <input id="cidr" class="mono" style="width:150px" .value=${cidr} @input=${(e: Event) => (this.cidr = (e.target as HTMLInputElement).value.trim())}>
            <span class="small muted">${plural(inside.length, "device")} online in it</span><span class="spacer"></span>
            <button class="btn primary" @click=${() => act("localnet_range_block", { enabled: true, cidr },
              { confirm: `Block every address in ${cidr} from the internet? ${plural(inside.length, "device")} online now${flagged.length ? `, including ${flagged.map(name).join(", ")}` : ""}.`, danger: flagged.length > 0, done: `${cidr} blocked from the internet` })}>Block this range</button></div>
          ${flagged.length ? html`<p class="small"><span class="badge warn">check</span> ${flagged.map(name).join(", ")} ${flagged.length === 1 ? "is in this range and probably needs" : "are in this range and probably need"} the internet. Use a smaller range (e.g. ${prefix}.0/25 covers .0–.127) to leave ${flagged.length === 1 ? "it" : "them"} out.</p>` : nothing}`}
    </div>`;
  }

  render() {
    const { snap, act } = this.ctx;
    const ln = snap.localnet;
    const prefix = ln.prefix || "192.168.2";
    const assigned = ln.assignments || {};
    const isAssigned = (c: Client) => !!assigned[c.mac.toLowerCase()];
    const groups = {
      blocked: snap.clients.filter((c) => c.blocked || c.state === "quarantined"),
      local: snap.clients.filter((c) => !(c.blocked || c.state === "quarantined") && isAssigned(c)),
      review: snap.clients.filter((c) => !(c.blocked || c.state === "quarantined") && !isAssigned(c) && c.state === "new"),
      internet: snap.clients.filter((c) => !(c.blocked || c.state === "quarantined") && !isAssigned(c) && c.state !== "new"),
    };
    const fw = ln.firewall || {};
    const missing = (fw.total_devices || 0) - (fw.blocked_count || 0);
    const candidates = snap.clients.filter((c) => !isAssigned(c) && c.category !== "unknown" && c.state !== "quarantined" && !c.blocked);
    const nas = snap.clients.filter((c) => c.category === "nas");
    return html`
      <h1>Network</h1>
      <p class="sub">Who can reach what, and the local-only setup.</p>
      <div class="tiles">
        <div class="tile"><div class="n">${groups.internet.length}</div><div class="l">internet access</div></div>
        <div class="tile ok"><div class="n">${groups.local.length}</div><div class="l">local-only</div></div>
        <div class="tile"><div class="n">${groups.blocked.length}</div><div class="l">blocked</div></div>
        <button class="tile ${groups.review.length > 10 ? "warn" : ""}" @click=${() => this.ctx.go("devices", "new")}><div class="n">${groups.review.length}</div><div class="l">not reviewed yet</div></button>
      </div>

      ${this.rangeCard(prefix)}

      <div class="card">
        <h2>Local-only</h2>
        <p>Local-only devices get an address in <span class="mono">${ln.subnet || `${prefix}.0/24`}</span> and a per-device traffic rule on the gateway that blocks them from the internet. They keep working on your network.</p>
        <p class="small muted">Local-only stops internet access, not access to the rest of your LAN: those addresses are on the same network as everything else. Keeping a camera away from your other devices takes a separate VLAN.</p>
        <div class="row" style="margin:8px 0">
          ${fw.total_devices ? html`<span class="badge ${missing ? "warn" : "ok"}">${fw.blocked_count}/${fw.total_devices} rules in place</span>` : html`<span class="badge">no devices yet</span>`}
          ${missing > 0 ? html`<button class="btn primary" @click=${() => act("localnet_ensure_rule", {}, { done: "Missing rules created" })}>Create ${plural(missing, "missing rule")}</button>` : nothing}
        </div>
        ${Object.keys(assigned).length ? html`<div class="scroll"><table>
          <thead><tr><th>Device</th><th>Address</th><th>Category</th><th>Internet</th><th></th></tr></thead>
          <tbody>${Object.entries(assigned).map(([mac, a]) => {
            const c = snap.clients.find((x) => x.mac.toLowerCase() === mac);
            return html`<tr><td>${c ? html`<button class="linkish" @click=${() => this.ctx.open(mac)}>${name(c)}</button>` : html`${a.name || mac} <span class="muted small">(offline)</span>`}</td>
              <td class="mono">${a.ip}</td><td>${a.category}</td>
              <td>${c?.phone_home ? html`<span class="small">${c.phone_home.attempts} attempts blocked</span>` : html`<span class="muted small">—</span>`}</td>
              <td><button class="btn" @click=${() => act("localnet_remove", { mac }, { confirm: `Take ${c ? name(c) : mac} off local-only? It gets internet access again.`, done: "Removed from local-only" })}>Remove</button></td></tr>`;
          })}</tbody></table></div>` : nothing}
        <button class="btn" style="margin-top:12px" aria-expanded=${this.showCandidates ? "true" : "false"} @click=${() => (this.showCandidates = !this.showCandidates)}>${this.showCandidates ? "Hide" : "Add devices"}</button>
        ${this.showCandidates ? html`<div class="scroll" style="margin-top:8px"><table><thead><tr><th>Device</th><th>Category</th><th></th></tr></thead>
          <tbody>${candidates.slice(0, 60).map((c) => html`<tr><td>${name(c)}<div class="muted small">${c.ip} · ${c.vendor}</div></td><td>${c.category_label}</td>
            <td><button class="btn" @click=${() => act("localnet_assign", { mac: c.mac, category: c.category }, { confirm: `Put ${name(c)} on local-only?`, done: `${name(c)} is now local-only` })}>Make local-only</button></td></tr>`)}</tbody></table></div>` : nothing}
        ${(ln.ranges || []).length ? html`<details style="margin-top:12px"><summary class="small">Address ranges by category</summary>
          <table class="small"><thead><tr><th>Category</th><th>Range</th><th>Used</th></tr></thead>
          <tbody>${(ln.ranges || []).map((r) => html`<tr><td>${(Object.fromEntries(categoryOptions(snap)) as Record<string, string>)[r.category] || r.category}</td><td class="mono">${r.range}</td><td>${r.used}/${r.total}</td></tr>`)}</tbody></table></details>` : nothing}
      </div>

      <div class="grid two">
        <div class="card">
          <h2>Is this address free?</h2>
          <p class="sub">Checks clients, offline devices, UniFi devices, reservations and local-only assignments before you hand an address out.</p>
          <div class="row"><input type="text" placeholder="${prefix}.35" aria-label="IP address" .value=${this.ip} @input=${(e: Event) => (this.ip = (e.target as HTMLInputElement).value)} @keydown=${(e: KeyboardEvent) => e.key === "Enter" && this.checkIp()}>
            <button class="btn primary" @click=${() => this.checkIp()}>Check</button></div>
          ${this.ipResult ? html`<p style="margin-top:10px"><strong>${this.ipResult.summary}</strong></p>
            <table class="small"><tbody>${(this.ipResult.checks || []).map((c: any) => html`<tr><td>${c.icon}</td><td>${c.check}</td><td>${c.result}</td></tr>`)}</tbody></table>` : nothing}
        </div>
        <div class="card">
          <h2>Storage (${nas.length})</h2>
          ${nas.length ? html`<table class="small"><tbody>${nas.map((c) => html`<tr class="click" @click=${() => this.ctx.open(c.mac)}><td>${name(c)}</td><td class="mono">${c.ip}</td><td>${c.vendor}</td><td>${stateBadge(c)}</td></tr>`)}</tbody></table>
            <p class="small muted" style="margin-top:8px">A NAS should stay on your main network with internet for updates and cloud backup. Don't put it on local-only.</p>`
            : html`<div class="empty">No NAS found.</div>`}
        </div>
      </div>
    `;
  }

  static styles = [shared];
}
