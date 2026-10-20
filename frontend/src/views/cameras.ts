import { LitElement, html, nothing } from "lit";
import { customElement, property } from "lit/decorators.js";
import { shared } from "../styles";
import { name, plural } from "../format";
import { containmentBadge, vulnBadge, type Ctx } from "../ui";

@customElement("ub-cameras")
export class UbCameras extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;

  render() {
    const { snap } = this.ctx;
    const cams = snap.clients.filter((c) => c.is_camera)
      .sort((a, b) => Number(!!b.containment === false) - Number(!!a.containment === false) || name(a).localeCompare(name(b)));
    const open = cams.filter((c) => !c.containment);
    const hotspots = snap.overview.hotspots || [];
    return html`
      <h1>Cameras</h1>
      <p class="sub">Each camera's containment, what it tries to reach, and whether its firmware has known-exploited bugs.</p>
      <div class="tiles">
        <div class="tile ${open.length ? "warn" : "ok"}"><div class="n">${cams.length - open.length}/${cams.length}</div><div class="l">off the internet</div></div>
        <div class="tile ${cams.some((c) => c.containment === "leaking") ? "bad" : ""}"><div class="n">${cams.filter((c) => c.containment === "leaking").length}</div><div class="l">not contained</div></div>
        <div class="tile"><div class="n">${cams.reduce((a, c) => a + (c.phone_home?.attempts || 0), 0)}</div><div class="l">blocked attempts (recent)</div></div>
        <div class="tile ${cams.some((c) => c.vulns?.worst === "affected" || c.vulns?.worst === "likely") ? "bad" : ""}"><div class="n">${cams.filter((c) => c.vulns?.findings?.length).length}</div><div class="l">firmware warnings</div></div>
      </div>
      ${open.length ? html`<div class="card"><div class="row">
        <span>${plural(open.length, "camera")} can still reach the internet.</span><span class="spacer"></span>
        <button class="btn primary" @click=${() => this.containAll(open.map((c) => c.mac))}>Block internet for all ${open.length}</button></div></div>` : nothing}
      <div class="card scroll" style="padding:0">
        <table>
          <thead><tr><th>Camera</th><th>Internet</th><th>Calls home to</th><th>Firmware</th><th>ONVIF</th><th></th></tr></thead>
          <tbody>${cams.map((c) => html`<tr>
            <td><button class="linkish" @click=${() => this.ctx.open(c.mac)}><strong>${name(c)}</strong></button><div class="muted small">${c.ip} · ${c.vulns?.family || c.onvif_manufacturer || c.vendor}</div></td>
            <td>${containmentBadge(c)}${c.phone_home ? html`<div class="small muted">${plural(c.phone_home.attempts, "attempt")}${c.phone_home.allowed ? `, ${c.phone_home.allowed} through` : ", all blocked"}</div>` : nothing}
              ${c.phone_home?.port_sweep ? html`<div class="small"><span class="badge warn">probing ${c.phone_home.port_sweep.ports} ports</span></div>` : nothing}</td>
            <td class="small">${c.phone_home ? (Object.keys(c.phone_home.clouds).join(", ") || Object.keys(c.phone_home.regions).join(", ") || "—") : html`<span class="muted">not visible</span>`}</td>
            <td>${vulnBadge(c)}<div class="small muted">${c.vulns?.firmware_date || ""}</div></td>
            <td>${c.onvif?.onvif ? html`<span class="badge ok">yes</span>${c.onvif.auth_required ? html` <span class="small muted">login</span>` : nothing}` : html`<span class="muted small">—</span>`}</td>
            <td>${c.containment ? nothing : html`<button class="btn" @click=${() => this.ctx.act("block_internet", { mac: c.mac }, { confirm: `Block ${name(c)} from the internet? It keeps its address, so recording keeps working.`, done: `${name(c)} blocked from the internet` })}>Block internet</button>`}</td>
          </tr>`)}</tbody>
        </table>
        ${cams.length ? nothing : html`<div class="empty">No cameras found yet. Run ONVIF discovery or Quantify from Tools.</div>`}
      </div>
      ${hotspots.length ? html`<div class="card"><h2>Camera Wi-Fi networks</h2>
        <p class="sub">A camera running its own Wi-Fi access point can be reached by anyone nearby, around your firewall. Turn that mode off in the camera's settings.</p>
        <table><thead><tr><th>Network</th><th>Why it's listed</th><th>Signal</th><th>Channel</th><th>Security</th></tr></thead>
        <tbody>${hotspots.map((h) => html`<tr><td>${h.essid || "(hidden)"}<div class="mono muted">${h.bssid}</div></td>
          <td>${h.reason === "own_camera" ? html`<span class="badge bad">your camera ${h.camera_name || h.camera_mac}</span>` : "camera setup name"}</td>
          <td>${h.rssi != null ? `${h.rssi} dBm` : "—"}</td><td>${h.channel ?? "—"}</td><td>${h.security || "open"}</td></tr>`)}</tbody></table></div>` : nothing}
      <div class="card small muted">
        UniFi only logs blocked connections, so a camera's internet use shows up once it's blocked: every attempt it makes is then blocked and listed. "Not contained" means UniFi logged traffic it let through from a camera that should be cut off. Most UniFi gateways log only blocked connections, though, so a block that isn't working can look the same as a quiet camera: test a new kind of block from a laptop on the same addresses.
      </div>
    `;
  }

  private async containAll(macs: string[]) {
    const ok = await this.ctx.confirm(`Block ${plural(macs.length, "camera")} from the internet? They keep their addresses, so your recorder keeps working.`);
    if (!ok) return;
    let done = 0;
    for (const mac of macs) {
      if (await this.ctx.act("block_internet", { mac }, { refresh: false })) done++;
    }
    this.ctx.say(`${plural(done, "camera")} blocked from the internet`);
    this.ctx.reload();
  }

  static styles = [shared];
}
