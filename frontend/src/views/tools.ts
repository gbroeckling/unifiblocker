import { LitElement, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { shared } from "../styles";
import { categoryOptions, type Ctx } from "../ui";
import { PRO_THEMES, THEME_NAMES } from "../themes";

const PORTS: [number | string, string, string, "bad" | "warn" | ""][] = [
  [34567, "XMEye / Xiongmai", "DVR protocol; these phone home to Xiongmai's cloud", "bad"],
  [34568, "XMEye media", "XMEye video stream", "bad"],
  [9530, "Dahua debug", "debug service on older Dahua firmware", "bad"],
  ["6789, 32100, 19000", "P2P relays", "camera cloud relays (P2P)", "bad"],
  [554, "RTSP", "camera video stream (local use is fine)", ""],
  [8000, "Hikvision SDK", "Hikvision management, also used by other things", ""],
  [37777, "Dahua TCP", "Dahua NVR/DVR protocol", ""],
  [23, "Telnet", "unencrypted remote shell; Mirai's way in", "warn"],
  [21, "FTP", "unencrypted file transfer", "warn"],
  [445, "SMB", "file sharing; lateral movement", "warn"],
  [1900, "UPnP", "can open ports on your router by itself", "warn"],
];

@customElement("ub-tools")
export class UbTools extends LitElement {
  @property({ attribute: false }) ctx!: Ctx;
  @state() private preview: any = null;
  @state() private discovering = false;
  @state() private debug: string | null = null;
  @state() private trialEmail = "";
  @state() private shownKey = "";

  private async discover() {
    this.discovering = true;
    const r = await this.ctx.act("onvif_discover", {}, { refresh: true });
    this.discovering = false;
    if (r) this.ctx.say(`ONVIF discovery found ${r.count ?? 0} camera${r.count === 1 ? "" : "s"}`);
  }

  private async enterKey() {
    const key = window.prompt("Your UniFi Blocker Pro key (UBLOK-XXXX-XXXX-XXXX-XXXX):");
    if (!key) return;
    const r = await this.ctx.act("licence_activate", { key }, { refresh: true });
    if (r) this.ctx.say(r.ok ? "UniFi Blocker Pro is on" : r.message, !r.ok);
  }

  private async startTrial() {
    const r = await this.ctx.act("licence_trial", { email: this.trialEmail.trim() }, { refresh: true });
    if (r) this.ctx.say(r.ok ? `Pro trial on for ${r.days_left ?? 30} days` : r.message, !r.ok);
  }

  private licenceCard() {
    const L = this.ctx.snap.licence;
    const until = L.expires ? new Date(L.expires) : null;
    const lifetime = until && until.getFullYear() >= 2090;
    const date = until && !lifetime ? until.toLocaleDateString() : "";
    const status = !L.has_key
      ? html`<p>No licence on this install. Everything below "What Pro adds" is locked; everything else is free and stays free.</p>`
      : !L.active
        ? html`<p><span class="badge bad">expired</span> Your Pro licence ended on ${date}, so the Pro features are off. Blocks already on your controller stay where they are and can always be turned off.</p>`
        : L.in_grace
          ? html`<p><span class="badge warn">renew</span> Your Pro licence ended on ${date}. It keeps working for ${L.grace_days ?? 14} days after that.</p>`
          : L.trial
            ? html`<p><span class="badge ok">trial</span> Pro trial, ${L.days_left ?? "?"} days left.</p>`
            : html`<p><span class="badge ok">Pro</span> UniFi Blocker Pro${lifetime ? ", lifetime" : date ? `, valid until ${date}` : ""}${!lifetime && (L.days_left ?? 99) <= 14 ? ` · renews in ${L.days_left} days` : ""}.</p>`;
    const buy = !L.has_key || !L.active || L.in_grace || L.trial;
    return html`<div class="card">
      <h2>UniFi Blocker Pro</h2>
      ${status}
      <details><summary class="small">What Pro adds</summary>
        <ul class="small">
          <li>Block a whole address range from the internet with one switch (Network page).</li>
          <li>Block new cameras from the internet automatically as they join.</li>
          <li>Traffic insight: what each device tries to reach, port sweeps, devices using their own DNS, 24-hour traffic and spikes, and an alert when a cut-off device gets through.</li>
          <li>The mining tracker: live hashrate, temperatures, power and profit per rig.</li>
          <li>The Day, Graphite, Ocean, Dusk and High contrast themes.</li>
        </ul>
        <p class="small muted">Free, always: finding and identifying every device, recommendations, the security log, firmware warnings, port scans, ONVIF, and blocking, local-only and quarantine device by device.</p>
      </details>
      <div class="row" style="margin-top:8px">
        ${buy ? html`<a class="btn primary" href=${L.buy_url || "https://unifiblocker.enerx.ca/pro/"} target="_blank" rel="noopener noreferrer">${L.has_key && !L.trial ? "Renew" : "Buy"} Pro, ${L.price || "$35 CAD/year"}</a>` : nothing}
        <button class="btn" @click=${() => this.enterKey()}>${L.has_key ? "Replace licence key" : "Enter licence key"}</button>
        ${L.has_key ? html`<button class="btn" @click=${async () => { const r = await this.ctx.act("licence_reveal", {}, { refresh: false }); if (r) this.shownKey = r.key; }}>Show key</button>
          <button class="btn" @click=${() => this.ctx.act("licence_remove", {}, { confirm: "Take the licence key off this install? You can enter it again later.", done: "Licence key removed" })}>Remove key</button>` : nothing}
      </div>
      ${this.shownKey ? html`<p class="mono" style="margin-top:8px">${this.shownKey}</p>` : nothing}
      ${!L.has_key && !L.trial_used ? html`<div class="row" style="margin-top:12px">
        <span class="small">Try Pro free for ${L.trial_days ?? 30} days, once per home:</span>
        <input type="email" placeholder="your email" aria-label="Email for the trial key" .value=${this.trialEmail}
          @input=${(e: Event) => (this.trialEmail = (e.target as HTMLInputElement).value)}>
        <button class="btn" ?disabled=${!this.trialEmail.includes("@")} @click=${() => this.startTrial()}>Start free trial</button>
      </div><p class="small muted">Your email is kept with the trial key on the licence server, nothing else. Write the key down from "Show key" if you want it elsewhere.</p>` : nothing}
    </div>`;
  }

  private async showDebug(type: string) {
    const r = await this.ctx.act(type, {}, { refresh: false });
    if (r) this.debug = JSON.stringify(r, null, 2);
  }

  render() {
    const { snap, act } = this.ctx;
    const report = snap.report;
    const L = snap.learned;
    const cats = categoryOptions(snap);
    const rules: [string, string, string, string][] = L ? [
      ...Object.entries(L.vendor_rules || {}).map(([k, c]) => ["vendor", k, `maker contains “${k}”`, c] as [string, string, string, string]),
      ...Object.entries(L.hostname_rules || {}).map(([k, c]) => ["hostname", k, `name starts “${k}”`, c] as [string, string, string, string]),
      ...Object.entries(L.mac_rules || {}).map(([k, c]) => ["mac", k, `MAC starts ${k}`, c] as [string, string, string, string]),
      ...(L.port_rules || []).map((r) => ["port", r.ports.join(","), `ports ${r.ports.join(", ")}`, r.category] as [string, string, string, string]),
    ] : [];
    return html`
      <h1>Tools</h1>
      <p class="sub">Your licence, scans, learned rules, and settings for the usage report.</p>
      ${this.licenceCard()}
      <div class="grid two">
        <div class="card">
          <h2>Find cameras</h2>
          <p class="sub">ONVIF discovery runs at startup and every 6 hours. Run it now after adding a camera. Quantify (on Overview) deep-scans everything still unknown.</p>
          <div class="row"><button class="btn primary" ?disabled=${this.discovering} @click=${() => this.discover()}>${this.discovering ? "Looking…" : "Run ONVIF discovery"}</button>
            <button class="btn" @click=${() => this.ctx.go("overview")}>Quantify…</button></div>
        </div>

        <div class="card">
          <h2>Help improve UniFi Blocker</h2>
          ${report ? html`
            <p>Off unless you turn it on. Once a day it sends counts and versions so problems on other networks can be found: device counts by category, which tools get used, poll times, API errors, warnings logged. <strong>Never</strong> MAC or IP addresses, names, vendor strings from your network, or entity ids, and the whole report is refused if anything like that is in it.</p>
            <div class="row">
              ${report.enabled ? html`<span class="badge ok">on</span><span class="small muted">${report.last_day ? `last sent ${report.last_day}` : "nothing sent yet"}</span>` : html`<span class="badge">off</span>`}
              <span class="spacer"></span>
              ${report.enabled
                ? html`<button class="btn" @click=${() => act("report_set", { enabled: false }, { done: "Usage report off" })}>Turn off</button>
                       <button class="btn" @click=${async () => { const r = await act("report_send", {}, { refresh: true }); if (r) this.ctx.say(r.sent ? `Report sent (${r.bytes} bytes)` : `Not sent: ${r.reason}`, !r.sent); }}>Send now</button>
                       <button class="btn" @click=${() => act("report_new_id", {}, { confirm: "Replace the anonymous ID? Reports after this count as a new install.", done: "New ID made" })}>New ID</button>`
                : html`<button class="btn primary" @click=${() => act("report_set", { enabled: true }, { done: "Usage report on" })}>Turn on</button>`}
              <button class="btn" @click=${async () => (this.preview = await act("report_preview", {}, { refresh: false }))}>Preview</button>
            </div>
            ${this.preview ? html`<p class="small" style="margin-top:8px">${this.preview.bytes} bytes to ${this.preview.url}${this.preview.problems?.length ? html` · <span class="badge bad">would be refused: ${this.preview.problems.join("; ")}</span>` : nothing}</p>
              <pre class="mono" style="max-height:300px;overflow:auto;white-space:pre-wrap">${JSON.stringify(this.preview.payload, null, 2)}</pre>` : nothing}
          ` : html`<p class="muted">Not available.</p>`}
        </div>
      </div>

      <div class="card">
        <h2>Theme</h2>
        <p class="sub">The same looks as PadSpan. Home Assistant follows your HA theme. This browser only.</p>
        <div class="chips" role="group" aria-label="Theme">${THEME_NAMES.map(([k, label]) => {
          const locked = PRO_THEMES.includes(k) && !snap.licence.pro;
          return html`<button class="chip" aria-pressed=${this.ctx.theme === k && !locked ? "true" : "false"} ?disabled=${locked}
            title=${locked ? "UniFi Blocker Pro" : ""} style=${locked ? "opacity:.45;cursor:default" : ""}
            @click=${() => this.ctx.setTheme(k)}>${label}${locked ? " · Pro" : ""}</button>`;
        })}</div>
        ${snap.licence.pro ? nothing : html`<p class="small muted">Day, Graphite, Ocean, Dusk and High contrast come with Pro.</p>`}
      </div>

      <div class="card">
        <h2>Learned rules (${rules.length})</h2>
        <p class="sub">Picked up when you set a device's category by hand, and used for devices nothing else identifies. Fix or delete wrong ones.</p>
        ${rules.length ? html`<div class="scroll"><table><thead><tr><th>Rule</th><th>Category</th><th></th></tr></thead>
          <tbody>${rules.map(([kind, key, label, cat]) => html`<tr><td>${label}</td>
            <td><select aria-label="Category for ${label}" @change=${(e: Event) => act("learned_rule_update", { kind, key, category: (e.target as HTMLSelectElement).value }, { done: "Rule updated" })}>
              ${cats.map(([k, v]) => html`<option value=${k} ?selected=${k === cat}>${v}</option>`)}</select></td>
            <td><button class="btn" @click=${() => act("learned_rule_update", { kind, key, category: null }, { confirm: `Delete the rule “${label}”?`, done: "Rule deleted" })}>Delete</button></td></tr>`)}</tbody></table></div>`
          : html`<div class="empty">No learned rules yet.</div>`}
      </div>

      <div class="card">
        <h2>Port reference</h2>
        <table class="small"><thead><tr><th>Port</th><th>What</th><th>Why it matters</th></tr></thead>
          <tbody>${PORTS.map(([p, n, w, tone]) => html`<tr><td class="mono">${p}</td><td>${tone ? html`<span class="badge ${tone}">${n}</span>` : n}</td><td>${w}</td></tr>`)}</tbody></table>
      </div>

      <details class="card"><summary>Troubleshooting</summary>
        <div class="row" style="margin-top:8px"><button class="btn" @click=${() => this.showDebug("traffic_rules_debug")}>Show traffic rules</button>
          <button class="btn" @click=${() => this.showDebug("firewall_rules_debug")}>Show firewall rules</button></div>
        ${this.debug ? html`<pre class="mono" style="max-height:400px;overflow:auto;white-space:pre-wrap">${this.debug}</pre>` : nothing}
      </details>
    `;
  }

  static styles = [shared];
}
