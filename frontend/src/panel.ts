import { LitElement, css, html, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { fetchSnapshot, ws, UbError } from "./api";
import { shared } from "./styles";
import type { Client, Hass, Snapshot } from "./types";
import "./views/overview";
import "./views/devices";
import "./views/device-detail";
import "./views/cameras";
import "./views/home";
import "./views/security";
import "./views/network";
import "./views/mining";
import "./views/tools";

export const VERSION = "0.3.61";

type View = "overview" | "devices" | "cameras" | "home" | "security" | "network" | "mining" | "tools";
const VIEWS: { id: View; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "M12 3 2 12h3v8h6v-6h2v6h6v-8h3z" },
  { id: "devices", label: "Devices", icon: "M4 6h16v10H4zM2 18h20v2H2z" },
  { id: "cameras", label: "Cameras", icon: "M17 10.5V7a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3.5l4 4v-11z" },
  { id: "home", label: "Home", icon: "M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" },
  { id: "security", label: "Security", icon: "M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5z" },
  { id: "network", label: "Network", icon: "M17 16l-4-4V8.8a3 3 0 1 0-2 0V12l-4 4H3v5h5v-3.1l4-4.1 4 4.1V21h5v-5z" },
  { id: "mining", label: "Mining", icon: "M14.8 2.2 13.4 3.6l7 7 1.4-1.4zM12 5 2 15l7 7 10-10z" },
  { id: "tools", label: "Tools", icon: "M22.7 19 13.6 9.9a6.4 6.4 0 0 0-8.4-8.4l4.3 4.3-3 3-4.4-4.3a6.4 6.4 0 0 0 8.4 8.4l9.1 9.1z" },
];

import type { ActOptions, Ctx } from "./ui";
import { applyTheme, effectiveTheme, savedTheme, saveTheme, type ThemeName } from "./themes";

/** Root of the sidebar panel. Owns the data, actions, toasts, the confirm
 *  dialog and the device drawer; the views just render and call act(). */
@customElement("unifiblocker-panel")
export class UniFiBlockerPanel extends LitElement {
  @property({ attribute: false }) hass!: Hass;
  @property({ type: Boolean }) narrow = false;
  @state() private view: View = "overview";
  @state() private snap: Snapshot = {
    overview: {}, clients: [], recs: {}, localnet: {}, miners: { rigs: [], summary: {} }, scans: {},
    report: null, learned: null, licence: { pro: false, has_key: false }, loaded: false, error: "", updated: 0,
  };
  @state() private toast: { text: string; bad: boolean } | null = null;
  @state() private ask: { text: string; danger: boolean; resolve: (ok: boolean) => void } | null = null;
  @state() private openMac: string | null = null;
  @state() private theme: ThemeName = savedTheme();
  @state() private devicesFilter = "all";
  private timer?: number;
  private toastTimer?: number;
  private lastReportedView = "";

  connectedCallback(): void {
    super.connectedCallback();
    applyTheme(this, this.theme);
    const fromUrl = new URLSearchParams(location.search).get("view") as View | null;
    if (fromUrl && VIEWS.some((v) => v.id === fromUrl)) this.view = fromUrl;
    document.addEventListener("visibilitychange", this.onVisibility);
    this.schedule(0);
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    document.removeEventListener("visibilitychange", this.onVisibility);
    window.clearTimeout(this.timer);
  }

  // Poll every 30 s while the panel is visible; stop while it's hidden.
  private onVisibility = () => {
    if (document.visibilityState === "visible") this.schedule(0);
    else window.clearTimeout(this.timer);
  };

  private schedule(ms: number) {
    window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => this.load(), ms);
  }

  async load() {
    if (!this.hass) return this.schedule(500);
    try {
      this.snap = await fetchSnapshot(this.hass);
      applyTheme(this, effectiveTheme(this.theme, this.snap.licence.pro));
    } catch (err: any) {
      this.snap = { ...this.snap, error: err?.message ?? String(err) };
    }
    if (document.visibilityState === "visible") this.schedule(30000);
  }

  /** Run a write command. Confirms first if asked, shows the outcome, refreshes. */
  act = async (type: string, payload: Record<string, unknown> = {}, opts: ActOptions = {}): Promise<any> => {
    if (opts.confirm && !(await this.confirm(opts.confirm, opts.danger))) return null;
    try {
      const res = await ws(this.hass, type, payload);
      if (res && res.ok === false) throw new UbError("failed", res.error || "The controller refused it");
      if (opts.done) this.say(opts.done);
      if (opts.refresh !== false) this.schedule(800);
      return res ?? {};
    } catch (err: any) {
      this.say(err instanceof UbError ? err.message : String(err), true);
      return null;
    }
  };

  say = (text: string, bad = false) => {
    this.toast = { text, bad };
    window.clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => (this.toast = null), bad ? 8000 : 4000);
  };

  confirm = (text: string, danger = false) =>
    new Promise<boolean>((resolve) => (this.ask = { text, danger, resolve }));

  openDevice = (mac: string) => (this.openMac = mac.toLowerCase());

  go = (view: View, filter?: string) => {
    this.view = view;
    if (filter) this.devicesFilter = filter;
    this.renderRoot.querySelector("main")?.scrollTo?.(0, 0);
  };

  protected updated() {
    if (this.snap.report?.enabled && this.view !== this.lastReportedView) {
      this.lastReportedView = this.view;
      ws(this.hass, "report_view", { view: this.view }).catch(() => undefined);
    }
  }

  private setTheme = (name: ThemeName) => {
    this.theme = name;
    saveTheme(name);
    applyTheme(this, effectiveTheme(name, this.snap.licence.pro));
  };

  private ctxObj(): Ctx {
    return { hass: this.hass, snap: this.snap, act: this.act, open: this.openDevice, go: this.go, say: this.say,
      confirm: this.confirm, reload: () => this.schedule(800), theme: this.theme, setTheme: this.setTheme };
  }

  private answer(ok: boolean) {
    this.ask?.resolve(ok);
    this.ask = null;
  }

  private renderView() {
    const common = this.ctxObj();
    switch (this.view) {
      case "overview": return html`<ub-overview .ctx=${common}></ub-overview>`;
      case "devices": return html`<ub-devices .ctx=${common} .filter=${this.devicesFilter} @filter=${(e: CustomEvent) => (this.devicesFilter = e.detail)}></ub-devices>`;
      case "cameras": return html`<ub-cameras .ctx=${common}></ub-cameras>`;
      case "home": return html`<ub-home .ctx=${common}></ub-home>`;
      case "security": return html`<ub-security .ctx=${common}></ub-security>`;
      case "network": return html`<ub-network .ctx=${common}></ub-network>`;
      case "mining": return html`<ub-mining .ctx=${common}></ub-mining>`;
      case "tools": return html`<ub-tools .ctx=${common}></ub-tools>`;
    }
  }

  render() {
    const o = this.snap.overview;
    const leaking = this.snap.clients.filter((c) => c.containment === "leaking").length;
    const critical = this.snap.recs.critical_count || 0;
    const open: Client | undefined = this.openMac ? this.snap.clients.find((c) => c.mac.toLowerCase() === this.openMac) : undefined;
    return html`
      <div class="toolbar">
        ${this.narrow ? html`<ha-menu-button .hass=${this.hass} .narrow=${this.narrow}></ha-menu-button>` : nothing}
        <div class="title">UniFi Blocker</div>
        <span class="status ${o.health?.connection_ok === false ? "bad" : ""}" title="Controller">
          ${!this.snap.loaded ? "Loading…" : o.health?.connection_ok === false ? "Controller unreachable" : `${o.health?.hostname || "Controller"} · ${o.total_clients ?? 0} devices`}
        </span>
        <button class="icon" aria-label="Refresh" title="Refresh" @click=${() => this.load()}>
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M17.65 6.35A8 8 0 1 0 19.7 14h-2.1a6 6 0 1 1-1.4-6.2L13 11h7V4z"/></svg>
        </button>
      </div>
      <nav aria-label="UniFi Blocker sections">
        ${VIEWS.map((v) => html`
          <button class="tab" aria-current=${this.view === v.id ? "page" : "false"} @click=${() => this.go(v.id)}>
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><path fill="currentColor" d=${v.icon}/></svg>
            <span>${v.label}</span>
            ${v.id === "security" && critical ? html`<span class="dot" aria-label="${critical} critical">${critical}</span>` : nothing}
            ${v.id === "cameras" && leaking ? html`<span class="dot" aria-label="${leaking} not contained">${leaking}</span>` : nothing}
            ${v.id === "devices" && (o.new_count || 0) > 0 ? html`<span class="dot soft">${o.new_count}</span>` : nothing}
          </button>`)}
      </nav>
      <main>
        ${this.snap.error ? html`<div class="card error" role="alert">Couldn't load data: ${this.snap.error}</div>` : nothing}
        ${this.renderView()}
        <footer class="muted small">UniFi Blocker ${VERSION}${this.snap.updated ? html` · updated ${new Date(this.snap.updated).toLocaleTimeString()}` : nothing}</footer>
      </main>
      ${open ? html`<ub-device-detail .ctx=${this.ctxObj()} .client=${open} @close=${() => (this.openMac = null)}></ub-device-detail>` : nothing}
      ${this.ask ? html`
        <div class="scrim" @click=${() => this.answer(false)}></div>
        <div class="dialog" role="alertdialog" aria-modal="true" aria-label="Confirm">
          <p>${this.ask.text}</p>
          <div class="row"><span class="spacer"></span>
            <button class="btn" @click=${() => this.answer(false)}>Cancel</button>
            <button class="btn ${this.ask.danger ? "danger" : "primary"}" @click=${() => this.answer(true)}>Continue</button>
          </div>
        </div>` : nothing}
      ${this.toast ? html`<div class="toast ${this.toast.bad ? "bad" : ""}" role="status">${this.toast.text}</div>` : nothing}
    `;
  }

  static styles = [shared, css`
    :host { display: flex; flex-direction: column; height: 100%; background: var(--primary-background-color); }
    .toolbar {
      display: flex; align-items: center; gap: 8px; height: var(--header-height, 56px); padding: 0 12px 0 16px;
      background: var(--app-header-background-color, var(--primary-color)); color: var(--app-header-text-color, #fff);
      box-sizing: border-box; flex-shrink: 0;
    }
    .title { font-size: 20px; flex: 1; }
    .status { font-size: 13px; opacity: 0.9; }
    .status.bad { font-weight: 600; }
    button.icon { all: unset; cursor: pointer; padding: 8px; border-radius: 50%; display: flex; }
    button.icon:focus-visible { outline: 2px solid currentColor; }
    nav {
      display: flex; gap: 2px; padding: 0 8px; overflow-x: auto; flex-shrink: 0;
      background: var(--app-header-background-color, var(--primary-color)); color: var(--app-header-text-color, #fff);
    }
    .tab {
      all: unset; display: flex; align-items: center; gap: 6px; padding: 10px 14px; cursor: pointer; white-space: nowrap;
      border-bottom: 3px solid transparent; opacity: 0.8; font-size: 14px; position: relative;
    }
    .tab[aria-current="page"] { opacity: 1; border-bottom-color: currentColor; }
    .tab:hover, .tab:focus-visible { opacity: 1; }
    .tab:focus-visible { outline: 2px solid currentColor; outline-offset: -2px; }
    .dot { background: var(--error-color, #db4437); color: #fff; border-radius: 10px; font-size: 11px; padding: 0 6px; line-height: 16px; }
    .dot.soft { background: color-mix(in srgb, currentColor 22%, transparent); color: inherit; }
    main { flex: 1; overflow-y: auto; padding: 16px; box-sizing: border-box; }
    @media (min-width: 900px) { main { padding: 24px; } }
    main > * { max-width: 1400px; margin-left: auto; margin-right: auto; display: block; }
    footer { text-align: center; padding: 12px 0 4px; }
    .card.error { border-color: var(--error-color); }
    .scrim { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.4); z-index: 10; }
    .dialog {
      position: fixed; z-index: 11; left: 50%; top: 30%; transform: translate(-50%, -30%); width: min(440px, 90vw);
      background: var(--ub-card); border-radius: var(--ub-radius); padding: 20px; box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
    }
    .toast {
      position: fixed; z-index: 12; left: 50%; bottom: 24px; transform: translateX(-50%); max-width: min(560px, 90vw);
      background: var(--primary-text-color); color: var(--primary-background-color); padding: 10px 16px; border-radius: 8px;
      font-size: 14px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .toast.bad { background: var(--error-color, #db4437); color: #fff; }
  `];
}
