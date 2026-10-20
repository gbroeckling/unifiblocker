import type { ThemeName } from "./themes";
import { html, nothing, svg, type TemplateResult } from "lit";
import type { Client, Hass, Rec, Snapshot } from "./types";
import { bytes, name } from "./format";

export interface ActOptions {
  confirm?: string;
  danger?: boolean;
  done?: string;
  refresh?: boolean;
}

/** What every view gets from the panel. */
export interface Ctx {
  hass: Hass;
  snap: Snapshot;
  act: (type: string, payload?: Record<string, unknown>, opts?: ActOptions) => Promise<any>;
  open: (mac: string) => void;
  go: (view: any, filter?: string) => void;
  say: (text: string, bad?: boolean) => void;
  confirm: (text: string, danger?: boolean) => Promise<boolean>;
  reload: () => void;
  theme: ThemeName;
  setTheme: (name: ThemeName) => void;
}

export function sparkline(series: number[] | null | undefined, w = 3, h = 22): TemplateResult | typeof nothing {
  if (!series || !series.length) return nothing;
  const max = Math.max(...series, 1);
  const total = series.reduce((a, b) => a + b, 0);
  return html`<svg width=${series.length * (w + 1)} height=${h} role="img"
    aria-label="Traffic per hour over 24 hours, ${bytes(total)} total" style="vertical-align:middle;color:var(--primary-color)">
    ${series.map((v, i) => {
      const bh = Math.max(1, Math.round((h * v) / max));
      return svg`<rect x=${i * (w + 1)} y=${h - bh} width=${w} height=${bh} fill="currentColor" opacity=${i === series.length - 1 ? 1 : 0.55}></rect>`;
    })}
  </svg>`;
}

export const STATE_BADGE: Record<string, string> = { new: "warn", trusted: "ok", ignored: "", quarantined: "bad" };

export function stateBadge(c: Client) {
  if (c.blocked && c.state !== "quarantined") return html`<span class="badge bad">blocked</span>`;
  return html`<span class="badge ${STATE_BADGE[c.state] ?? ""}">${c.state}</span>`;
}

export function containmentBadge(c: Client) {
  switch (c.containment) {
    case "holding": return html`<span class="badge ok">contained</span>`;
    case "quiet": return html`<span class="badge ok">contained · quiet</span>`;
    case "leaking": return html`<span class="badge bad">NOT contained</span>`;
    default: return c.is_camera ? html`<span class="badge warn">internet open</span>` : nothing;
  }
}

export function vulnBadge(c: Client) {
  const w = c.vulns?.worst;
  if (w === "affected") return html`<span class="badge bad">exploited bug</span>`;
  if (w === "likely") return html`<span class="badge bad">likely exploited bug</span>`;
  if (w === "check") return html`<span class="badge warn">check firmware</span>`;
  if ((c.vulns?.firmware_age_years ?? 0) >= 5) return html`<span class="badge warn">firmware ${c.vulns!.firmware_age_years}y old</span>`;
  return nothing;
}

export function categoryOptions(snap: Snapshot): [string, string][] {
  const labels = snap.overview.category_labels || {};
  return Object.entries(labels).sort((a, b) => a[1].localeCompare(b[1]));
}

const PRI_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const byPriority = (a: Rec, b: Rec) => (PRI_ORDER[a.priority] ?? 5) - (PRI_ORDER[b.priority] ?? 5);

/** The button for a recommendation's action, if it has one we can do. */
export function recAction(ctx: Ctx, r: Rec, mac?: string): TemplateResult | typeof nothing {
  const m = (r.action_data?.mac as string) || mac;
  if (!m) return nothing;
  const c = ctx.snap.clients.find((x) => x.mac.toLowerCase() === m.toLowerCase());
  const label = c ? name(c) : m;
  switch (r.action) {
    case "local_only":
      return html`<button class="btn primary" @click=${() => ctx.act("localnet_assign", { mac: m, category: (r.action_data?.category as string) || c?.category || "iot" },
        { confirm: `Put ${label} on local-only? It gets a ${ctx.snap.localnet.prefix || "192.168.2"}.x address and is blocked from the internet. It reconnects to pick up the new address.`, done: `${label} is now local-only` })}>Make local-only</button>`;
    case "block_internet":
      return html`<button class="btn primary" @click=${() => ctx.act("block_internet", { mac: m },
        { confirm: `Block ${label} from the internet? It keeps its address and keeps working on your network.`, done: `${label} blocked from the internet` })}>Block internet</button>`;
    case "quarantine":
      return html`<button class="btn danger" @click=${() => ctx.act("quarantine", { mac: m }, { confirm: `Quarantine ${label}? It's blocked on the controller and can't use the network at all.`, danger: true, done: `${label} quarantined` })}>Quarantine</button>`;
    case "review":
      return html`<button class="btn" @click=${() => ctx.open(m)}>Open device</button>`;
    default:
      return c ? html`<button class="btn" @click=${() => ctx.open(m)}>Open device</button>` : nothing;
  }
}

export function recCard(ctx: Ctx, r: Rec, mac?: string) {
  const c = mac ? ctx.snap.clients.find((x) => x.mac.toLowerCase() === mac.toLowerCase()) : undefined;
  return html`<div class="rec ${r.priority}">
    <div class="row">
      <span class="badge ${r.priority === "critical" ? "bad" : r.priority === "high" ? "warn" : r.priority === "medium" ? "info" : ""}">${r.priority}</span>
      <span class="t">${r.title}</span>
      ${c ? html`<span class="muted small">· ${name(c)}</span>` : nothing}
    </div>
    <div class="d">${r.detail}</div>
    <div class="row">${recAction(ctx, r, mac)}</div>
  </div>`;
}

/** A Pro feature that's locked here: what it is, and where to unlock it. */
export function proLocked(ctx: Ctx, what: string): TemplateResult {
  return html`<p class="small"><span class="badge info">Pro</span> ${what} is part of UniFi Blocker Pro
    (${ctx.snap.licence.price || "$35 CAD/year"}).
    <button class="linkish" @click=${() => ctx.go("tools")}>Licence and free trial</button></p>`;
}
