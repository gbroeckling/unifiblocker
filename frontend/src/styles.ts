import { css } from "lit";

// Home Assistant theme variables only, so light, dark and custom themes all
// work. Status is always text + colour, never colour alone.
export const shared = css`
  :host {
    --ub-ok: var(--success-color, #43a047);
    --ub-warn: var(--warning-color, #ffa000);
    --ub-bad: var(--error-color, #db4437);
    --ub-info: var(--info-color, #039be5);
    --ub-muted: var(--secondary-text-color);
    --ub-line: var(--divider-color, rgba(127, 127, 127, 0.25));
    --ub-card: var(--card-background-color, var(--ha-card-background, #fff));
    --ub-radius: var(--ha-card-border-radius, 12px);
    color: var(--primary-text-color);
    font-family: var(--paper-font-body1_-_font-family, Roboto, system-ui, sans-serif);
  }
  h1 { font-size: 22px; font-weight: 500; margin: 0 0 4px; }
  h2 { font-size: 16px; font-weight: 500; margin: 0 0 12px; }
  h3 { font-size: 14px; font-weight: 500; margin: 12px 0 6px; }
  p { margin: 0 0 8px; line-height: 1.45; }
  .sub { color: var(--ub-muted); font-size: 13px; margin-bottom: 16px; }
  .muted { color: var(--ub-muted); }
  .small { font-size: 12px; }
  .mono { font-family: var(--code-font-family, ui-monospace, Consolas, monospace); font-size: 12px; }
  .card {
    background: var(--ub-card);
    border-radius: var(--ub-radius);
    box-shadow: var(--ha-card-box-shadow, none);
    border: 1px solid var(--ha-card-border-color, var(--ub-line));
    padding: 16px;
    margin-bottom: 16px;
  }
  .grid { display: grid; gap: 16px; }
  .grid.two { grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); }
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .tile {
    background: var(--ub-card); border: 1px solid var(--ha-card-border-color, var(--ub-line));
    border-radius: var(--ub-radius); padding: 12px 14px; text-align: left; color: inherit; font: inherit;
  }
  button.tile { cursor: pointer; }
  button.tile:hover, button.tile:focus-visible { border-color: var(--primary-color); outline: none; }
  .tile .n { font-size: 26px; font-weight: 500; line-height: 1.2; }
  .tile .l { color: var(--ub-muted); font-size: 12px; }
  .tile.bad .n { color: var(--ub-bad); }
  .tile.warn .n { color: var(--ub-warn); }
  .tile.ok .n { color: var(--ub-ok); }
  .badge {
    display: inline-flex; align-items: center; gap: 4px; padding: 1px 8px; border-radius: 10px;
    font-size: 11px; font-weight: 500; line-height: 18px; white-space: nowrap;
    background: color-mix(in srgb, var(--ub-muted) 18%, transparent); color: var(--primary-text-color);
  }
  .badge.ok { background: color-mix(in srgb, var(--ub-ok) 20%, transparent); }
  .badge.warn { background: color-mix(in srgb, var(--ub-warn) 25%, transparent); }
  .badge.bad { background: color-mix(in srgb, var(--ub-bad) 22%, transparent); }
  .badge.info { background: color-mix(in srgb, var(--ub-info) 20%, transparent); }
  button.btn, a.btn {
    display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--ub-line); border-radius: 8px;
    background: transparent; color: var(--primary-text-color); padding: 6px 12px; font: inherit; font-size: 13px;
    cursor: pointer; text-decoration: none;
  }
  button.btn:hover, button.btn:focus-visible { border-color: var(--primary-color); outline: none; }
  button.btn.primary { background: var(--primary-color); border-color: var(--primary-color); color: var(--text-primary-color, #fff); }
  button.btn.danger { color: var(--ub-bad); border-color: color-mix(in srgb, var(--ub-bad) 50%, transparent); }
  button.btn:disabled { opacity: 0.5; cursor: default; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .spacer { flex: 1; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--ub-line); vertical-align: top; }
  th { color: var(--ub-muted); font-weight: 500; font-size: 12px; white-space: nowrap; }
  th button { all: unset; cursor: pointer; }
  th button:focus-visible { outline: 2px solid var(--primary-color); }
  tbody tr.click { cursor: pointer; }
  tbody tr.click:hover, tbody tr.click:focus-visible { background: color-mix(in srgb, var(--primary-color) 7%, transparent); outline: none; }
  .scroll { overflow-x: auto; }
  .empty { color: var(--ub-muted); padding: 16px 0; text-align: center; }
  .chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
  .chip {
    border: 1px solid var(--ub-line); border-radius: 16px; padding: 4px 12px; background: transparent;
    color: inherit; font: inherit; font-size: 13px; cursor: pointer;
  }
  .chip[aria-pressed="true"] { background: var(--primary-color); border-color: var(--primary-color); color: var(--text-primary-color, #fff); }
  input[type="search"], input[type="text"], select {
    font: inherit; font-size: 14px; padding: 7px 10px; border-radius: 8px; border: 1px solid var(--ub-line);
    background: var(--ub-card); color: var(--primary-text-color);
  }
  .kv { display: grid; grid-template-columns: 120px 1fr; gap: 4px 12px; font-size: 13px; }
  .kv > :nth-child(odd) { color: var(--ub-muted); }
  .rec { border-left: 4px solid var(--ub-line); padding: 8px 12px; margin-bottom: 10px; }
  .rec.critical { border-color: var(--ub-bad); }
  .rec.high { border-color: var(--ub-warn); }
  .rec.medium { border-color: var(--ub-info); }
  .rec .t { font-weight: 500; }
  .rec .d { color: var(--ub-muted); font-size: 13px; white-space: pre-line; margin: 4px 0; }
  button.linkish { all: unset; cursor: pointer; color: var(--primary-color); }
  button.linkish:focus-visible { outline: 2px solid var(--primary-color); }
  .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
`;
