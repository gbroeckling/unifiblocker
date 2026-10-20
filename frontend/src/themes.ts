// PadSpan's looks, for this panel only. By default the panel follows the
// Home Assistant theme; picking one of these sets HA's own colour variables
// on the panel, so everything inside follows without its own styling.
//
// The colours are PadSpan's: Night is its palette, and Day, Graphite, Ocean,
// Dusk and High contrast are what PadSpan's day_theme.js turns Night's
// colours into. Light is PadSpan's accessibility inversion of Night. The
// green accent and the colours that mean something (amber, red, blue) are
// kept, as in PadSpan.

export type ThemeName = "ha" | "night" | "day" | "graphite" | "ocean" | "dusk" | "contrast" | "light";

export const THEME_NAMES: [ThemeName, string][] = [
  ["ha", "Home Assistant"], ["night", "Night"], ["day", "Day"], ["graphite", "Graphite"],
  ["ocean", "Ocean"], ["dusk", "Dusk"], ["contrast", "High contrast"], ["light", "Light (inverted)"],
];

interface Palette {
  bg: string; card: string; inset: string; line: string; header: string;
  text: string; text2: string; accent: string; onAccent: string;
  warn: string; error: string; info: string; dark: boolean;
}

const NIGHT: Palette = {
  bg: "#0a150e", card: "#0f1a12", inset: "#0c1a0e", line: "#1b3526", header: "#071008",
  text: "#e2e8f0", text2: "#94a3b8", accent: "#52b788", onAccent: "#071008",
  warn: "#f59e0b", error: "#f87171", info: "#60a5fa", dark: true,
};

const PALETTES: Record<Exclude<ThemeName, "ha" | "light">, Palette> = {
  night: NIGHT,
  day: {
    bg: "#f0f2f1", card: "#ebeeec", inset: "#ecefed", line: "#d4e2da", header: "#f4f6f4",
    text: "#0f151d", text2: "#47566b", accent: "#398964", onAccent: "#ffffff",
    warn: "#ba7808", error: "#b90909", info: "#0657bc", dark: false,
  },
  graphite: { ...NIGHT, bg: "#0f0f10", card: "#131416", inset: "#121314", line: "#26272a", header: "#0b0b0c", text: "#e8e9ea", text2: "#a2a5aa" },
  ocean: { ...NIGHT, bg: "#080f17", card: "#0d141c", inset: "#0a121c", line: "#172639", header: "#060b11", text2: "#94a4b8" },
  dusk: { ...NIGHT, bg: "#110916", card: "#160e1b", inset: "#150b1b", line: "#2c1a36", header: "#0d0710", text: "#e9e5ed", text2: "#a69cb0" },
  contrast: {
    bg: "#070707", card: "#090909", inset: "#090909", line: "#a8a8a8", header: "#050505",
    text: "#ffffff", text2: "#dbdbdb", accent: "#93d2b5", onAccent: "#000000",
    warn: "#f9c56c", error: "#f87171", info: "#6babfa", dark: true,
  },
};

const VARS = (p: Palette): Record<string, string> => ({
  "--primary-background-color": p.bg,
  "--secondary-background-color": p.inset,
  "--card-background-color": p.card,
  "--ha-card-background": p.card,
  "--divider-color": p.line,
  "--ha-card-border-color": p.line,
  "--primary-text-color": p.text,
  "--secondary-text-color": p.text2,
  "--primary-color": p.accent,
  "--text-primary-color": p.onAccent,
  "--app-header-background-color": p.header,
  "--app-header-text-color": p.text,
  "--success-color": p.accent,
  "--warning-color": p.warn,
  "--error-color": p.error,
  "--info-color": p.info,
});

const KEY = "unifiblocker.theme";
const ALL_VARS = Object.keys(VARS(NIGHT));

export function savedTheme(): ThemeName {
  try {
    const v = localStorage.getItem(KEY) as ThemeName | null;
    return v && THEME_NAMES.some(([k]) => k === v) ? v : "ha";
  } catch {
    return "ha";
  }
}

export function saveTheme(name: ThemeName): void {
  try {
    localStorage.setItem(KEY, name);
  } catch {
    /* private mode: the choice lasts until the page reloads */
  }
}

/** Put *name*'s colours on the panel element (or take them off for "ha"). */
export function applyTheme(el: HTMLElement, name: ThemeName): void {
  for (const v of ALL_VARS) el.style.removeProperty(v);
  el.style.removeProperty("color-scheme");
  el.style.filter = "";
  if (name === "ha") return;
  const p = name === "light" ? NIGHT : PALETTES[name];
  for (const [k, v] of Object.entries(VARS(p))) el.style.setProperty(k, v);
  el.style.setProperty("color-scheme", p.dark ? "dark" : "light");
  if (name === "light") el.style.filter = "invert(1) hue-rotate(180deg)";
}
