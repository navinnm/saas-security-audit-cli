/**
 * Terminal design system (from the "saas-audit CLI Redesign" canvas): GitHub-dark palette,
 * a five-stop rainbow brand gradient, severity badges, and layout helpers.
 * Truecolor when the terminal supports it, 256-colour otherwise, plain text with NO_COLOR.
 */

const env = process.env;
export const COLOR = !("NO_COLOR" in env) && env.TERM !== "dumb" && (Boolean(process.stdout.isTTY) || "FORCE_COLOR" in env);
export const TRUECOLOR = COLOR && (/truecolor|24bit/i.test(env.COLORTERM ?? "") || /^(iTerm|vscode|WezTerm|ghostty)/i.test(env.TERM_PROGRAM ?? ""));

export const P = {
  text: "#D1D7E0", muted: "#8B949E", dim: "#7D8590", accent: "#79C0FF", accent2: "#A5D6FF", ok: "#3FB950",
  crit: "#FF7B85", high: "#FFA657", med: "#E3B341", low: "#79C0FF", line: "#30363D", track: "#2A323D",
  glow: "#E6F1FF", blocked: "#5C2329", warnBox: "#5A3A12", infoBox: "#1F3B5C",
};
export const RAINBOW = ["#3FB950", "#E3B341", "#FF5CAA", "#79C0FF", "#BC8CFF"];

const hexRgb = (hex: string): [number, number, number] => {
  const n = Number.parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const toHex = ([r, g, b]: number[]) => "#" + [r, g, b].map((v) => Math.round(v).toString(16).padStart(2, "0")).join("");

function ansi256([r, g, b]: [number, number, number]): number {
  if (Math.abs(r - g) < 10 && Math.abs(g - b) < 10) {
    if (r < 8) return 16;
    if (r > 248) return 231;
    return Math.round(((r - 8) / 247) * 24) + 232;
  }
  const q = (v: number) => Math.round((v / 255) * 5);
  return 16 + 36 * q(r) + 6 * q(g) + q(b);
}

const code = (hex: string, layer: 38 | 48) => {
  const rgb = hexRgb(hex);
  return TRUECOLOR ? `${layer};2;${rgb.join(";")}` : `${layer};5;${ansi256(rgb)}`;
};

/** Foreground colour. */
export const fg = (hex: string, s: string) => (COLOR && s ? `\x1b[${code(hex, 38)}m${s}\x1b[39m` : s);
/** Background + foreground colour. */
export const bg = (bgHex: string, fgHex: string, s: string) =>
  COLOR && s ? `\x1b[${code(bgHex, 48)};${code(fgHex, 38)}m${s}\x1b[49;39m` : s;
const sgr = (open: string, close: string) => (s: string) => (COLOR && s ? `\x1b[${open}m${s}\x1b[${close}m` : s);
export const bold = sgr("1", "22");
export const underline = sgr("4", "24");

export const c = {
  bold, underline,
  text: (s: string) => fg(P.text, s), muted: (s: string) => fg(P.muted, s), dim: (s: string) => fg(P.dim, s),
  accent: (s: string) => fg(P.accent, s), ok: (s: string) => fg(P.ok, s), crit: (s: string) => fg(P.crit, s),
  high: (s: string) => fg(P.high, s), med: (s: string) => fg(P.med, s), low: (s: string) => fg(P.low, s),
  // Aliases kept for older call sites.
  gray: (s: string) => fg(P.muted, s), cyan: (s: string) => fg(P.accent, s), green: (s: string) => fg(P.ok, s),
  yellow: (s: string) => fg(P.med, s), red: (s: string) => fg(P.crit, s),
};

/** Colour at position t (0..1) along the rainbow brand gradient. */
export function rainbowAt(t: number): string {
  const stops = RAINBOW.map(hexRgb);
  const x = Math.max(0, Math.min(1, t)) * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(x));
  const f = x - i;
  return toHex(stops[i].map((v, k) => v + (stops[i + 1][k] - v) * f));
}

/** Rainbow gradient across a string. */
export function gradient(s: string): string {
  if (!COLOR) return s;
  const chars = [...s];
  return chars.map((ch, i) => (ch === " " ? ch : fg(rainbowAt(chars.length > 1 ? i / (chars.length - 1) : 0), ch))).join("");
}

/** Multi-line art with one gradient across columns (so letters line up vertically). */
export function gradientBlock(lines: string[]): string[] {
  const width = Math.max(...lines.map((l) => [...l].length));
  return lines.map((l) => (COLOR ? [...l].map((ch, i) => (ch === " " ? ch : fg(rainbowAt(i / Math.max(1, width - 1)), ch))).join("") : l));
}

// ---------- severity ----------

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;
export const SEV_SHORT: Record<string, string> = { Critical: "CRIT", High: "HIGH", Medium: "MED", Low: "LOW", Informational: "INFO" };
export const SEV_LOWER: Record<string, string> = { Critical: "crit", High: "high", Medium: "med", Low: "low", Informational: "info" };
export const SEV_COLOR: Record<string, string> = { Critical: P.crit, High: P.high, Medium: P.med, Low: P.low, Informational: P.muted };
const BADGE: Record<string, [string, string]> = {
  Critical: ["#F85149", "#140203"], High: ["#FFA657", "#1A0D02"], Medium: ["#E3B341", "#1A1402"],
  Low: ["#1F3B5C", "#A5D6FF"], Informational: ["#21262D", "#8B949E"],
};

/** 6-cell severity badge: ` CRIT `. */
export function badge(sev: string): string {
  const label = SEV_SHORT[sev] ?? sev;
  const cell = label.padStart(Math.ceil((6 + label.length) / 2)).padEnd(6);
  if (!COLOR) return `[${label}]`.padEnd(6);
  const [b, f] = BADGE[sev] ?? BADGE.Informational;
  return bold(bg(b, f, cell));
}
export const sevText = (sev: string, s: string) => fg(SEV_COLOR[sev] ?? P.muted, s);

// ---------- layout ----------

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;
export const vlen = (s: string) => [...s.replace(ANSI, "")].length;
export const padEnd = (s: string, w: number) => s + " ".repeat(Math.max(0, w - vlen(s)));
export const padStart = (s: string, w: number) => " ".repeat(Math.max(0, w - vlen(s))) + s;
/** Truncate plain text to `max` cells, ending in an ellipsis. */
export const fit = (plain: string, max: number) =>
  max <= 1 ? "…" : [...plain].length <= max ? plain : [...plain].slice(0, max - 1).join("") + "…";
/** Thousands separators: 9544 → "9,544". */
export const num = (n: number) => n.toLocaleString("en-US");
export const termWidth = (cols?: number) => Math.max(80, Math.min(cols ?? 120, 132));

/** Left page margin for every interactive screen, so nothing hugs the terminal edge. */
export const MARGIN = "  ";
/** Usable width inside the left and right margins. */
export const contentWidth = (cols?: number) => termWidth(cols) - 2 * MARGIN.length;
export const withMargin = (lines: string[]) => lines.map((l) => (l ? MARGIN + l : l));

/** Spread two pieces across a line: left … right. */
export const spread = (left: string, right: string, width: number) =>
  left + " ".repeat(Math.max(2, width - vlen(left) - vlen(right))) + right;

export const label = (s: string) => fg(P.muted, s.toUpperCase());

/** Rounded box; `dashed` uses ┄ edges. Lines are padded to the inner width. */
export function box(lines: string[], width: number, color = P.line, dashed = false): string[] {
  const inner = width - 4;
  const h = dashed ? "┄" : "─";
  const v = dashed ? "┆" : "│";
  return [
    fg(color, "╭" + h.repeat(width - 2) + "╮"),
    ...lines.map((l) => `${fg(color, v)} ${padEnd(l, inner)} ${fg(color, v)}`),
    fg(color, "╰" + h.repeat(width - 2) + "╯"),
  ];
}

/** Proportional bar of `width` cells using eighth blocks. */
export function bar(value: number, max: number, width: number): string {
  if (max <= 0 || value <= 0) return "";
  const exact = (value / max) * width;
  const full = Math.floor(exact);
  const eighths = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"][Math.floor((exact - full) * 8)];
  const out = "█".repeat(full) + eighths;
  return out || "▏";
}

/** Rainbow progress line: filled part in the brand gradient, a glowing head, then a dim track. */
export function rainbowProgress(fraction: number, width: number): string {
  const filled = Math.round(Math.max(0, Math.min(1, fraction)) * width);
  if (!COLOR) return "━".repeat(filled) + "─".repeat(width - filled);
  let out = "";
  for (let i = 0; i < width; i++) {
    if (i < filled - 1 || (filled === width && i === width - 1)) out += fg(rainbowAt(i / Math.max(1, width - 1)), "━");
    else if (i === filled - 1) out += fg(P.glow, "●");
    else out += fg(P.track, "━");
  }
  return out;
}

export const FULGID = "https://www.fulgid.in";
export const poweredBy = (withHost = true) =>
  `${c.muted("powered by")} ${bold(c.accent("Fulgid"))}${withHost ? " " + c.dim("fulgid.in") : ""}`;

/** The six areas that group the 22 controls (a finding's primary control decides its area). */
export const GROUPS: { label: string; controls: number[] }[] = [
  { label: "Secrets & dependencies", controls: [15] },
  { label: "Tenant isolation & access", controls: [1, 2, 3, 9, 14, 21] },
  { label: "Injection & input", controls: [5, 6] },
  { label: "Transport & config", controls: [4, 7, 8, 10, 11, 12, 18] },
  { label: "Storage & webhooks", controls: [13, 16, 19] },
  { label: "SSRF & AI / LLM", controls: [20, 22] },
];
export const groupOf = (control: number) => GROUPS.findIndex((g) => g.controls.includes(control));

/** Ink colour (hex) for a severity in the live panel. */
export const SEV_INK = SEV_COLOR;
