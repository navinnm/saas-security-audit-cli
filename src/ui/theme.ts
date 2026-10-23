/** Colours, gradients, and labels shared by the live panel and the final report. */

const env = process.env;
export const COLOR = !("NO_COLOR" in env) && env.TERM !== "dumb" && (process.stdout.isTTY || "FORCE_COLOR" in env);
export const TRUECOLOR = COLOR && /truecolor|24bit/i.test(env.COLORTERM ?? "");

// Brand gradient, matching the plugin icon: cyan -> violet.
export const BRAND_FROM: [number, number, number] = [34, 211, 238];
export const BRAND_TO: [number, number, number] = [139, 92, 246];
export const BEAM = "#7DECFF";
export const AMBER = "#FBB024";

const sgr = (open: string, close: string) => (s: string) => (COLOR ? `\x1b[${open}m${s}\x1b[${close}m` : s);
export const c = {
  bold: sgr("1", "22"), dim: sgr("2", "22"), italic: sgr("3", "23"), underline: sgr("4", "24"),
  red: sgr("31", "39"), green: sgr("32", "39"), yellow: sgr("33", "39"), blue: sgr("34", "39"),
  magenta: sgr("35", "39"), cyan: sgr("36", "39"), gray: sgr("90", "39"), white: sgr("97", "39"),
  bgRed: sgr("41", "49"), bgYellow: sgr("43", "49"), bgBlue: sgr("44", "49"), bgGray: sgr("100", "49"), bgCyan: sgr("46", "49"),
};

export function rgb(r: number, g: number, b: number, s: string): string {
  if (!COLOR) return s;
  if (TRUECOLOR) return `\x1b[38;2;${r};${g};${b}m${s}\x1b[39m`;
  return c.cyan(s);
}

export function lerpRgb(t: number): [number, number, number] {
  return [0, 1, 2].map((i) => Math.round(BRAND_FROM[i] + (BRAND_TO[i] - BRAND_FROM[i]) * t)) as [number, number, number];
}

export const hex = ([r, g, b]: [number, number, number]) =>
  "#" + [r, g, b].map((v) => v.toString(16).padStart(2, "0")).join("");

/** Brand gradient across a string (truecolor), or plain cyan elsewhere. */
export function gradient(s: string): string {
  if (!TRUECOLOR) return COLOR ? c.cyan(s) : s;
  const chars = [...s];
  return chars.map((ch, i) => rgb(...lerpRgb(chars.length > 1 ? i / (chars.length - 1) : 0), ch)).join("");
}

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;
export const SEV_SHORT: Record<string, string> = { Critical: "CRIT", High: "HIGH", Medium: "MED", Low: "LOW", Informational: "INFO" };
/** Ink colour names per severity (for the live panel). */
export const SEV_INK: Record<string, string> = { Critical: "redBright", High: "red", Medium: "yellow", Low: "blue", Informational: "gray" };

export function sevBadge(sev: string): string {
  const label = ` ${SEV_SHORT[sev] ?? sev} `.padEnd(6);
  if (!COLOR) return `[${(SEV_SHORT[sev] ?? sev).padEnd(4)}]`;
  switch (sev) {
    case "Critical": return c.bold(c.white(c.bgRed(label)));
    case "High": return c.bold(c.red(label));
    case "Medium": return c.bold(c.yellow(label));
    case "Low": return c.blue(label);
    default: return c.gray(label);
  }
}

export const CONTROL_SHORT = [
  "Tenant isolation / RLS", "Route authN / authZ", "Server-side enforcement", "Rate limiting",
  "Input validation & encoding", "Parameterized queries", "CORS policy", "HTTPS & cookies",
  "IDOR / BOLA", "Debug & error handling", "Anti-automation", "Audit logging",
  "Private storage", "Admin protection", "Dependencies & secrets", "File uploads",
  "Independent review", "Security headers", "Webhook security", "SSRF & egress",
  "JWT & sessions", "AI / LLM security",
];

/** Live-panel categories, keyed by a finding's primary control. */
export const GROUPS: { label: string; controls: number[] }[] = [
  { label: "Secrets & dependencies", controls: [15] },
  { label: "Tenant isolation & access", controls: [1, 2, 3, 9, 14, 21] },
  { label: "Injection & input", controls: [5, 6] },
  { label: "Transport & config", controls: [4, 7, 8, 10, 11, 12, 18] },
  { label: "Storage & webhooks", controls: [13, 16, 19] },
  { label: "SSRF & AI / LLM", controls: [20, 22] },
];

export const groupOf = (control: number) => GROUPS.findIndex((g) => g.controls.includes(control));
