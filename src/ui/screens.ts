/**
 * The redesigned terminal screens (canvas "saas-audit CLI Redesign"):
 *  1 Welcome · 2 Live scan frame · 3 Summary & verdict · 4 Findings by rule · 5 Fix plan · 6 CI text / GitHub annotations.
 * Each returns plain strings with ANSI colour, so they can be printed, tested, or framed by Ink.
 */
import type { Finding } from "../engine.js";
import type { Result } from "../report.js";
import { topFolder, type Profile } from "../profile.js";
import { RULE_TITLES, SEVERITY_RANK } from "../rules.js";
import {
  areas, buildView, CONTROL_SHORT, fixPlan, pathRole, RULE_SHORT, verdict, whereWorst, type Verdict, type View,
} from "../view.js";
import {
  P, SEVERITY_ORDER, SEV_LOWER, SEV_SHORT, GROUPS, badge, bar, bg, bold, box, c, fg, fit, gradientBlock, label, num, padEnd,
  padStart, poweredBy, rainbowAt, rainbowProgress, sevText, spread, termWidth, underline, vlen, FULGID,
} from "./theme.js";

export interface RunInfo {
  version: string;
  project: string;
  path: string;
  stack: string[];
  width: number;
}

const CONTROL_TINY = ["Tenancy", "Auth", "Server rules", "Rate limit", "Input", "Queries", "CORS", "Transport", "IDOR", "Errors",
  "Bots", "Audit log", "Storage", "Admin", "Secrets", "Uploads", "Review", "Headers", "Webhooks", "SSRF", "Sessions", "AI / LLM"];

const BANNER = [
  "█████  ███   ███  █████    ███  █   █ ████  █████ █████",
  "█     █   █ █   █ █       █   █ █   █ █   █   █     █",
  "█████ █████ █████ █████   █████ █   █ █   █   █     █",
  "    █ █   █ █   █     █   █   █ █   █ █   █   █     █",
  "█████ █   █ █   █ █████   █   █ █████ ████  █████   █",
];

/** Lay two blocks of lines side by side. */
function columns(left: string[], right: string[], leftWidth: number, gap = 4): string[] {
  const n = Math.max(left.length, right.length);
  return Array.from({ length: n }, (_, i) => padEnd(left[i] ?? "", leftWidth) + " ".repeat(gap) + (right[i] ?? ""));
}

/**
 * Section heading used on every screen: bold title, optional dim meta, optional right-aligned
 * note, and a thin rule underneath that ties the title to the content indented below it.
 */
export function heading(title: string, width: number, meta = "", right = ""): string[] {
  const left = `${bold(c.text(title.toUpperCase()))}${meta ? "  " + c.muted(meta) : ""}`;
  return [right ? spread(left, c.dim(right), width) : left, fg("#2A313C", "─".repeat(Math.max(4, width)))];
}
/** Content sits two columns in from its heading. */
const SUB = "  ";
const sub = (lines: string[]) => lines.map((l) => (l ? SUB + l : l));

const kv = (rows: [string, string][], keyWidth: number) => rows.map(([k, v]) => padEnd(c.muted(k), keyWidth) + v);
const indent = (lines: string[], n = 1) => lines.map((l) => " ".repeat(n) + l);
const rule = (w: number, color = P.line) => fg(color, "─".repeat(w));

// ---------- shared chrome ----------

export function headerLine(info: RunInfo): string[] {
  const w = info.width - 2;
  const right = `${c.muted("offline · read-only ·")} ${poweredBy(false)}`;
  const parts = [`${bold(c.accent("◆ SaaS Security Audit"))}  ${c.muted("v" + info.version)}`, `${bold(info.project)}  ${c.muted(info.path)}`];
  if (info.stack.length) parts.push(c.muted(info.stack.join(" · ")));
  let left = parts.join(`  ${c.dim("│")}  `);
  if (vlen(left) + vlen(right) + 4 > w) left = [parts[0], bold(info.project), ...(info.stack.length ? [c.muted(info.stack.join(" · "))] : [])].join(`  ${c.dim("│")}  `);
  const line = vlen(left) + vlen(right) + 4 > w ? left : spread(left, right, w);
  return [" " + line, " " + rule(w)];
}

export function topBand(pct: number, meta: string, width: number, done = false): string[] {
  const w = width - 2;
  const left = `${label("overall")}  ${bold(`${Math.round(pct)}%`)}${done ? "  " + c.ok("✓") : ""}`;
  return [" " + spread(left, c.muted(meta), w), " " + rainbowProgress(pct / 100, w), ""];
}

// ---------- 1 · Welcome ----------

export interface WelcomeInfo extends RunInfo {
  files: number;
  profile: Profile;
  report: string | null;
  failOn: string;
}

export function welcomeScreen(i: WelcomeInfo): string[] {
  const w = Math.min(i.width, 110);
  const inner = w - 4;
  const art = gradientBlock(BANNER).map((l) => "  " + l);
  const tag = c.muted("Offline security review for SaaS codebases. Your code never leaves this machine.");
  const rainbowRule = rainbowProgress(1, inner - 2);
  const card = box([
    "",
    ...art,
    "",
    `  ${bold("SaaS Security Audit")}   ${c.muted("v" + i.version)}`,
    "  " + tag,
    "",
    "  " + rainbowRule,
    "  " + spread(`${c.muted("powered by")} ${bold(c.accent("Fulgid"))}  ${c.dim(FULGID)}`, c.dim("read-only · offline · no telemetry"), inner - 4),
    "",
  ], w, "#232A33");

  const half = Math.floor((w - 6) / 2);
  const stack = i.stack.length ? `${fit(i.stack.join(" · "), half - 26)} ${c.ok("✓ detected")}` : c.muted("not detected · generic rules");
  const target = [...heading("Target", half - 2), ...sub(kv([
    ["Project", bold(i.project)], ["Path", fit(i.path, half - 14)], ["Stack", stack], ["Files", `${num(i.files)} found`],
  ], 12))];
  const run = [...heading("Run", half - 2), ...sub(kv([
    ["Mode", "offline · read-only"],
    ["Report", i.report ? i.report : c.muted("none · add --output report.html")],
    ["CI gate", i.failOn === "none" ? c.muted("off · add --fail-on high") : `on · fails on ${i.failOn} and above`],
    ["Controls", "22 across 6 areas"],
  ], 12))];

  const checked = checkedGrid(w - 6);

  return [
    "",
    ...indent(card),
    "",
    ...indent(columns(target, run, half), 2),
    "",
    ...indent(columns(languageBlock(i.profile, half), folderBlock(i.profile, half), half), 2),
    "",
    ...indent(heading("What gets checked", w - 4, "6 areas · 22 controls"), 2),
    ...indent(sub(checked), 2),
    "",
  ];
}

/** What each area looks for, in plain words, for the welcome screen. */
const AREA_DETAIL: Record<string, string> = {
  "Secrets & dependencies": "leaked keys · env files · lockfiles",
  "Tenant isolation & access": "RLS · route auth · IDOR · admin · sessions",
  "Injection & input": "SQL · XSS · shell · deserialization",
  "Transport & config": "CORS · cookies · TLS · headers · debug",
  "Storage & webhooks": "public buckets · uploads · signatures",
  "SSRF & AI / LLM": "outbound fetches · prompt injection",
};

/** WHAT GETS CHECKED: the six areas as an aligned two-column grid with control counts. */
function checkedGrid(width: number): string[] {
  const colW = Math.floor((width - 4) / 2);
  const cell = (g: { label: string; controls: number[] }, k: number) => {
    const count = `${g.controls.length} control${g.controls.length === 1 ? "" : "s"}`;
    return [
      spread(`${fg(rainbowAt(k / (GROUPS.length - 1)), "●")} ${bold(g.label)}`, c.muted(count), colW),
      `  ${c.dim(fit(AREA_DETAIL[g.label] ?? "", colW - 2))}`,
    ];
  };
  const out: string[] = [];
  for (let k = 0; k < GROUPS.length; k += 2) {
    const left = cell(GROUPS[k], k);
    const right = GROUPS[k + 1] ? cell(GROUPS[k + 1], k + 1) : ["", ""];
    if (out.length) out.push("");
    out.push(...left.map((l, n) => padEnd(l, colW) + "    " + right[n]));
  }
  return out;
}

const ROLE_TEXT: Record<string, (s: string) => string> = {
  source: (s) => s, "build output": (s) => c.muted(s), tests: (s) => c.muted(s), docs: (s) => c.muted(s),
  config: (s) => c.muted(s), dependencies: (s) => c.dim(s), assets: (s) => c.dim(s),
};

/** LANGUAGES: top languages by file count, with share and a gradient bar. */
export function languageBlock(p: Profile, width: number, rows = 6): string[] {
  const out = heading("Languages", width - 2, `${p.languages.length} detected`);
  if (!p.languages.length) return [...out, SUB + c.muted("no source files recognised")];
  const nameW = 12;
  const barW = Math.max(6, Math.min(16, width - nameW - 22));
  const top = p.languages.slice(0, rows);
  top.forEach((l, k) => {
    const pct = `${Math.max(l.share * 100 < 1 ? 1 : 0, Math.round(l.share * 100))}%`;
    out.push(SUB + `${padEnd(k === 0 ? bold(l.name) : l.name, nameW)} ${c.muted(padStart(num(l.files), 7))}  ${padStart(pct, 4)}  ${fg(rainbowAt(k / Math.max(1, rows - 1)), bar(l.share, top[0].share, barW))}`);
  });
  const rest = p.languages.length - top.length;
  if (rest > 0 || p.otherFiles) {
    out.push(SUB + c.dim([rest > 0 ? `+${rest} more language${rest === 1 ? "" : "s"}` : "", p.otherFiles ? `${num(p.otherFiles)} other files` : ""].filter(Boolean).join(" · ")));
  }
  return out;
}

/** FOLDERS: top-level folders by file count, with each folder's role. */
export function folderBlock(p: Profile, width: number, rows = 6): string[] {
  const out = heading("Folders", width - 2, `${p.folders.length} top-level`);
  const nameW = Math.max(14, Math.min(24, width - 30));
  for (const f of p.folders.slice(0, rows)) {
    out.push(SUB + `${padEnd(fit(f.name + "/", nameW), nameW)} ${c.muted(padStart(num(f.files), 7))}  ${ROLE_TEXT[f.role](f.role)}`);
  }
  const rest = p.folders.length - Math.min(rows, p.folders.length);
  const extras = [rest > 0 ? `+${rest} more folder${rest === 1 ? "" : "s"}` : "", p.rootFiles ? `${num(p.rootFiles)} files at root` : ""].filter(Boolean);
  if (extras.length) out.push(SUB + c.dim(extras.join(" · ")));
  if (p.skippedDirs.length) out.push(SUB + c.dim(`skipped: ${p.skippedDirs.join(" · ")}`));
  return out;
}

export const welcomeFooter = (width: number) =>
  "  " + spread(c.dim("tip: skip this screen with --yes · saas-audit --help for all flags"), c.dim("© Fulgid"), Math.min(width, 110) - 4);

/** Rough duration estimate for the welcome prompt. */
export function estimate(analysable: number): string {
  const secs = Math.max(2, Math.round(analysable * 0.004));
  if (secs < 60) return `about ${secs} seconds for a repo this size`;
  const mins = Math.round(secs / 60);
  return `about ${mins} minute${mins === 1 ? "" : "s"} for a repo this size`;
}

// ---------- 2 · Live scan frame ----------

export type StepState = "done" | "active" | "pending";
export interface LiveState {
  info: RunInfo;
  height: number;
  frame: number;
  steps: { name: string; state: StepState; detail: string; time?: string }[];
  analyse: { done: number; total: number; eta: string };
  overall: number;
  elapsed: number;
  stepIndex: number;
  current: string;
  counts: Record<string, number>;
  areaTotals: { label: string; total: number; crit: number; high: number; signals: boolean }[];
  latest: Finding[];
  prompt?: string[];
}

const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export function liveFrame(s: LiveState): string {
  const W = s.info.width;
  const w = W - 2;
  const out: string[] = [];
  const active = s.steps[s.stepIndex];
  const eta = s.analyse.eta ? ` · ETA ${s.analyse.eta}` : "";
  out.push(...topBand(s.overall, `step ${s.stepIndex + 1} of ${s.steps.length} · ${active?.name ?? "Done"} · ${s.elapsed.toFixed(1)}s elapsed${eta}`, W));
  out.push(...headerLine(s.info), "");

  out.push(...indent(heading("Pipeline", w, `step ${s.stepIndex + 1} of ${s.steps.length}`)));
  const barW = Math.max(10, Math.min(40, w - 72));
  for (const st of s.steps) {
    const icon = st.state === "done" ? c.ok("✓") : st.state === "active" ? bold(c.accent(SPIN[s.frame % SPIN.length])) : c.dim("○");
    const name = st.state === "pending" ? c.dim(st.name.padEnd(12)) : st.state === "active" ? bold(st.name.padEnd(12)) : st.name.padEnd(12);
    let detail: string;
    let time = st.time ? c.muted(st.time) : "";
    if (st.name === "Analyse" && st.state === "active") {
      const frac = s.analyse.total ? s.analyse.done / s.analyse.total : 0;
      detail = `${rainbowProgress(frac, barW)}  ${bold(`${Math.round(frac * 100)}%`)}  ${c.muted(`${num(s.analyse.done)} / ${num(s.analyse.total)} files`)}`;
      time = s.analyse.eta ? c.muted(`ETA ${s.analyse.eta}`) : "";
    } else detail = st.state === "pending" ? c.dim(st.detail) : c.muted(st.detail);
    out.push(" " + SUB + spread(`${icon}  ${name} ${detail}`, time, w - 2));
  }
  if (s.current) out.push(`      ${c.dim("↳")} ${c.muted(fit(s.current, w - 8))}`);
  out.push("");

  // LEADS SO FAR: severity totals on the header line, the same leads split by area right below.
  const counts = ["Critical", "High", "Medium", "Low"].map((sev) => `${badge(sev)} ${padEnd(bold(num(s.counts[sev] ?? 0)), 6)}`).join("  ");
  out.push(...indent(heading("Leads so far", w, "", "running total · not final")));
  out.push(" " + SUB + counts);

  // Fit the area breakdown to the terminal height.
  const used = out.length + 3;
  const room = s.height - used - (s.prompt ? s.prompt.length + 1 : 3);
  const sorted = [...s.areaTotals].sort((a, b) => Number(b.total > 0) - Number(a.total > 0));
  if (room >= 10) {
    const cardW = Math.floor((w - 6) / 3);
    const cards = sorted.map((a) => {
      const sub = a.total === 0 ? c.dim(a.signals ? "no leads · needs manual review" : "no signals · needs manual review")
        : a.crit ? c.crit(`▲ ${num(a.crit)} critical`) : a.high ? c.high(`▲ ${num(a.high)} high`) : c.muted("medium and low only");
      const head = spread(a.total ? a.label : c.muted(a.label), a.total ? bold(num(a.total)) : c.muted("—"), cardW - 4);
      return box([head, sub], cardW, a.total ? "#232A33" : "#30363D", a.total === 0);
    });
    for (let r = 0; r < cards.length; r += 3) {
      const row = cards.slice(r, r + 3);
      for (let line = 0; line < row[0].length; line++) out.push(" " + SUB + row.map((card) => card[line]).join("  "));
    }
  } else if (room >= 3) {
    const cells = sorted.map((a) => `${padEnd(a.total ? a.label : c.muted(a.label), 27)} ${a.total ? bold(padStart(num(a.total), 6)) : c.muted(padStart("—", 6))}`);
    for (let i = 0; i < cells.length; i += 2) out.push(" " + SUB + padEnd(cells[i], Math.floor(w / 2)) + (cells[i + 1] ?? ""));
  }
  out.push("");

  const latestRoom = Math.max(0, s.height - out.length - (s.prompt ? s.prompt.length + 1 : 3) - 2);
  if (latestRoom >= 2) {
    out.push(...indent(heading("Latest critical & high", w, "", "medium and low are counted, not streamed")));
    const rows = s.latest.slice(0, Math.min(5, latestRoom - 2));
    if (!rows.length) out.push(" " + SUB + c.dim("none yet"));
    for (const f of rows) {
      const titleW = 30;
      const pathW = Math.min(52, w - 6 - 2 - 7 - 2 - titleW - 4);
      out.push(` ${SUB}${badge(f.severity)}  ${c.muted(f.id.padEnd(7))} ${padEnd(fit(`${f.file}:${f.line}`, pathW), pathW)}  ${c.muted(fit(RULE_SHORT[f.id] ? capitalizeFirst(shortTitle(f)) : f.title, titleW))}`);
    }
    out.push("");
  }

  if (s.prompt) out.push(...indent(s.prompt));
  else {
    out.push(" " + rule(w));
    out.push(" " + spread(c.dim("ctrl+c to cancel · partial results are kept"), `${c.dim("your code never leaves this machine ·")} ${poweredBy()}`, w));
  }
  return out.join("\n");
}

const capitalizeFirst = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
function shortTitle(f: Finding): string {
  const t = f.title.replace(/^Known-format secret: /, "");
  return t.length <= 32 ? t : RULE_SHORT[f.id] ?? t;
}

// ---------- 3 · Summary & verdict ----------

export interface SummaryInfo extends RunInfo {
  elapsed: number;
  filesWalked: number;
  report: string | null;
  failOn: string;
  gateTripped: boolean;
  partial?: { percent: number };
  includeTests: boolean;
  profile?: Profile;
}

export function summaryScreen(result: Result, i: SummaryInfo): { lines: string[]; view: View; verdict: Verdict } {
  const W = i.width;
  const w = W - 2;
  const v = buildView(result, i.includeTests);
  const verdictV = verdict(v.sourceCounts, i.failOn, i.gateTripped);
  const out: string[] = [];
  const s = result.stats;
  out.push(...topBand(i.partial ? i.partial.percent : 100, i.partial ? `stopped · ${i.elapsed.toFixed(1)}s` : `5 of 5 steps · ${i.elapsed.toFixed(1)}s`, W, !i.partial));
  out.push(...headerLine(i), "");
  out.push(i.partial
    ? ` ${c.high("◐")} ${bold("Scan stopped")}  ${c.muted(`at ${Math.round(i.partial.percent)}% · partial results · ${num(s.files_scanned)} analysed · ${i.elapsed.toFixed(1)}s`)}`
    : ` ${c.ok("✓")} ${bold("Scan complete")}  ${c.muted(`${num(i.filesWalked)} files checked · ${num(s.files_scanned)} analysed · ${i.elapsed.toFixed(1)}s · code never left this machine`)}`);
  out.push("");

  // Verdict box
  const vColor = { blocked: P.crit, risk: P.high, passed: P.ok, review: P.med, clean: P.ok }[verdictV.kind];
  const vBorder = { blocked: P.blocked, risk: P.warnBox, passed: "#1E3A26", review: "#5A4512", clean: "#1E3A26" }[verdictV.kind];
  const boxW = Math.min(w, 120);
  const counts = SEVERITY_ORDER.map((sev) => `${badge(sev)} ${padEnd(bold(num(v.sourceCounts[sev] ?? 0)), 7)}`).join("  ");
  out.push(...indent(box([
    spread(bold(fg(vColor, verdictV.title)), c.muted(verdictV.gate), boxW - 4),
    ...wrap(verdictV.detail, boxW - 4),
    "",
    counts,
  ], boxW, vBorder)), "");

  // Where the worst are · severity shape
  const half = Math.floor((w - 4) / 2);
  const worst = whereWorst(v.shown);
  const left: string[] = [];
  if (worst) {
    const noun = worst.severity === "Critical" ? "critical" : "high";
    left.push(...heading(`Where the ${num(worst.total)} ${worst.total === 1 ? `${noun} is` : `${noun}s are`}`, half - 2));
    for (const g of worst.groups.slice(0, 4)) {
      const ratio = `${g.count} / ${worst.total}`;
      left.push(SUB + `${padEnd(g.role === "source" ? bold(sevText(worst.severity, ratio)) : bold(c.muted(ratio)), 9)}  ${fit(shortDir(g.dir), half - 14)}`);
      left.push(SUB + `${" ".repeat(11)}${c.muted(fit(g.label, half - 14))}`);
    }
    if (worst.groups.length > 4) left.push(SUB + c.dim(`${" ".repeat(11)}+${worst.groups.length - 4} more places`));
  }
  const totalSource = SEVERITY_ORDER.reduce((a, sev) => a + (v.sourceCounts[sev] ?? 0), 0);
  const maxCount = Math.max(1, ...["Critical", "High", "Medium", "Low"].map((sev) => v.sourceCounts[sev] ?? 0));
  const right = heading("Severity shape", half - 2, `${num(totalSource)} in source`);
  const barW = Math.max(8, half - 20);
  for (const sev of ["Critical", "High", "Medium", "Low"]) {
    const n = v.sourceCounts[sev] ?? 0;
    right.push(SUB + `${sevText(sev, SEV_LOWER[sev].padEnd(5))} ${padStart(num(n), 7)}  ${sevText(sev, bar(n, maxCount, barW))}`);
  }
  if (v.hidden.length) right.push(SUB + c.dim(`+${num(v.hidden.length)} more in tests and local env files · on request`));
  out.push(...indent(worst ? columns(left, right, half) : right), "");

  // By area
  const areaList = areas(v.shown, GROUPS, result).sort((a, b) => b.total - a.total);
  const maxArea = Math.max(1, ...areaList.map((a) => a.total));
  out.push(...indent(heading("By area", w, `${areaList.filter((a) => a.total).length} of 6 with leads`)));
  out.push(" " + SUB + `${c.dim("AREA".padEnd(28))}${c.dim(padStart("LEADS", 8))}  ${c.dim("".padEnd(22))}${c.dim("DRIVEN BY")}`);
  for (const a of areaList) {
    if (!a.total) {
      out.push(" " + SUB + `${c.muted(a.label.padEnd(28))}${c.muted(padStart("—", 8))}  ${"".padEnd(22)}${c.dim(a.hasSignals ? "no leads · not proven safe" : "no signals · not proven safe")}`);
      continue;
    }
    const driven = a.topRules.slice(0, 2).map((r) => `${r.id} ${RULE_SHORT[r.id] ?? ""} ×${num(r.count)}`).join(" · ");
    out.push(" " + SUB + `${a.label.padEnd(28)}${bold(padStart(num(a.total), 8))}  ${padEnd(c.accent(bar(a.total, maxArea, 20)), 22)}${c.muted(fit(driven, w - 62))}`);
  }
  out.push("");

  // By folder
  if (i.profile) out.push(...byFolder(v.shown, i.profile, w), "");

  // Control coverage grid
  out.push(...indent(heading("Control coverage", w, "22 controls", "a control passes only when enforcement is located and tested")));
  const leadIds = new Set(v.coverage.leads.map((r) => r.id));
  const noneIds = new Set(v.coverage.noSignals.map((r) => r.id));
  const cellW = Math.max(6, Math.floor((w - 12) / 11) - 1);
  for (let row = 0; row < 2; row++) {
    const cells: string[] = [];
    for (let id = row * 11 + 1; id <= row * 11 + 11; id++) {
      const lead = leadIds.has(id);
      const none = noneIds.has(id);
      const txt = `${lead ? "◐ " : none ? "○ " : ""}C${id}`;
      const centered = txt.padStart(Math.floor((cellW + txt.length) / 2)).padEnd(cellW);
      cells.push(lead ? bg("#2B2210", P.med, centered) : none ? bg("#0F1A13", P.ok, centered) : bg("#161B22", P.muted, centered));
    }
    out.push(" " + SUB + cells.join(" "));
  }
  out.push(" " + SUB + spread(
    `${c.med(`◐ ${v.coverage.leads.length} leads to verify`)}    ${c.ok(`○ ${v.coverage.noSignals.length} no signals`)}    ${c.muted(`┄ ${v.coverage.notVerified.length} not verified · manual review`)}`,
    c.dim("0 passed"), w - 2), "");

  // Footer
  out.push(" " + rule(w));
  out.push(...indent(kv([
    ["Report", i.report ? c.accent(i.report) : c.muted("none · add --output security-report.html")],
    ["Details", `saas-audit show ${c.muted("<rule>")}   ${c.dim(`e.g. saas-audit show ${v.guidance[0]?.id ?? "SEC031"}`)}`],
    ["Verify & fix", `/saas-security-audit:audit ${c.muted("in Claude Code")}`],
  ], 14)));
  out.push(" " + padStart(poweredBy(), w), "");
  return { lines: out, view: v, verdict: verdictV };
}

/** BY FOLDER: which top-level folders hold the leads, with their size and role. */
function byFolder(shown: Finding[], p: Profile, w: number): string[] {
  const filesIn = new Map(p.folders.map((f) => [f.name, f]));
  const counts = new Map<string, { total: number; crit: number; high: number }>();
  for (const f of shown) {
    const top = topFolder(f.file);
    const k = counts.get(top) ?? { total: 0, crit: 0, high: 0 };
    k.total++;
    if (f.severity === "Critical") k.crit++;
    if (f.severity === "High") k.high++;
    counts.set(top, k);
  }
  const rows = [...counts.entries()].sort((a, b) => b[1].crit - a[1].crit || b[1].high - a[1].high || b[1].total - a[1].total);
  const out = indent(heading("By folder", w, `${p.folders.length} top-level`, p.languages.slice(0, 3).map((l) => `${l.name} ${l.share > 0 && l.share < 0.005 ? "<1" : Math.round(l.share * 100)}%`).join(" · ")));
  if (!rows.length) return [...out, " " + SUB + c.muted("no leads in any folder")];
  const nameW = Math.min(30, Math.max(16, w - 72));
  out.push(" " + SUB + `${c.dim("FOLDER".padEnd(nameW))}${c.dim(padStart("FILES", 8))}${c.dim(padStart("LEADS", 8))}  ${c.dim("CRIT".padStart(5))} ${c.dim("HIGH".padStart(5))}   ${c.dim("ROLE")}`);
  for (const [name, k] of rows.slice(0, 8)) {
    const meta = filesIn.get(name);
    const role = name === "(root)" ? "root files" : meta?.role ?? "source";
    const display = name === "(root)" ? "(repo root)" : name + "/";
    out.push(" " + SUB + `${padEnd(fit(display, nameW - 1), nameW)}${c.muted(padStart(meta ? num(meta.files) : name === "(root)" ? num(p.rootFiles) : "—", 8))}${bold(padStart(num(k.total), 8))}  ${k.crit ? c.crit(padStart(num(k.crit), 5)) : c.dim(padStart("–", 5))} ${k.high ? c.high(padStart(num(k.high), 5)) : c.dim(padStart("–", 5))}   ${(ROLE_TEXT[role] ?? ((s: string) => c.muted(s)))(role)}`);
  }
  const quiet = p.folders.length - rows.filter(([n]) => n !== "(root)").length;
  if (rows.length > 8 || quiet > 0) out.push(" " + SUB + c.dim([rows.length > 8 ? `+${rows.length - 8} more folders with leads` : "", quiet > 0 ? `${quiet} folder${quiet === 1 ? "" : "s"} with no leads` : ""].filter(Boolean).join(" · ")));
  return out;
}

function shortDir(dir: string): string {
  if (dir === "./") return "(repo root)";
  const parts = dir.replace(/\/$/, "").split("/");
  return parts.length <= 4 ? dir : [...parts.slice(0, 2), "…", parts[parts.length - 1]].join("/") + "/";
}

function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  let cur = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (vlen(cur ? cur + " " + word : word) > width && cur) { lines.push(cur); cur = word; }
    else cur = cur ? cur + " " + word : word;
  }
  if (cur) lines.push(cur);
  return lines;
}

// ---------- 4 · Findings by rule ----------

export interface FindingsInfo {
  width: number;
  /** e.g. "in source" or "incl. tests". */
  scope?: string;
  all: boolean;
  report: string | null;
  findings: Finding[];
}

function groupTitle(list: Finding[]): string {
  const titles = new Set(list.map((f) => f.title));
  const t = titles.size === 1 ? list[0].title : RULE_TITLES[list[0].id] ?? list[0].title;
  return t.replace(/: (.)/, (_, ch: string) => " · " + ch.toLowerCase());
}

/** Locations of one rule as a tree, grouped by file; long lists end with a "show" hint. */
function locationTree(id: string, list: Finding[], width: number, maxRows: number): string[] {
  const byFile = new Map<string, Finding[]>();
  for (const f of list) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
  const order: Record<string, number> = { source: 0, "local env": 1, docs: 2, test: 3, build: 4 };
  const files = [...byFile.entries()].sort((a, b) =>
    order[pathRole(a[1][0])] - order[pathRole(b[1][0])] || b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const shown = files.slice(0, maxRows);
  const pad = " ".repeat(16);
  const lines = shown.map(([file, hits], i) => {
    const role = pathRole(hits[0]);
    const branch = c.dim(i === shown.length - 1 && files.length <= maxRows ? "└─" : "├─");
    const lineNos = hits.map((h) => h.line).sort((a, b) => a - b);
    const locs = lineNos.slice(0, 4).map((n, k) => (k ? ":" + n : ":" + n)).join(", ") + (lineNos.length > 4 ? ", …" : "");
    const rightText = role !== "source" || hits.length > 1 ? `${hits.length} hit${hits.length === 1 ? "" : "s"} · ${role}` : "";
    const right = role === "source" && hits.some((h) => h.severity === "Critical") ? c.crit(rightText) : c.muted(rightText);
    const pathW = width - 16 - 3 - 20;
    const pathText = fit(file, pathW - vlen(locs) - 1);
    const path = role === "source" ? `${pathText}${c.muted(locs)}` : c.muted(`${pathText}${locs}`);
    return pad + `${branch} ${padEnd(path, pathW)} ${right}`;
  });
  if (files.length > maxRows) lines.push(pad + `${c.dim("└─")} ${c.dim(`+ ${files.length - maxRows} more file${files.length - maxRows === 1 ? "" : "s"} · saas-audit show ${id}`)}`);
  return lines;
}

function ruleGroup(id: string, list: Finding[], width: number, maxRows: number): string[] {
  const worst = list.reduce((a, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[a] ? f.severity : a), list[0].severity);
  const ctl = list[0].controls[0];
  const titleW = width - 1 - 6 - 2 - 7 - 2 - 16 - 8;
  const head = ` ${badge(worst)}  ${c.muted(id.padEnd(7))} ${padEnd(bold(fit(groupTitle(list), titleW)), titleW)}  ${c.muted(`C${ctl} ${CONTROL_TINY[ctl - 1]}`.padEnd(14))} ${bold(padStart(`×${num(list.length)}`, 6))}`;
  const fixW = width - 16 - 3;
  const fix = wrap(list[0].guidance, fixW).map((l, i) => " ".repeat(16) + (i ? "  " : c.ok("→ ")) + l);
  return [head, ...locationTree(id, list, width, maxRows), ...fix];
}

export function findingsScreen(i: FindingsInfo): string[] {
  const W = i.width;
  const w = W - 2;
  const byRule = new Map<string, Finding[]>();
  for (const f of i.findings) byRule.set(f.id, [...(byRule.get(f.id) ?? []), f]);
  const worst = (l: Finding[]) => Math.max(...l.map((f) => SEVERITY_RANK[f.severity]));
  const rules = [...byRule.entries()].sort((a, b) => worst(b[1]) - worst(a[1]) || b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const expanded = rules.filter(([, l]) => i.all || worst(l) >= SEVERITY_RANK.High);
  const collapsedRules = rules.filter(([, l]) => !i.all && worst(l) < SEVERITY_RANK.High);
  const out: string[] = [];
  out.push(...indent(heading("Findings", w, `${num(i.findings.length)} ${i.scope ?? "in source"} · ${rules.length} rules · grouped by rule, worst first`, "--group rule · --sort severity")));
  if (!rules.length) {
    out.push("", "  " + c.ok("No leads in source code.") + " " + c.muted("That isn't proof of security — the controls still need verifying."), "");
    return out;
  }
  for (const [id, list] of expanded) {
    out.push(" " + fg("#1C232C", "─".repeat(w)));
    out.push(...ruleGroup(id, list, w, 4));
  }
  if (collapsedRules.length) {
    const total = collapsedRules.reduce((a, [, l]) => a + l.length, 0);
    const max = Math.max(...collapsedRules.map(([, l]) => l.length));
    out.push(" " + fg("#1C232C", "─".repeat(w)));
    out.push("", ...indent(heading("Medium & low", w, `${num(total)} · collapsed`, "expand with --all")));
    const titleW = Math.max(20, w - 7 - 2 - 7 - 2 - 22 - 4);
    for (const [id, list] of collapsedRules) {
      const sev = list.some((f) => f.severity === "Medium") ? "Medium" : list[0].severity;
      const tag = sev === "Low" ? " " + bg("#161B22", P.muted, " LOW ") : sev === "Informational" ? " " + bg("#161B22", P.muted, " INFO ") : "";
      out.push(` ${c.muted(id.padEnd(7))}  ${padEnd(fit(groupTitle(list), titleW - vlen(tag)) + tag, titleW)}  ${bold(padStart(num(list.length), 7))}  ${sevText(sev, bar(list.length, max, 20))}`);
    }
  }
  out.push(" " + rule(w));
  out.push(" " + spread(
    c.dim(i.report ? `every location, line and snippet → ${i.report}` : "every location, line and snippet → saas-audit --output report.html"),
    `${c.dim("saas-audit show <rule> · --json for tooling ·")} ${poweredBy(false)}`, w), "");
  return out;
}

// ---------- 5 · Fix plan & next steps ----------

export interface FixInfo {
  width: number;
  view: View;
  verdict: Verdict;
  report: string | null;
  failOn: string;
  elapsed: number;
}

export function fixScreen(i: FixInfo): string[] {
  const w = i.width - 2;
  const allActions = fixPlan(i.view.shown);
  const MAX_ACTIONS = 8;
  const actions = allActions.slice(0, MAX_ACTIONS);
  const out: string[] = [];
  out.push(...indent(heading("Fix order", w, allActions.length
    ? `${allActions.length} action${allActions.length === 1 ? "" : "s"} · every critical, then the high-severity rules`
    : "no critical or high-severity leads in source code", "ordered by severity × blast radius")));
  out.push("");
  actions.forEach((a, n) => {
    const numCell = bold(bg(a.severity === "Critical" ? "#F85149" : "#3D2A14", a.severity === "Critical" ? "#140203" : P.high, ` ${n + 1} `.padEnd(4)));
    const whenText = a.severity === "Critical" ? c.crit(a.when) : c.high(a.when);
    const textW = w - 6 - 16;
    out.push(" " + spread(`${numCell}  ${bold(fit(a.title, textW))}`, whenText, w));
    for (const l of a.detail ? wrap(a.detail, textW) : []) out.push(" ".repeat(7) + c.muted(l));
    if (a.command) out.push(" ".repeat(7) + c.accent(a.command));
    out.push(" ".repeat(7) + a.tags.map((t) => bg("#161B22", P.muted, ` ${t} `)).join(" "));
    out.push("");
  });
  if (allActions.length > MAX_ACTIONS) {
    out.push("  " + c.dim(`+ ${allActions.length - MAX_ACTIONS} more high-severity rules · each is listed under FINDINGS above`), "");
  }

  const nv = i.view.coverage.notVerified;
  if (nv.length) {
    const boxW = Math.min(w, 120);
    const colW = Math.floor((boxW - 4) / 3);
    const cells = nv.map((r) => `${c.muted(`C${r.id} `)}${fit(CONTROL_SHORT[r.id - 1], colW - 5)}`);
    const rows: string[] = [];
    for (let k = 0; k < cells.length; k += 3) rows.push(cells.slice(k, k + 3).map((cell) => padEnd(cell, colW)).join(""));
    out.push(...indent(box([
      spread(label(`needs manual review · ${nv.length} controls not verified`), c.dim("no signal is not a pass"), boxW - 4),
      ...rows,
    ], boxW, "#30363D", true)), "");
  }

  out.push(...indent(heading("Next", w)));
  const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  const topRule = actions[0]?.tags[0]?.split(" ")[0] ?? i.view.guidance[0]?.id;
  out.push(...indent(kv([
    ...(i.report ? [["Open the report", `${opener} ${i.report}`] as [string, string]] : [["Write a report", "saas-audit --output security-report.html"] as [string, string]]),
    ...(topRule ? [["Drill into a rule", `saas-audit show ${topRule}`] as [string, string]] : []),
    ["Verify & fix", `/saas-security-audit:audit ${c.dim("in Claude Code")}`],
    ["Gate CI", "saas-audit --fail-on high --format json"],
  ], 20), 2), "");

  out.push(" " + rule(w));
  const crit = i.view.sourceCounts.Critical ?? 0;
  const high = i.view.sourceCounts.High ?? 0;
  const exitLine = i.verdict.exit
    ? `${bold(c.crit("✗ exit 1"))} ${c.muted(`· blocked by ${num(crit)} critical, ${num(high)} high · gate ${i.failOn}`)}`
    : i.failOn === "none"
      ? `${bold(c.ok("✓ exit 0"))} ${c.muted("· no gate · add --fail-on high to block releases")}`
      : `${bold(c.ok("✓ exit 0"))} ${c.muted(`· gate ${i.failOn} passed`)}`;
  out.push(" " + spread(exitLine, `${c.dim(`${i.elapsed.toFixed(1)}s ·`)} ${poweredBy()}`, w), "");
  return out;
}

// ---------- show <rule> ----------

export function showRule(id: string, findings: Finding[], width: number): string[] {
  const w = width - 2;
  const list = findings.filter((f) => f.id === id.toUpperCase());
  if (!list.length) return [` ${c.muted(`No findings for ${id.toUpperCase()} in this repository.`)}`, ""];
  const out = ruleGroup(list[0].id, list, w, Number.POSITIVE_INFINITY).slice(0, 1);
  out.push(" " + fg("#1C232C", "─".repeat(w)));
  for (const f of list) {
    const role = pathRole(f);
    out.push(`  ${badge(f.severity)}  ${underline(`${f.file}:${f.line}`)}${role === "source" ? "" : " " + c.muted(`(${role})`)}`);
    for (const l of wrap(f.evidence, w - 10)) out.push(`          ${c.dim(l)}`);
  }
  out.push("");
  wrap(list[0].guidance, w - 6).forEach((l, k) => out.push(`  ${k ? " " : c.ok("→")} ${l}`));
  out.push(`  ${c.muted(`Controls: ${list[0].controls.map((n) => `C${n} ${CONTROL_SHORT[n - 1]}`).join(", ")} · confidence ${list[0].confidence}`)}`, "");
  return out;
}

// ---------- 6 · CI text and GitHub annotations ----------

export function ciText(result: Result, o: { version: string; project: string; elapsed: number; filesWalked: number; failOn: string; gateTripped: boolean; report: string | null; profile?: Profile }): string {
  const v = buildView(result, false);
  const sc = v.sourceCounts;
  const lines = [
    ["saas-audit", `${o.version} · ${o.project} · offline · read-only`],
    ["scan", `${o.filesWalked} files · ${result.stats.files_scanned} analysed · ${o.elapsed.toFixed(1)}s`],
    ["result", `${o.failOn === "none" ? "DONE" : o.gateTripped ? "FAIL" : "PASS"}  gate=${o.failOn}`],
    ["counts", `crit=${sc.Critical ?? 0} high=${sc.High ?? 0} med=${sc.Medium ?? 0} low=${sc.Low ?? 0} info=${sc.Informational ?? 0}`],
    ["controls", `leads=${v.coverage.leads.length} no_signal=${v.coverage.noSignals.length} not_verified=${v.coverage.notVerified.length} passed=0`],
  ];
  if (o.profile) {
    lines.splice(2, 0,
      ["languages", o.profile.languages.slice(0, 5).map((l) => `${l.name} ${l.files} (${Math.round(l.share * 100)}%)`).join(" · ") || "none recognised"],
      ["folders", o.profile.folders.slice(0, 5).map((f) => `${f.name}/ ${f.files}`).join(" · ") + (o.profile.skippedDirs.length ? ` · skipped ${o.profile.skippedDirs.join(",")}` : "")]);
  }
  const out = lines.map(([k, val]) => k.padEnd(12) + val);
  const byRule = new Map<string, Finding[]>();
  for (const f of v.shown.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.High)) byRule.set(f.id, [...(byRule.get(f.id) ?? []), f]);
  if (byRule.size) {
    out.push("", "BLOCKING · CRITICAL AND HIGH, BY RULE");
    const rows = [...byRule.entries()].sort((a, b) =>
      Math.max(...b[1].map((f) => SEVERITY_RANK[f.severity])) - Math.max(...a[1].map((f) => SEVERITY_RANK[f.severity])) || b[1].length - a[1].length);
    for (const [id, l] of rows) {
      const sev = l.some((f) => f.severity === "Critical") ? "crit" : "high";
      out.push(`${sev.padEnd(6)}${id.padEnd(8)}${String(l.length).padEnd(6)}${RULE_TITLES[id] ?? l[0].title}`);
    }
  }
  if (v.hidden.length) out.push("", `+${v.hidden.length} leads in test files and local env files (not counted above)`);
  out.push("", `${"report".padEnd(12)}${o.report ?? "none (add --output report.md)"}`, `${"exit".padEnd(12)}${o.gateTripped ? 1 : 0}`, `${"by".padEnd(12)}powered by Fulgid · ${FULGID}`);
  return out.join("\n") + "\n";
}

const ghEscape = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const ghProp = (s: string) => ghEscape(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

/** GitHub Actions workflow commands: errors for critical/high, warnings for medium (source code only). */
export function githubAnnotations(result: Result): string {
  const v = buildView(result, false);
  return v.shown.filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.Medium).map((f) => {
    const level = SEVERITY_RANK[f.severity] >= SEVERITY_RANK.High ? "error" : "warning";
    return `::${level} file=${ghProp(f.file)},line=${f.line},title=${ghProp(`${f.id} ${SEV_SHORT[f.severity]}`)}::${ghEscape(`${f.id} ${f.title}`)}`;
  }).join("\n") + (v.shown.length ? "\n" : "");
}
