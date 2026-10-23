import type { Result } from "../report.js";
import type { Finding } from "../engine.js";
import { buildView, controlLabel, type CoverageRow } from "../view.js";
import { SEVERITY_ORDER, SEV_SHORT, c, gradient, sevBadge } from "./theme.js";

export { shownByDefault } from "../view.js";

const MAX_LISTED = 40;
// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;
const vlen = (s: string) => [...s.replace(ANSI, "")].length;
const fit = (plain: string, max: number) =>
  max <= 1 ? "…" : [...plain].length <= max ? plain : [...plain].slice(0, max - 1).join("") + "…";
const padTo = (styled: string, width: number) => styled + " ".repeat(Math.max(0, width - vlen(styled)));
const termWidth = (n?: number) => Math.max(72, Math.min(n ?? 100, 140));

export interface SummaryOptions {
  elapsedMs: number;
  columns?: number;
  filesWalked?: number;
  includeTests?: boolean;
  /** Whether the CLI will offer to show the hidden findings after the summary. */
  willPrompt?: boolean;
  reports?: string[];
}

function box(lines: string[], width: number): string[] {
  const inner = width - 4;
  return [
    gradient(" ╭" + "─".repeat(width - 2) + "╮"),
    ...lines.map((l) => `${gradient(" │")} ${padTo(l, inner)} ${gradient("│")}`),
    gradient(" ╰" + "─".repeat(width - 2) + "╯"),
  ];
}

function wrapWords(items: string[], sep: string, width: number): string[] {
  const lines: string[] = [];
  let cur = "";
  for (const item of items) {
    const next = cur ? cur + sep + item : item;
    if (vlen(next) > width && cur) {
      lines.push(cur + sep.trimEnd());
      cur = item;
    } else cur = next;
  }
  if (cur) lines.push(cur);
  return lines;
}

/** One line per finding: severity, rule, control, location, issue. */
function findingsTable(findings: Finding[], width: number, max: number): string[] {
  const showControl = width >= 110;
  const longest = Math.max(18, ...findings.slice(0, max).map((f) => vlen(`${f.file}:${f.line}`) + (f.context === "source" ? 0 : f.context.length + 3)));
  const locWidth = Math.min(longest, 40, Math.floor(width * 0.32));
  const ctlWidth = showControl ? 26 : 0;
  const fixed = 2 + 6 + 2 + 7 + 2 + (showControl ? ctlWidth + 2 : 0) + locWidth + 2;
  const issueWidth = Math.max(16, width - fixed);
  const head = "  " + c.gray(["SEV   ", "RULE   ", ...(showControl ? ["CONTROL".padEnd(ctlWidth)] : []), "LOCATION".padEnd(locWidth), "ISSUE"].join("  "));
  const lines = [head];
  for (const f of findings.slice(0, max)) {
    const ctx = f.context === "source" ? "" : c.gray(` (${f.context})`);
    const loc = fit(`${f.file}:${f.line}`, locWidth - vlen(ctx));
    lines.push("  " + [
      padTo(sevBadge(f.severity), 6),
      c.gray(f.id.padEnd(7)),
      ...(showControl ? [c.gray(fit(controlLabel(f.controls[0]), ctlWidth).padEnd(ctlWidth))] : []),
      padTo(c.underline(loc) + ctx, locWidth),
      fit(f.title, issueWidth),
    ].join("  "));
  }
  return lines;
}

function coverageLines(label: string, marker: string, rows: CoverageRow[], width: number, color: (s: string) => string): string[] {
  if (!rows.length) return [];
  const prefix = `  ${color(marker)} ${label.padEnd(18)} ${c.gray(String(rows.length).padStart(2))}  `;
  const indent = " ".repeat(vlen(prefix));
  const items = rows.map((r) => `C${r.id} ${r.short}`);
  return wrapWords(items, " · ", width - vlen(prefix) - 1).map((l, i) => (i ? indent : prefix) + c.gray(l));
}

export function renderSummary(result: Result, opts: SummaryOptions): { text: string; hidden: Finding[] } {
  const width = termWidth(opts.columns);
  const v = buildView(result, Boolean(opts.includeTests));
  const s = result.stats;
  const out: string[] = [];
  const secs = (opts.elapsedMs / 1000).toFixed(1);
  const files = opts.filesWalked !== undefined ? `${opts.filesWalked} files checked, ${s.files_scanned} analysed` : `${s.files_scanned} files analysed`;

  out.push("", "");
  out.push(` ${c.green("✔")} ${c.bold("Scan complete")} ${c.gray(`· ${v.project} · ${files} · ${secs}s · offline scan, your code never left this machine`)}`);
  out.push("");

  const postureColor = { critical: (t: string) => c.bold(c.red(t)), high: (t: string) => c.bold(c.red(t)),
    medium: (t: string) => c.bold(c.yellow(t)), low: (t: string) => c.bold(c.green(t)) }[v.posture.level];
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = v.sourceCounts[sev] ?? 0;
    return n ? `${sevBadge(sev)}${c.bold(String(n))}` : c.gray(` ${SEV_SHORT[sev]} 0`.padEnd(8));
  }).join("  ");
  const boxLines = [
    postureColor((v.posture.level === "low" ? "✔ " : "▲ ") + v.posture.headline),
    ...wrapWords(v.posture.detail.split(" "), " ", width - 6).map((l) => c.gray(l)),
    "",
    counts + c.gray("   in source code"),
  ];
  if (v.stack.length) boxLines.push(c.gray("Stack   ") + v.stack.join(c.gray(" · ")));
  const extras: string[] = [];
  if (v.hidden.length) extras.push(`${v.hidden.length} more in test files / local env files${opts.willPrompt ? " (shown on request)" : " (--include-tests)"}`);
  if (s.suppressed) extras.push(`${s.suppressed} suppressed inline`);
  extras.push(`${v.controlsWithLeads}/22 controls with leads`);
  boxLines.push(c.gray(extras.join(" · ")));
  out.push(...box(boxLines, Math.min(width, 100)), "");

  if (!v.shown.length) {
    out.push(`  ${c.green("No leads in your source code.")} ${c.gray("That isn't proof of security — verify the controls below.")}`, "");
  } else {
    out.push(` ${c.bold("FINDINGS IN SOURCE CODE")} ${c.gray(String(v.shown.length))}`);
    out.push(...findingsTable(v.shown, width, MAX_LISTED));
    if (v.shown.length > MAX_LISTED) {
      out.push(c.gray(`  +${v.shown.length - MAX_LISTED} more — ` +
        (opts.reports?.length ? `see ${opts.reports.join(", ")}` : "write a full report with --output report.html")));
    }
    out.push("");
    out.push(` ${c.bold("HOW TO FIX")}`);
    const idWidth = 7;
    for (const g of v.guidance) {
      const lead = `  ${c.gray(g.id.padEnd(idWidth))} ${c.bold(fit(g.title, 44))}${c.gray(g.count > 1 ? ` ×${g.count}` : "")}`;
      out.push(lead);
      for (const l of wrapWords(g.guidance.split(" "), " ", width - 13)) out.push(`  ${" ".repeat(idWidth)}  ${c.gray(l)}`);
    }
    out.push("");
  }

  out.push(` ${c.bold("CONTROL COVERAGE")} ${c.gray("· 22 controls")}`);
  out.push(...coverageLines("Leads to verify", "◍", v.coverage.leads, width, c.yellow));
  out.push(...coverageLines("No signals found", "◌", v.coverage.noSignals, width, c.gray));
  out.push(...coverageLines("Not verified", "◌", v.coverage.notVerified, width, c.gray));
  out.push(c.gray("  PASS is never automatic: a control passes only when enforcement is located and tested."), "");

  if (!result.inventory.test_files) out.push(`  ${c.yellow("!")} No test files detected — most controls can't reach PASS without negative tests.`, "");
  out.push(` ${c.bold("NEXT")}`);
  if (opts.reports?.length) out.push(`  ${gradient("›")} Reports written    ${opts.reports.map((r) => c.underline(r)).join(c.gray(" · "))}`);
  else out.push(`  ${gradient("›")} Share a report     ${c.cyan("saas-audit --output report.pdf --output report.html")}`);
  out.push(`  ${gradient("›")} Verify & fix       ${c.cyan("/saas-security-audit:audit")} ${c.gray("in Claude Code")}`);
  out.push(`  ${gradient("›")} Gate CI            ${c.cyan("saas-audit --fail-on high --format json")}`);
  out.push("");
  return { text: out.join("\n"), hidden: v.hidden };
}

/** The findings hidden from the default view, shown after the user asks for them. */
export function renderHidden(hidden: Finding[], columns?: number): string {
  const width = termWidth(columns);
  return ["", ` ${c.bold("TEST FILES & LOCAL ENV FILES")} ${c.gray(String(hidden.length))}`,
    ...findingsTable(hidden, width, Number.POSITIVE_INFINITY), ""].join("\n");
}
