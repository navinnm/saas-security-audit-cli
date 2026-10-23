import type { Result } from "../report.js";
import type { Finding } from "../engine.js";
import { SEVERITY_RANK } from "../rules.js";
import { CONTROL_SHORT, SEVERITY_ORDER, SEV_SHORT, c, gradient, sevBadge } from "./theme.js";

const MAX_LISTED = 30;

function fit(plain: string, max: number): string {
  return [...plain].length <= max ? plain : [...plain].slice(0, Math.max(1, max - 1)).join("") + "…";
}

/**
 * Shown in the terminal by default: findings in the project's own source code, plus real-format
 * secrets wherever they are (a live key in a test fixture is still a leaked key).
 */
export const shownByDefault = (f: Finding) => f.context === "source" || (f.context === "test" && f.id === "SEC012");

export interface SummaryOptions {
  elapsedMs: number;
  columns?: number;
  outputPath?: string;
  filesWalked?: number;
  includeTests?: boolean;
  /** Whether the CLI will offer to show the hidden findings after the summary. */
  willPrompt?: boolean;
}

/** Findings grouped by primary control, worst control first. */
function renderFindings(findings: Finding[], cols: number, max: number): { lines: string[]; listed: number } {
  const lines: string[] = [];
  let listed = 0;
  const worst = (cid: number) => Math.max(...findings.filter((f) => f.controls[0] === cid).map((f) => SEVERITY_RANK[f.severity]));
  const controls = [...new Set(findings.map((f) => f.controls[0]))].sort((a, b) => worst(b) - worst(a) || a - b);
  for (const cid of controls) {
    if (listed >= max) break;
    const group = findings.filter((f) => f.controls[0] === cid);
    lines.push(` ${gradient("┃")} ${c.bold(`C${cid} · ${CONTROL_SHORT[cid - 1]}`)} ${c.gray(`(${group.length})`)}`);
    const seenGuidance = new Set<string>();
    for (const f of group) {
      if (listed >= max) break;
      listed++;
      lines.push(` ${gradient("┃")}  ${sevBadge(f.severity)} ${c.gray(f.id)}  ${c.underline(`${f.file}:${f.line}`)}${contextTag(f)}`);
      lines.push(` ${gradient("┃")}         ${fit(f.title, cols - 12)}`);
      if (!seenGuidance.has(f.id)) {
        seenGuidance.add(f.id);
        lines.push(` ${gradient("┃")}         ${c.gray("→ " + fit(f.guidance, cols - 14))}`);
      }
    }
    lines.push("");
  }
  return { lines, listed };
}

const cols = (n?: number) => Math.max(60, Math.min(n ?? 100, 120));

export function renderSummary(result: Result, opts: SummaryOptions): { text: string; hidden: Finding[] } {
  const width = cols(opts.columns);
  const out: string[] = [];
  const s = result.stats;
  const secs = (opts.elapsedMs / 1000).toFixed(1);
  const shown = opts.includeTests ? result.findings : result.findings.filter(shownByDefault);
  const hidden = opts.includeTests ? [] : result.findings.filter((f) => !shownByDefault(f));

  out.push("", "");
  out.push(` ${c.green("✔")} ${c.bold("Scan complete")} ${c.gray(`— ${opts.filesWalked !== undefined ? `${opts.filesWalked} files checked, ${s.files_scanned} analysed` : `${s.files_scanned} files analysed`} · ${secs}s · offline scan · your code never left this machine`)}`);
  out.push("");
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = s.by_severity_source[sev] ?? 0;
    return n ? `${sevBadge(sev)}${c.bold(String(n))}` : c.gray(` ${SEV_SHORT[sev]} 0`.padEnd(8));
  });
  out.push("  " + counts.join("   ") + c.gray("   in source code"));
  if (hidden.length) {
    out.push(c.gray(`  ${hidden.length} more in test files or gitignored local env files — ` +
      (opts.willPrompt ? "you can show them after the summary" : "list them with --include-tests")));
  }
  if (s.suppressed) out.push(c.gray(`  ${s.suppressed} suppressed inline (listed in the Markdown/JSON report)`));
  out.push("");

  if (!shown.length) {
    out.push(`  ${c.green("No leads in your source code.")} ${c.gray("That does not mean the project is secure — verify the controls below.")}`);
    out.push("");
  } else {
    const { lines, listed } = renderFindings(shown, width, MAX_LISTED);
    out.push(...lines);
    if (shown.length > listed) {
      out.push(c.gray(`  +${shown.length - listed} more — ` +
        (opts.outputPath ? `all ${result.findings.length} leads are in ${opts.outputPath}` : "write the full report with --output security-report.md")));
      out.push("");
    }
  }

  const leadCount = (id: number) => shown.filter((f) => f.controls[0] === id).length;
  out.push(` ${c.bold("22-CONTROL COVERAGE")}   ${c.gray(`leads${opts.includeTests ? "" : " in source"} · signals src/test · status`)}`);
  for (const ctl of result.controls) {
    const sig = ctl.signals;
    const n = leadCount(ctl.id);
    const leads = n ? c.yellow(String(n).padStart(3)) : c.gray("  –");
    const sigText = sig === null ? "   —    " : `${String(sig.source_count).padStart(4)}/${String(sig.test_count).padEnd(3)}`;
    const gap = sig !== null && sig.source_count === 0 && ctl.id !== 15 && ctl.id !== 17;
    const status = n ? c.yellow("◍ leads to verify") : gap ? c.gray("◌ no signals found") : c.gray("◌ not verified");
    out.push(`  ${c.gray(`C${String(ctl.id).padEnd(2)}`)} ${CONTROL_SHORT[ctl.id - 1].padEnd(28)} ${leads}  ${c.gray(sigText)}  ${status}`);
  }
  out.push(c.gray("  PASS is never automatic: a control passes only when enforcement is located and tested."));
  out.push("");

  if (!result.inventory.test_files) out.push(`  ${c.yellow("!")} No test files detected — most controls can't reach PASS without negative tests.`);
  out.push(` ${c.bold("Next")}`);
  out.push(`  ${gradient("›")} Verify & fix with Claude Code:  ${c.cyan("/saas-security-audit:audit")}`);
  if (opts.outputPath) out.push(`  ${gradient("›")} Report written:  ${c.underline(opts.outputPath)}`);
  else out.push(`  ${gradient("›")} Full report:     ${c.cyan("saas-audit --output security-report.md")}`);
  out.push(`  ${gradient("›")} CI gate:         ${c.cyan("saas-audit --fail-on high --format json")}`);
  out.push("");
  return { text: out.join("\n"), hidden };
}

/** The findings hidden from the default view, shown after the user asks for them. */
export function renderHidden(hidden: Finding[], columns?: number): string {
  const { lines, listed } = renderFindings(hidden, cols(columns), Number.POSITIVE_INFINITY);
  return ["", ` ${c.bold("TEST FILES & LOCAL ENV FILES")} ${c.gray(`(${listed})`)}`, ...lines].join("\n");
}

function contextTag(f: Finding): string {
  return f.context === "source" ? "" : " " + c.gray(`(${f.context})`);
}
