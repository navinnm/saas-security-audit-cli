import type { Result } from "../report.js";
import type { Finding } from "../engine.js";
import { SEVERITY_RANK } from "../rules.js";
import { CONTROL_SHORT, SEVERITY_ORDER, SEV_SHORT, c, gradient, sevBadge } from "./theme.js";

const MAX_LISTED = 30;

function fit(plain: string, max: number): string {
  return [...plain].length <= max ? plain : [...plain].slice(0, Math.max(1, max - 1)).join("") + "…";
}

export function renderSummary(result: Result, opts: { elapsedMs: number; columns?: number; outputPath?: string; filesWalked?: number }): string {
  const cols = Math.max(60, Math.min(opts.columns ?? 100, 120));
  const out: string[] = [];
  const s = result.stats;
  const secs = (opts.elapsedMs / 1000).toFixed(1);

  out.push("", "");
  out.push(` ${c.green("✔")} ${c.bold("Scan complete")} ${c.gray(`— ${opts.filesWalked !== undefined ? `${opts.filesWalked} files checked, ${s.files_scanned} analysed` : `${s.files_scanned} files analysed`} · ${secs}s · offline · nothing left your machine`)}`);
  out.push("");
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = s.by_severity_source[sev] ?? 0;
    return n ? `${sevBadge(sev)}${c.bold(String(n))}` : c.gray(` ${SEV_SHORT[sev]} 0`.padEnd(8));
  });
  out.push("  " + counts.join("   ") + c.gray("   in source code"));
  const sourceTotal = Object.values(s.by_severity_source).reduce((a, b) => a + b, 0);
  if (s.findings > sourceTotal) {
    out.push(c.gray(`  +${s.findings - sourceTotal} more in test files or gitignored local env files (listed below, marked by context)`));
  }
  if (s.suppressed) out.push(c.gray(`  ${s.suppressed} suppressed inline (listed in the Markdown/JSON report)`));
  out.push("");

  const findings = result.findings;
  if (!findings.length) {
    out.push(`  ${c.green("No heuristic leads found.")} ${c.gray("That does not mean the project is secure — verify the controls below.")}`);
    out.push("");
  } else {
    let listed = 0;
    const controls = [...new Set(findings.map((f) => f.controls[0]))].sort((a, b) => {
      const worst = (cid: number) => Math.max(...findings.filter((f) => f.controls[0] === cid).map((f) => SEVERITY_RANK[f.severity]));
      return worst(b) - worst(a) || a - b;
    });
    for (const cid of controls) {
      if (listed >= MAX_LISTED) break;
      const group = findings.filter((f) => f.controls[0] === cid);
      out.push(` ${gradient("┃")} ${c.bold(`C${cid} · ${CONTROL_SHORT[cid - 1]}`)} ${c.gray(`(${group.length})`)}`);
      const seenGuidance = new Set<string>();
      for (const f of group) {
        if (listed >= MAX_LISTED) break;
        listed++;
        out.push(` ${gradient("┃")}  ${sevBadge(f.severity)} ${c.gray(f.id)}  ${c.underline(`${f.file}:${f.line}`)}${contextTag(f)}`);
        out.push(` ${gradient("┃")}         ${fit(f.title, cols - 12)}`);
        if (!seenGuidance.has(f.id)) {
          seenGuidance.add(f.id);
          out.push(` ${gradient("┃")}         ${c.gray("→ " + fit(f.guidance, cols - 14))}`);
        }
      }
      out.push("");
    }
    if (findings.length > listed) {
      out.push(c.gray(`  +${findings.length - listed} more leads — ` +
        (opts.outputPath ? `all ${findings.length} are in ${opts.outputPath}` : "write the full report with --output security-report.md")));
      out.push("");
    }
  }

  out.push(` ${c.bold("22-CONTROL COVERAGE")}   ${c.gray("leads · signals src/test · status")}`);
  for (const ctl of result.controls) {
    const sig = ctl.signals;
    const leads = ctl.lead_count ? c.yellow(String(ctl.lead_count).padStart(3)) : c.gray("  –");
    const sigText = sig === null ? "   —    " : `${String(sig.source_count).padStart(4)}/${String(sig.test_count).padEnd(3)}`;
    const gap = sig !== null && sig.source_count === 0 && ctl.id !== 15 && ctl.id !== 17;
    const status = ctl.lead_count ? c.yellow("◍ leads to verify") : gap ? c.gray("◌ no signals found") : c.gray("◌ not verified");
    out.push(`  ${c.gray(`C${String(ctl.id).padEnd(2)}`)} ${CONTROL_SHORT[ctl.id - 1].padEnd(28)} ${leads}  ${c.gray(sigText)}  ${status}`);
  }
  out.push(c.gray("  PASS is never automatic: a control passes only when enforcement is located and tested."));
  out.push("");

  if (!result.inventory.test_files) out.push(`  ${c.yellow("!")} No test files detected — most controls can't reach PASS without negative tests.`);
  out.push(` ${c.bold("Next")}`);
  out.push(`  ${gradient("›")} Verify & fix with Claude Code:  ${c.cyan("/saas-security-audit:audit")}`);
  if (opts.outputPath) out.push(`  ${gradient("›")} Report written:  ${c.underline(opts.outputPath)}`);
  else out.push(`  ${gradient("›")} Full report:     ${c.cyan("saas-audit --format markdown --output security-report.md")}`);
  out.push(`  ${gradient("›")} CI gate:         ${c.cyan("saas-audit --fail-on high --format json")}`);
  out.push("");
  return out.join("\n");
}

function contextTag(f: Finding): string {
  return f.context === "source" ? "" : " " + c.gray(`(${f.context})`);
}

