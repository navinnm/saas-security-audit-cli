/** JSON result (same schema as the plugin scanner), baseline comparison, and Markdown report. */
import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";
import { CONTROLS, R, RULE_TITLES, SCHEMA_VERSION, SEVERITY_RANK, VERSION } from "./rules.js";
import type { Finding, ScanState } from "./engine.js";
import { markdownStandards, standardsSummary, standardsTag, vibeSummary, type StandardsSummary, type VibeCheck } from "./standards.js";

const cmpStr = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** shutil.which: is an executable with this name on PATH? (Checks existence only; runs nothing.) */
export function which(binary: string): boolean {
  const exts = process.platform === "win32" ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      try {
        accessSync(join(dir, binary + ext), constants.X_OK);
        return true;
      } catch { /* keep looking */ }
    }
  }
  return false;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) =>
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || cmpStr(a.file, b.file) || a.line - b.line || cmpStr(a.id, b.id));
}

function toolInventory(state: ScanState) {
  const ecosystems = [...new Set(state.manifests.map((m) => R.manifests[m.split("/").pop() as string]))].sort(cmpStr);
  const tools: { command: string; purpose: string; installed: boolean; needs_network: boolean }[] = [];
  const seen = new Set<string>();
  for (const eco of ecosystems) {
    for (const t of R.dep_tools[eco] ?? []) {
      if (seen.has(t.command)) continue;
      seen.add(t.command);
      tools.push({ command: t.command, purpose: `${eco} dependency audit`, installed: which(t.binary), needs_network: t.network });
    }
  }
  for (const t of R.general_tools) {
    tools.push({ command: t.command, purpose: "secrets/static analysis", installed: which(t.binary), needs_network: t.network });
  }
  return { ecosystems, tools };
}

export type Comparison = {
  new: Finding[];
  resolved: Pick<Finding, "id" | "title" | "file" | "line" | "fingerprint">[];
  persisting: number;
};

export function compare(findings: Finding[], baseline: { findings?: Finding[] }): Comparison {
  const old = new Map<string, Finding>();
  for (const f of baseline.findings ?? []) if (f && "fingerprint" in f) old.set(f.fingerprint, f);
  const cur = new Map<string, Finding>();
  for (const f of findings) cur.set(f.fingerprint, f);
  return {
    new: [...cur.entries()].filter(([k]) => !old.has(k)).map(([, f]) => f),
    resolved: [...old.entries()].filter(([k]) => !cur.has(k))
      .map(([, f]) => ({ id: f.id, title: f.title, file: f.file, line: f.line, fingerprint: f.fingerprint })),
    persisting: [...cur.keys()].filter((k) => old.has(k)).length,
  };
}

export function buildResult(root: string, findings: Finding[], state: ScanState, baseline?: { findings?: Finding[] }): Result {
  const { ecosystems, tools } = toolInventory(state);
  const bySeverity: Record<string, number> = {};
  const bySeveritySource: Record<string, number> = {};
  for (const s of Object.keys(SEVERITY_RANK)) {
    bySeverity[s] = findings.filter((f) => f.severity === s).length;
    bySeveritySource[s] = findings.filter((f) => f.severity === s && f.context === "source").length;
  }
  const result: Record<string, unknown> = {
    scanner: "saas-security-audit-heuristics", version: VERSION, schema_version: SCHEMA_VERSION,
    root, mode: "read-only-local-heuristics",
    stats: { files_scanned: state.files_scanned, skipped_large_lines: state.skipped_large_lines,
      findings: findings.length, suppressed: state.suppressed.length, by_severity: bySeverity,
      by_severity_source: bySeveritySource },
    findings, suppressed: state.suppressed,
    controls: CONTROLS.map((name, i) => {
      const id = i + 1;
      const sig = state.signals[id];
      return { id, name, status: "NOT VERIFIED", lead_count: findings.filter((f) => f.controls[0] === id).length,
        signals: sig ? { source_count: sig.source_count, test_count: sig.test_count, locations: sig.source } : null };
    }),
    inventory: { manifests: state.manifests, ecosystems, recommended_tools: tools,
      security_packages: Object.keys(state.packages).sort(cmpStr)
        .map((p) => ({ package: p, control: state.packages[p][0], role: state.packages[p][1] })),
      env_files: state.env_files, test_files: state.test_files, ci_files: state.ci_files },
    standards: standardsSummary(findings),
    vibe_review: vibeSummary(findings),
    limitations: [
      "Regex heuristics only; false positives and false negatives are expected.",
      "No control is automatically marked PASS; signals show where to look, not that a control is enforced.",
      "Env files are judged by the root .gitignore; folders any .gitignore leaves out (build output, generated code) are skipped. Git history is not inspected.",
      "No network access or target-code execution; dependency CVEs require the recommended tools.",
    ],
  };
  if (baseline !== undefined) result.comparison = compare(findings, baseline);
  return result as unknown as Result;
}

export interface Result {
  scanner: string; version: string; schema_version: number; root: string; mode: string;
  stats: { files_scanned: number; skipped_large_lines: number; findings: number; suppressed: number;
    by_severity: Record<string, number>; by_severity_source: Record<string, number> };
  findings: Finding[]; suppressed: Finding[];
  controls: { id: number; name: string; status: string; lead_count: number;
    signals: { source_count: number; test_count: number; locations: string[] } | null }[];
  inventory: { manifests: string[]; ecosystems: string[];
    recommended_tools: { command: string; purpose: string; installed: boolean; needs_network: boolean }[];
    security_packages: { package: string; control: number; role: string }[];
    env_files: { file: string; gitignored: boolean; example: boolean }[]; test_files: number; ci_files: string[] };
  standards: StandardsSummary; vibe_review: VibeCheck[];
  limitations: string[]; comparison?: Comparison;
  /** Present when the user stopped the scan early. */
  partial?: { stopped_at_percent: number };
}

const mdEscape = (t: string) => t.replace(/`/g, "'").replace(/\|/g, "\\|");

export function markdown(result: Result): string {
  const findings = result.findings;
  const stats = result.stats;
  const out: string[] = ["# Local SaaS Security Heuristic Scan", "",
    `- **Scanner:** v${VERSION}, read-only local heuristics; no network requests, no target-code execution.`,
    `- **Files scanned:** ${stats.files_scanned}`,
    "- **Interpretation:** Every finding is a lead to validate in code, not a confirmed vulnerability.",
    "- **Coverage:** No control is automatically marked PASS.", "",
    "## Summary", "", "| Severity | In source code | All leads |", "|---|---|---|"];
  for (const [s, n] of Object.entries(stats.by_severity)) out.push(`| ${s} | ${stats.by_severity_source[s]} | ${n} |`);
  const other = stats.findings - Object.values(stats.by_severity_source).reduce((a, b) => a + b, 0);
  out.push("", `**In source code** excludes ${other} lead(s) in test paths or gitignored local env files; ` +
    "those stay listed below, marked by context. " +
    `Suppressed inline: ${stats.suppressed}.`, "");
  if (!findings.length) out.push("No heuristic matches detected. This does **not** mean the project is secure.", "");
  else {
    out.push("## Leads by control", "");
    CONTROLS.forEach((name, i) => {
      const group = findings.filter((f) => f.controls[0] === i + 1);
      if (!group.length) return;
      out.push(`### C${i + 1}. ${name}`, "");
      for (const rid of [...new Set(group.map((f) => f.id))].sort(cmpStr)) {
        const items = group.filter((f) => f.id === rid)
          .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || cmpStr(a.file, b.file) || a.line - b.line);
        const first = items[0];
        const also = first.controls.slice(1).map((c) => `C${c}`);
        const heading = RULE_TITLES[rid] ?? first.title;
        out.push(`**${rid} — ${heading}** · confidence ${first.confidence}` + (also.length ? ` · also ${also.join(", ")}` : ""), "",
          `Guidance: ${first.guidance}`, "");
        for (const f of items) {
          const ctx = f.context === "source" ? "" : ` _(${f.context})_`;
          const label = f.title !== heading ? ` ${f.title}` : "";
          out.push(`- ${f.severity}${label} — \`${f.file}:${f.line}\`${ctx} — \`${mdEscape(f.evidence)}\`${standardsTag(f)}`);
        }
        out.push("");
      }
    });
  }
  out.push("## Control coverage", "",
    "Status stays NOT VERIFIED until enforcement and tests are confirmed in code. " +
    "Signals are places where enforcement probably lives (source hits / test hits).", "",
    "| # | Control | Status | Leads | Signals (src/test) | Look first |", "|---|---|---|---|---|---|");
  for (const c of result.controls) {
    const sig = c.signals;
    const sigText = sig === null ? "—" : `${sig.source_count}/${sig.test_count}`;
    const look = c.id === 17 ? "agent review" : c.id === 15 ? "dependency tools"
      : sig && !sig.locations.length ? "none found — check for a gap"
      : (sig ? sig.locations.slice(0, 3) : []).map((l) => `\`${l}\``).join(", ");
    out.push(`| ${c.id} | ${c.name} | NOT VERIFIED | ${c.lead_count} | ${sigText} | ${look} |`);
  }
  out.push(...markdownStandards(result));
  const inv = result.inventory;
  out.push("", "## Inventory", "",
    `- Dependency manifests: ${inv.manifests.map((m) => `\`${m}\``).join(", ") || "none found"}`,
    `- Test files detected: ${inv.test_files}` + (!inv.test_files ? " — PASS is unattainable for most controls without tests." : ""),
    `- CI files: ${inv.ci_files.map((c) => `\`${c}\``).join(", ") || "none found"}`);
  if (inv.security_packages.length) {
    out.push("- Security-relevant packages (presence ≠ enforcement): " +
      inv.security_packages.map((p) => `\`${p.package}\` (C${p.control} ${p.role})`).join(", "));
  }
  out.push("", "Recommended tools (ask before running anything that needs network access):", "");
  for (const t of inv.recommended_tools) {
    out.push(`- \`${t.command}\` — ${t.purpose}; ${t.installed ? "installed" : "not installed"}${t.needs_network ? "; needs network" : "; offline"}`);
  }
  if (result.suppressed.length) {
    out.push("", "## Suppressed leads", "", "Inline `security-audit: ignore` markers. Each still needs a reviewer to agree with the reason.", "");
    for (const f of result.suppressed) out.push(`- ${f.id} \`${f.file}:${f.line}\` — reason: ${mdEscape(f.suppressed ?? "")}`);
  }
  if (result.comparison) {
    const c = result.comparison;
    out.push("", "## Baseline comparison", "",
      `- New: ${c.new.length} · Resolved: ${c.resolved.length} · Persisting: ${c.persisting}`,
      "- A resolved lead means the pattern no longer matches — confirm the root cause was fixed, not just reworded.", "");
    for (const f of c.new) out.push(`- NEW ${f.id} \`${f.file}:${f.line}\` — ${f.title}`);
    for (const f of c.resolved) out.push(`- RESOLVED ${f.id} \`${f.file}\` — ${f.title}`);
  }
  out.push("", "## Limitations", "", ...result.limitations.map((l) => `- ${l}`));
  return out.join("\n") + "\n";
}
