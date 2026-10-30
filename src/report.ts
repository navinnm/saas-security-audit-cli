/** JSON result (same schema as the plugin scanner), baseline comparison, and Markdown report. */
import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";
import { CONTROLS, R, RULE_TITLES, SCHEMA_VERSION, SEVERITY_RANK, VERSION } from "./rules.js";
import type { Finding, ScanState } from "./engine.js";
import { CLI_VERSION } from "./version.js";
import { standardsSummary, vibeSummary, type StandardsSummary, type VibeCheck } from "./standards.js";
import { buildView, checklistLines, controlLabel, coverageLines, formatDate, standardSections } from "./view.js";

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
      env_files: state.env_files, test_files: state.test_files, ci_files: state.ci_files,
      third_party: state.third_party, third_party_files: state.third_party_files },
    standards: standardsSummary(findings),
    vibe_review: vibeSummary(findings),
    dependencies: state.deps ?? null,
    limitations: [
      "Pattern rules, plus code-flow analysis for JavaScript/TypeScript. Some issues will be missed and some matches will turn out to be safe.",
      "A scan cannot prove that a control works, so no control is marked as passed.",
      "Bundled libraries (third_party/ and similar folders, minified bundles, files that open with an open-source licence header) are scanned but reported separately from the application's own code.",
      "Env files are judged by the root .gitignore; folders any .gitignore leaves out (build output, generated code) are skipped. Git history is not inspected.",
      state.deps && "packages" in state.deps
        ? "No target-code execution. Network: only package names and versions were sent, to api.osv.dev and registry.npmjs.org (--offline turns this off)."
        : "No network access or target-code execution; dependency CVEs were not checked (offline or no lockfile).",
      state.tests_read ? "Test files and gitignored local env files were read (--include-tests)." : "Test files and gitignored local env files were not read; --include-tests reads them.",
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
    env_files: { file: string; gitignored: boolean; example: boolean }[]; test_files: number; ci_files: string[];
    /** Bundled libraries: matches inside them are reported with context "third-party". */
    third_party?: { path: string; files: number }[]; third_party_files?: number };
  standards: StandardsSummary; vibe_review: VibeCheck[];
  limitations: string[]; comparison?: Comparison;
  /** Online dependency check: what was checked, or why it was skipped. */
  dependencies?: ScanState["deps"] | null;
  /** Present when the user stopped the scan early. */
  partial?: { stopped_at_percent: number };
}

export function depsLine(d: Result["dependencies"]): string {
  if (!d) return "not checked";
  if ("skipped" in d) return d.skipped === "offline" ? "not checked (offline)" : d.skipped;
  if (!d.packages) return "no lockfile found (package-lock.json, pnpm-lock.yaml or yarn.lock)";
  return `${d.packages} packages (${(d.ecosystems ?? []).join(", ")}) from ${d.lockfiles.join(", ")} checked against OSV.dev on ${d.checked_at.slice(0, 10)}: ` +
    `${d.vulnerable} with known vulnerabilities (${d.advisories} advisories), ${d.outdated} direct dependencies a major version or more behind` +
    (d.error ? ` (incomplete: ${d.error})` : "");
}

const mdEscape = (t: string) => t.replace(/`/g, "'").replace(/\|/g, "\\|");

/** Locations listed per finding in the Markdown and PDF reports; the JSON output and `saas-audit show` have all of them. */
export const MAX_LOCATIONS = 25;

export function markdown(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): string {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const inv = result.inventory;
  const own = result.stats.files_scanned - (inv.third_party_files ?? 0);
  const out: string[] = [`# Security review: ${v.project}`, R.report_markdown_marker, "",
    "| | |", "|---|---|",
    `| Target | \`${mdEscape(result.root)}\` |`,
    `| Date | ${formatDate(v.generatedAt)} |`,
    `| Scope | ${own} files of application code${inv.third_party_files ? `, ${inv.third_party_files} files in bundled libraries` : ""}; dependencies ${depsLine(result.dependencies)} |`,
    `| Method | Static source review: pattern rules plus code-flow analysis for JavaScript/TypeScript. Read-only; no code was run. |`,
    `| Tool | saas-security-audit v${CLI_VERSION} (rules ${VERSION}) |`, "",
    "## 1. Summary", "", ...v.summary.flatMap((p) => [p, ""])];
  if (v.issues.length) {
    out.push("| Ref | Issue | Severity | Locations |", "|---|---|---|---|");
    for (const i of v.issues) out.push(`| ${i.ref} | ${mdEscape(i.title)} | ${i.severity} | ${i.locations.length} |`);
    out.push("");
  }

  out.push("## 2. Findings", "");
  if (!v.issues.length) out.push("No issues found in the application's own code.", "");
  for (const i of v.issues) {
    out.push(`### ${i.ref} ${i.title}`, "",
      `**Severity:** ${i.severity} · **Confidence:** ${i.confidence} · **Area:** ${controlLabel(i.controls[0])} · **Rule:** ${i.id}`, "");
    if (i.risk) out.push(`**Risk.** ${i.risk}`, "");
    out.push(`**Affected locations** (${i.locations.length} in ${i.files} file${i.files === 1 ? "" : "s"})`, "");
    for (const f of i.locations.slice(0, MAX_LOCATIONS)) {
      const extra = [i.mixed ? f.severity : "", f.title !== i.title ? f.title : ""].filter(Boolean).join(", ");
      out.push(`- \`${f.file}:${f.line}\`${extra ? ` (${mdEscape(extra)})` : ""}: \`${mdEscape(f.evidence)}\``);
    }
    if (i.locations.length > MAX_LOCATIONS) out.push(`- …and ${i.locations.length - MAX_LOCATIONS} more (\`saas-audit show ${i.id}\` lists them all)`);
    out.push("", `**Recommendation.** ${i.guidance}`, "");
    if (i.verify) out.push(`**How to verify.** ${i.verify}`, "");
    if (i.references.length) out.push(`**References.** ${i.references.join(" · ")}`, "");
  }

  let n = 2;
  if (v.libraries.length) {
    out.push(`## ${++n}. Bundled third-party code`, "",
      `${v.thirdParty.length} matches are inside libraries copied into the repository. They are not counted as findings: the code belongs to the library, ` +
      "and the fix is to keep the library on a supported, patched release (or install it through a package manager) rather than edit it.", "",
      "| Library path | Files | Matches | Rules |", "|---|---|---|---|");
    for (const l of v.libraries) out.push(`| \`${mdEscape(l.path)}\` | ${l.files} | ${l.matches} | ${l.rules.join(", ")} |`);
    out.push("");
  }

  out.push(`## ${++n}. Control coverage`, "",
    "A control passes only when its enforcement is found in code and covered by a test. A scan cannot show that, so no control is marked as passed.", "",
    "| # | Control | Result | Findings |", "|---|---|---|---|");
  for (const c of coverageLines(result, v.issues)) out.push(`| C${c.id} | ${c.name} | ${c.result} | ${c.refs.join(", ") || "–"} |`);

  out.push("", `## ${++n}. Common implementation mistakes`, "",
    "Twelve mistakes that turn up most often in quickly built SaaS apps. \"Not found\" means no pattern matched.", "",
    "| # | Check | Result |", "|---|---|---|");
  for (const c of checklistLines(result, v.issues)) out.push(`| ${c.id} | ${c.title} | ${c.refs.length ? `Found: ${c.refs.join(", ")}` : "Not found"} |`);

  out.push("", `## ${++n}. Standards`, "", result.standards.note, "");
  const fws = result.standards.frameworks.filter((fw) => fw.requirements.length);
  for (const sec of standardSections(result, v.issues)) {
    if (!sec.rows.length) continue;
    out.push(`**${sec.title}**`, "", `| ID | ${sec.kind} | Findings |`, "|---|---|---|");
    for (const r of sec.rows) out.push(`| ${r.id} | ${mdEscape(r.name)} | ${r.refs.join(", ")} |`);
    out.push("");
  }
  if (fws.length) {
    out.push("**Compliance frameworks (related requirements)**", "");
    for (const fw of fws) out.push(`- ${fw.name}: ${fw.requirements.map((r) => `${r.ref}${r.name ? ` ${r.name}` : ""}`).join("; ")}`);
    out.push("");
  }

  if (result.suppressed.length) {
    out.push(`## ${++n}. Suppressed matches`, "", "Inline `security-audit: ignore` markers. Each still needs a reviewer to agree with the reason.", "");
    for (const f of result.suppressed) out.push(`- ${f.id} \`${f.file}:${f.line}\`: ${mdEscape(f.suppressed ?? "")}`);
    out.push("");
  }
  if (result.comparison) {
    const c = result.comparison;
    out.push(`## ${++n}. Compared with the previous scan`, "",
      `New: ${c.new.length} · Resolved: ${c.resolved.length} · Unchanged: ${c.persisting}`, "",
      "A resolved match means the pattern no longer matches. Confirm the cause was fixed, not just reworded.", "");
    for (const f of c.new) out.push(`- New: ${f.id} \`${f.file}:${f.line}\` ${f.title}`);
    for (const f of c.resolved) out.push(`- Resolved: ${f.id} \`${f.file}\` ${f.title}`);
    out.push("");
  }

  out.push(`## ${++n}. Scope and limitations`, "",
    "This is an automated static review. Each finding marks code that matches a known weak pattern; a reviewer should confirm it before it is treated as a vulnerability, " +
    `using the "How to verify" step. ${R.verify_note}`, "",
    ...result.limitations.map((l) => `- ${l}`), "",
    `Dependency manifests: ${inv.manifests.map((m) => `\`${m}\``).join(", ") || "none found"}. ` +
    `Test files: ${inv.test_files}. CI files: ${inv.ci_files.map((c) => `\`${c}\``).join(", ") || "none found"}.`, "",
    "Further checks worth running:", "");
  for (const t of inv.recommended_tools) {
    out.push(`- \`${t.command}\` (${t.purpose}; ${t.installed ? "installed" : "not installed"}, ${t.needs_network ? "needs network" : "offline"})`);
  }
  return out.join("\n") + "\n";
}
