/**
 * Standards mapping (OWASP Top 10 / API Top 10 / LLM Top 10, CWE, compliance frameworks) and the
 * vibe-code review checklist. A faithful port of the plugin scanner, driven by rules.json.
 */
import type { Finding } from "./engine.js";
import { R } from "./rules.js";

export interface FindingStandards { owasp: string | null; owasp_api: string[]; owasp_llm: string[]; cwe: string[] }

const EMPTY = { owasp: null, api: [] as string[], llm: [] as string[], cwe: [] as string[], kind: null as string | null };
const std = (rid: string) => R.standards[rid] ?? EMPTY;

export function standardsFor(rid: string): FindingStandards {
  const s = std(rid);
  return { owasp: s.owasp ? `${s.owasp}:2021` : null, owasp_api: s.api.map((a) => `${a}:2023`), owasp_llm: s.llm.map((l) => `${l}:2025`), cwe: [...s.cwe] };
}

export interface StandardRow { id: string; name: string; leads: number; rules: string[]; checked: boolean }
export interface StandardsSummary {
  owasp_top10_2021: StandardRow[];
  owasp_api_2023: StandardRow[];
  owasp_llm_2025: StandardRow[];
  cwe: { id: string; name: string; leads: number; top25: boolean }[];
  frameworks: { id: string; name: string; requirements: { ref: string; name: string; leads: number }[] }[];
  note: string;
}
export interface VibeCheck { id: string; title: string; rules: string[]; leads: number; status: "found" | "not found" }

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function standardsSummary(findings: Finding[]): StandardsSummary {
  const src = findings.filter((f) => f.context === "source");
  const block = (names: Record<string, string>, codesOf: (rid: string) => string[]): StandardRow[] =>
    Object.entries(names).map(([code, name]) => {
      const rules = Object.keys(R.standards).filter((rid) => codesOf(rid).includes(code)).sort(cmp);
      return { id: code, name, leads: src.filter((f) => rules.includes(f.id)).length, rules, checked: rules.length > 0 };
    });
  const cweCounts = new Map<string, number>();
  for (const f of src) for (const c of std(f.id).cwe) cweCounts.set(c, (cweCounts.get(c) ?? 0) + 1);
  const top25 = new Set(R.cwe_top25_2024);
  const cwe = [...cweCounts.entries()]
    .sort((a, b) => b[1] - a[1] || Number(a[0].split("-")[1]) - Number(b[0].split("-")[1]))
    .map(([id, leads]) => ({ id, name: R.cwe_names[id] ?? id, leads, top25: top25.has(id) }));
  const kindCounts = new Map<string, number>();
  for (const f of src) {
    const kind = std(f.id).kind;
    if (kind) kindCounts.set(kind, (kindCounts.get(kind) ?? 0) + 1);
  }
  const frameworks = R.frameworks.map((fw) => {
    const refs = new Map<string, number>();
    for (const [kind, n] of kindCounts) for (const ref of fw.mapping[kind] ?? []) refs.set(ref, (refs.get(ref) ?? 0) + n);
    return {
      id: fw.id, name: fw.name,
      requirements: [...refs.entries()].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))
        .map(([ref, leads]) => ({ ref, name: R.framework_ref_names[ref] ?? "", leads })),
    };
  });
  return {
    owasp_top10_2021: block(R.owasp_top10, (rid) => (std(rid).owasp ? [std(rid).owasp as string] : [])),
    owasp_api_2023: block(R.owasp_api, (rid) => std(rid).api),
    owasp_llm_2025: block(R.owasp_llm, (rid) => std(rid).llm),
    cwe, frameworks, note: R.standards_note,
  };
}

export function vibeSummary(findings: Finding[]): VibeCheck[] {
  const src = findings.filter((f) => f.context === "source");
  return R.vibe_checks.map((v) => {
    const leads = src.filter((f) => v.rules.includes(f.id)).length;
    return { id: v.id, title: v.title, rules: v.rules, leads, status: leads ? "found" : "not found" };
  });
}

/** " · A03 · CWE-89" — the compact tag used in Markdown and terminal lists. */
export function standardsTag(f: Finding): string {
  const st = f.standards;
  if (!st) return "";
  const tags = [...(st.owasp ? [st.owasp.split(":")[0]] : []), ...st.owasp_api.map((a) => a.split(":")[0]),
    ...st.owasp_llm.map((l) => l.split(":")[0]), ...st.cwe];
  return tags.length ? ` · ${tags.join(" · ")}` : "";
}

export function markdownStandards(result: { standards: StandardsSummary; vibe_review: VibeCheck[] }): string[] {
  const s = result.standards;
  const out = ["", "## Vibe-code review", "",
    "Mistakes that AI-generated apps make most often. \"Not found\" means no lead matched; it is not a pass.", "",
    "| # | Check | Status | Leads in source | Rules |", "|---|---|---|---|---|"];
  for (const v of result.vibe_review) out.push(`| ${v.id} | ${v.title} | ${v.status === "found" ? "FOUND" : "not found"} | ${v.leads} | ${v.rules.join(", ")} |`);
  const row = (r: StandardRow) => `| ${r.id} | ${r.name} | ${r.checked ? r.leads : "—"} | ${r.rules.join(", ") || "not checked by this scanner"} |`;
  out.push("", "## Standards", "", s.note, "", "### OWASP Top 10 (2021)", "", "| ID | Category | Leads in source | Rules |", "|---|---|---|---|");
  out.push(...s.owasp_top10_2021.map(row));
  for (const [title, rows] of [["OWASP API Security Top 10 (2023)", s.owasp_api_2023], ["OWASP Top 10 for LLM Applications (2025)", s.owasp_llm_2025]] as const) {
    out.push("", `### ${title}`, "", "| ID | Category | Leads in source | Rules |", "|---|---|---|---|", ...rows.map(row));
  }
  out.push("", "### CWE", "");
  if (s.cwe.length) {
    out.push("| CWE | Weakness | Leads in source | CWE Top 25 (2024) |", "|---|---|---|---|");
    for (const c of s.cwe) out.push(`| ${c.id} | ${c.name} | ${c.leads} | ${c.top25 ? "yes" : ""} |`);
  } else out.push("No CWE-mapped leads in source code.");
  out.push("", "### Compliance frameworks (related requirements)", "");
  for (const fw of s.frameworks) {
    const reqs = fw.requirements.map((r) => (r.name ? `${r.ref} ${r.name} (${r.leads})` : `${r.ref} (${r.leads})`)).join(", ");
    out.push(`- **${fw.name}:** ${reqs || "no related leads in source code"}`);
  }
  return out;
}
