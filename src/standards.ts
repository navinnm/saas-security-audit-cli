/**
 * Standards mapping (OWASP Top 10 / API Top 10 / LLM Top 10, CWE, compliance frameworks, MITRE ATT&CK,
 * ATLAS and D3FEND) and the vibe-code review checklist, driven by rules.json.
 */
import type { Finding } from "./engine.js";
import { R } from "./rules.js";

export interface FindingStandards {
  owasp: string | null; owasp_api: string[]; owasp_llm: string[]; cwe: string[];
  attack: string[]; atlas: string[]; d3fend: string[];
}

const EMPTY = { owasp: null, api: [] as string[], llm: [] as string[], cwe: [] as string[], kind: null as string | null,
  attack: [] as string[], atlas: [] as string[], d3fend: [] as string[] };
const std = (rid: string) => R.standards[rid] ?? EMPTY;

export function standardsFor(rid: string): FindingStandards {
  const s = std(rid);
  return { owasp: s.owasp ? `${s.owasp}:2021` : null, owasp_api: s.api.map((a) => `${a}:2023`), owasp_llm: s.llm.map((l) => `${l}:2025`), cwe: [...s.cwe],
    attack: [...s.attack], atlas: [...s.atlas], d3fend: [...s.d3fend] };
}

/** Every standard a finding maps to, labelled for reports: "OWASP A03:2021", "CWE-89", "ATT&CK T1190, T1059", "D3FEND D3-CV". */
export function standardsLabels(st: FindingStandards | undefined): string[] {
  if (!st) return [];
  const family = (name: string, ids: string[]) => (ids.length ? `${name} ${ids.join(", ")}` : "");
  return [st.owasp ? `OWASP ${st.owasp}` : "", ...st.owasp_api.map((a) => `OWASP ${a}`), ...st.owasp_llm.map((l) => `OWASP ${l}`), ...st.cwe,
    family("ATT&CK", st.attack), family("ATLAS", st.atlas), family("D3FEND", st.d3fend)].filter(Boolean);
}

export interface StandardRow { id: string; name: string; leads: number; rules: string[]; checked: boolean }
/** A MITRE technique (ATT&CK, ATLAS) or D3FEND countermeasure that at least one rule maps to. */
export interface TechniqueRow { id: string; name: string; leads: number; rules: string[]; found: string[] }
export interface StandardsSummary {
  owasp_top10_2021: StandardRow[];
  owasp_api_2023: StandardRow[];
  owasp_llm_2025: StandardRow[];
  cwe: { id: string; name: string; leads: number; top25: boolean }[];
  frameworks: { id: string; name: string; requirements: { ref: string; name: string; leads: number }[] }[];
  mitre_attack: TechniqueRow[];
  mitre_atlas: TechniqueRow[];
  mitre_d3fend: TechniqueRow[];
  versions: { attack: string; atlas: string; d3fend: string };
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
  // Every technique the rules can map to, with leads first; a 0 means checked, nothing found.
  const techniques = (names: Record<string, string>, idsOf: (rid: string) => string[]): TechniqueRow[] =>
    Object.entries(names).map(([id, name]) => {
      const rules = Object.keys(R.standards).filter((rid) => idsOf(rid).includes(id)).sort(cmp);
      const hits = src.filter((f) => rules.includes(f.id));
      return { id, name, leads: hits.length, rules, found: rules.filter((rid) => hits.some((f) => f.id === rid)) };
    }).filter((t) => t.rules.length).sort((a, b) => b.leads - a.leads || cmp(a.id, b.id));
  return {
    owasp_top10_2021: block(R.owasp_top10, (rid) => (std(rid).owasp ? [std(rid).owasp as string] : [])),
    owasp_api_2023: block(R.owasp_api, (rid) => std(rid).api),
    owasp_llm_2025: block(R.owasp_llm, (rid) => std(rid).llm),
    cwe, frameworks,
    mitre_attack: techniques(R.attack_techniques, (rid) => std(rid).attack),
    mitre_atlas: techniques(R.atlas_techniques, (rid) => std(rid).atlas),
    mitre_d3fend: techniques(R.d3fend_techniques, (rid) => std(rid).d3fend),
    versions: { ...R.threat_framework_versions },
    note: R.standards_note,
  };
}

export function vibeSummary(findings: Finding[]): VibeCheck[] {
  const src = findings.filter((f) => f.context === "source");
  return R.vibe_checks.map((v) => {
    const leads = src.filter((f) => v.rules.includes(f.id)).length;
    return { id: v.id, title: v.title, rules: v.rules, leads, status: leads ? "found" : "not found" };
  });
}

/** " · A03 · CWE-89 · T1190" — the compact tag used in Markdown and terminal lists. */
export function standardsTag(f: Finding): string {
  const st = f.standards;
  if (!st) return "";
  const tags = [...(st.owasp ? [st.owasp.split(":")[0]] : []), ...st.owasp_api.map((a) => a.split(":")[0]),
    ...st.owasp_llm.map((l) => l.split(":")[0]), ...st.cwe, ...st.attack, ...st.atlas];
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
  const v = s.versions;
  for (const [title, rows, kind] of [[`MITRE ATT&CK (v${v.attack})`, s.mitre_attack, "Technique"], [`MITRE ATLAS (${v.atlas})`, s.mitre_atlas, "Technique"],
    [`MITRE D3FEND (${v.d3fend}) countermeasures`, s.mitre_d3fend, "Countermeasure"]] as const) {
    out.push("", `### ${title}`, "", `| ID | ${kind} | Leads in source | Rules |`, "|---|---|---|---|");
    for (const t of rows) out.push(`| ${t.id} | ${t.name} | ${t.leads || "—"} | ${t.rules.join(", ")} |`);
  }
  return out;
}

/** MITRE ATT&CK Navigator layer (format 4.5): every technique the scan checks, scored by leads in source. */
export function attackLayer(result: { standards: StandardsSummary }, project: string): object {
  const rows = result.standards.mitre_attack;
  const max = Math.max(1, ...rows.map((t) => t.leads));
  return {
    name: `${project} · saas-security-audit`,
    versions: { attack: result.standards.versions.attack.split(".")[0], navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: "Techniques an attacker could use against weaknesses this static scan checks for. Score = leads in source code; grey = checked, no leads. Leads are unverified.",
    techniques: rows.map((t) => ({
      techniqueID: t.id, score: t.leads, enabled: true,
      comment: t.leads ? `${t.leads} lead${t.leads === 1 ? "" : "s"} from ${t.found.join(", ")}` : `Checked by ${t.rules.join(", ")}, no leads`,
      ...(t.leads ? {} : { color: "#d9d9d9" }),
    })),
    gradient: { colors: ["#ffe0b2", "#e65100"], minValue: 1, maxValue: max },
    legendItems: [{ label: "Checked, no leads", color: "#d9d9d9" }, { label: "Leads found (darker = more)", color: "#e65100" }],
    hideDisabled: false, showTacticRowBackground: false,
  };
}
