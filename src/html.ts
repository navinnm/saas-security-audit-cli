/**
 * Self-contained HTML report: no external fonts, scripts, or images, so it opens offline and
 * never makes a network request. Laid out like a security assessment document (numbered sections,
 * restrained type, one accent colour) for screen and for print (A4).
 */
import type { Finding } from "./engine.js";
import type { Result } from "./report.js";
import { standardsLabels, type TechniqueRow } from "./standards.js";
import { R } from "./rules.js";
import { CLI_VERSION as VERSION } from "./version.js";
import { buildView, controlLabel, formatDate, SEVERITY_ORDER, type CoverageRow, type View } from "./view.js";

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
const SEV_KEY: Record<string, string> = { Critical: "crit", High: "high", Medium: "med", Low: "low", Informational: "info" };
const SEV_LABEL: Record<string, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", Informational: "Informational" };
const RATING: Record<View["posture"]["level"], string> = { critical: "Critical risk", high: "Elevated risk", medium: "Moderate risk", low: "Low risk" };

/** Finding numbers for the report (F-01, F-02 …), in the order shown. */
const ref = (i: number, total: number) => `F-${String(i + 1).padStart(Math.max(2, String(total).length), "0")}`;

const sev = (s: string) => `<span class="sev ${SEV_KEY[s]}"><i></i>${SEV_LABEL[s]}</span>`;

const stdTags = (f: Finding) => standardsLabels(f.standards).map(esc).join(" · ");

function findingRow(f: Finding, i: number, total: number, withEvidence: boolean): string {
  const k = SEV_KEY[f.severity];
  const ctx = f.context === "source" ? "" : ` <span class="muted">(${esc(f.context)})</span>`;
  const search = esc(`${f.id} ${f.title} ${f.file} ${controlLabel(f.controls[0])}`.toLowerCase());
  const tags = stdTags(f);
  const detail = withEvidence
    ? `<details><summary>Evidence and remediation</summary>
<dl class="detail"><dt>Evidence</dt><dd><pre>${esc(f.evidence)}</pre></dd>
<dt>Remediation</dt><dd>${esc(f.guidance)}</dd>
<dt>Classification</dt><dd>${esc(controlLabel(f.controls[0]))}${f.controls.length > 1 ? ` (also ${f.controls.slice(1).map((c) => esc(controlLabel(c))).join(", ")})` : ""} · confidence ${esc(f.confidence)}${tags ? ` · ${tags}` : ""}</dd></dl></details>`
    : "";
  return `<tr class="f" data-sev="${k}" data-q="${search}"><td class="ref">${ref(i, total)}</td><td>${sev(f.severity)}</td>
<td><div class="title">${esc(f.title)}</div><div class="loc">${esc(f.file)}:${f.line}${ctx}</div>${detail}</td>
<td class="rule">${esc(f.id)}</td></tr>`;
}

function findingsTable(findings: Finding[], withEvidence: boolean, id: string): string {
  if (!findings.length) return `<p class="note">No leads in source code. This is not evidence that the application is secure; the controls listed under Control coverage still need verification.</p>`;
  return `<table class="findings" id="${id}"><thead><tr><th>Ref.</th><th>Severity</th><th>Finding and location</th><th>Rule</th></tr></thead>
<tbody>${findings.map((f, i) => findingRow(f, i, findings.length, withEvidence)).join("\n")}</tbody></table>`;
}

function coverageRow(r: CoverageRow, status: "leads" | "none" | "unverified"): string {
  const label = { leads: `<span class="status warn">Leads to verify</span>`, none: `<span class="status">No signals found</span>`, unverified: `<span class="status">Not verified</span>` }[status];
  const sig = r.signals ? `${r.signals.source_count} / ${r.signals.test_count}` : "–";
  const look = r.id === 17 ? "Independent review (Claude Code plugin)" : r.id === 15 ? "Dependency and secret scanning tools"
    : r.signals?.locations.length ? r.signals.locations.slice(0, 3).map((l) => `<code>${esc(l)}</code>`).join(" ") : `<span class="muted">–</span>`;
  return `<tr><td class="ref">C${r.id}</td><td>${esc(r.name)}</td><td>${label}</td><td class="num">${r.leads || "–"}</td><td class="num muted">${sig}</td><td class="look">${look}</td></tr>`;
}

function vibeHtml(result: Result, n: number): string {
  const found = result.vibe_review.filter((v) => v.status === "found").length;
  return `<section><h2><span>${n}</span>Vibe-code review</h2>
<p class="lede">Patterns common in AI-generated code. ${found} of ${result.vibe_review.length} were matched. "Not matched" means no lead was found; it is not a pass.</p>
<table><thead><tr><th>Pattern</th><th>Rules</th><th>Result</th><th class="num">Leads</th></tr></thead><tbody>
${result.vibe_review.map((v) => `<tr><td>${esc(v.title)}</td><td class="muted mono small">${esc(v.rules.join(", "))}</td>
<td>${v.status === "found" ? `<span class="status warn">Matched</span>` : `<span class="status">Not matched</span>`}</td><td class="num">${v.status === "found" ? v.leads : "–"}</td></tr>`).join("")}
</tbody></table></section>`;
}

function techTable(title: string, kind: string, rows: TechniqueRow[]): string {
  return `<h3>${esc(title)}</h3><table><thead><tr><th>ID</th><th>${kind}</th><th class="num">Leads</th><th>Rules</th></tr></thead><tbody>
${rows.map((t) => `<tr><td class="mono${t.leads ? " strong" : ""}">${esc(t.id)}</td><td>${esc(t.name)}</td><td class="num${t.leads ? " strong" : ""}">${t.leads || "–"}</td>
<td class="muted small">${esc(t.rules.join(", "))}</td></tr>`).join("")}</tbody></table>`;
}

function standardsHtml(result: Result, n: number): string {
  const s = result.standards;
  const table = (title: string, rows: typeof s.owasp_top10_2021) => `<h3>${title}</h3><table><thead><tr><th>ID</th><th>Category</th><th class="num">Leads</th><th>Rules</th></tr></thead><tbody>
${rows.map((r) => `<tr><td class="mono${r.leads ? " strong" : ""}">${esc(r.id)}</td><td>${esc(r.name)}</td><td class="num${r.leads ? " strong" : ""}">${r.checked ? (r.leads || "–") : "–"}</td>
<td class="muted small">${r.checked ? esc(r.rules.join(", ")) : "Not covered by this scanner"}</td></tr>`).join("")}</tbody></table>`;
  const cwe = s.cwe.length ? `<table><thead><tr><th>CWE</th><th>Weakness</th><th class="num">Leads</th><th>CWE Top 25 (2024)</th></tr></thead><tbody>
${s.cwe.map((x) => `<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.name)}</td><td class="num">${x.leads}</td><td>${x.top25 ? "Yes" : `<span class="muted">–</span>`}</td></tr>`).join("")}</tbody></table>`
    : `<p class="note">No CWE-mapped leads in source code.</p>`;
  const fws = s.frameworks.map((fw) => `<tr><td class="strong">${esc(fw.name)}</td><td>${fw.requirements.length
    ? fw.requirements.map((r) => `<span class="req">${esc(r.ref)}${r.name ? ` ${esc(r.name)}` : ""} <span class="muted">(${r.leads})</span></span>`).join("")
    : '<span class="muted">No related leads in source code</span>'}</td></tr>`).join("");
  return `<section><h2><span>${n}</span>Standards mapping</h2>
<p class="lede">${esc(s.note)}</p>
${table("OWASP Top 10 (2021)", s.owasp_top10_2021)}
${table("OWASP API Security Top 10 (2023)", s.owasp_api_2023)}
${table("OWASP Top 10 for LLM Applications (2025)", s.owasp_llm_2025)}
<h3>CWE</h3>${cwe}
<h3>Compliance frameworks</h3><table><thead><tr><th>Framework</th><th>Related requirements (leads)</th></tr></thead><tbody>${fws}</tbody></table>
${techTable(`MITRE ATT&CK (v${s.versions.attack})`, "Technique", s.mitre_attack)}
${techTable(`MITRE ATLAS (${s.versions.atlas})`, "Technique", s.mitre_atlas)}
${techTable(`MITRE D3FEND (${s.versions.d3fend}) countermeasures`, "Countermeasure", s.mitre_d3fend)}</section>`;
}

export function renderHtml(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): string {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const s = result.stats;
  const inv = result.inventory;
  const total = SEVERITY_ORDER.reduce((a, x) => a + (v.sourceCounts[x] ?? 0), 0);
  const sevRows = SEVERITY_ORDER.map((x) => {
    const n = v.sourceCounts[x] ?? 0;
    return `<tr${n ? "" : ' class="zero"'}><td>${sev(x)}</td><td class="num">${n}</td><td class="barcell"><span class="bar ${SEV_KEY[x]}" style="width:${total ? (100 * n) / total : 0}%"></span></td></tr>`;
  }).join("");
  const filters = [`<button class="filter on" data-f="all">All (${v.shown.length})</button>`,
    ...SEVERITY_ORDER.map((x) => {
      const n = v.shown.filter((f) => f.severity === x).length;
      return n ? `<button class="filter" data-f="${SEV_KEY[x]}">${SEV_LABEL[x]} (${n})</button>` : "";
    })].join("");
  const coverage = ([
    ...v.coverage.leads.map((r) => [r, "leads"] as const),
    ...v.coverage.noSignals.map((r) => [r, "none"] as const),
    ...v.coverage.notVerified.map((r) => [r, "unverified"] as const),
  ]).sort((x, y) => x[0].id - y[0].id).map(([r, st]) => coverageRow(r, st)).join("\n");
  const plan = v.guidance.map((g, i) => `<tr><td class="ref">${i + 1}</td><td><div class="title">${esc(g.title)}</div><div class="muted">${esc(g.guidance)}</div>${g.verify ? `<div class="verify"><b>Verify:</b> ${esc(g.verify)}</div>` : ""}</td>
<td class="rule">${esc(g.id)}</td><td class="num">${g.count}</td></tr>`).join("");
  const tools = inv.recommended_tools.map((t) => `<tr><td><code>${esc(t.command)}</code></td><td>${esc(t.purpose)}</td>
<td>${t.installed ? "Installed" : `<span class="muted">Not installed</span>`}</td><td class="muted">${t.needs_network ? "Needs network" : "Offline"}</td></tr>`).join("");
  const date = formatDate(v.generatedAt);
  // Sections are numbered as they appear (the remediation plan is left out when there is nothing to fix).
  let sectionNo = 0;
  const no = () => ++sectionNo;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security assessment · ${esc(v.project)}</title>
<style>
:root{--ink:#111827;--body:#374151;--muted:#6b7280;--rule:#e5e7eb;--rule2:#d1d5db;--shade:#f9fafb;--accent:#1f3a5f;
--crit:#991b1b;--high:#b45309;--med:#a16207;--low:#1d4ed8;--info:#4b5563}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:#eef0f3;color:var(--body);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-feature-settings:"tnum" 1}
.page{max-width:920px;margin:32px auto;background:#fff;border:1px solid var(--rule2);padding:56px 64px 40px}
.mono,code,pre{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
code{font-size:12px;color:var(--ink);word-break:break-all}
h1,h2,h3{color:var(--ink);font-weight:600;letter-spacing:-.005em}
.doc-head{border-top:4px solid var(--accent);padding-top:22px}
.kicker{font-size:11px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);margin:0}
h1{font-size:28px;line-height:1.2;margin:10px 0 22px}
.meta{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:0;font-size:13px;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);padding:14px 0}
.meta dt{color:var(--muted)}.meta dd{margin:0;color:var(--ink);word-break:break-all}
section{margin-top:40px}
h2{font-size:18px;margin:0 0 6px;padding-bottom:8px;border-bottom:1px solid var(--rule2);display:flex;gap:12px;align-items:baseline}
h2 span{color:var(--accent);font-variant-numeric:tabular-nums;min-width:18px}
h3{font-size:14px;margin:24px 0 8px}
.lede{color:var(--muted);margin:10px 0 16px;font-size:13.5px}
.note{color:var(--muted);margin:8px 0}
.summary{display:grid;grid-template-columns:1fr 1fr;gap:28px;margin-top:16px}
.rating{border:1px solid var(--rule2);border-left:4px solid var(--c);padding:14px 18px}
.rating .label{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.rating .value{font-size:20px;font-weight:600;color:var(--c);margin:2px 0 6px}
.rating p{margin:0;font-size:13.5px}
.critical{--c:var(--crit)}.high{--c:var(--high)}.medium{--c:var(--med)}.low{--c:#166534}
dl.facts{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;margin:14px 0 0;font-size:13px}
dl.facts dt{color:var(--muted)}dl.facts dd{margin:0;color:var(--ink);font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;border-bottom:1px solid var(--rule2);background:var(--shade)}
td{padding:9px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.muted{color:var(--muted)}.verify{margin-top:4px;font-size:12px;color:var(--muted)}.verify b{color:var(--ink);font-weight:600}.small{font-size:12px}.strong{color:var(--ink);font-weight:600}
.sev{display:inline-flex;align-items:center;gap:7px;color:var(--c);font-weight:600;font-size:12.5px;white-space:nowrap}
.sev i{width:9px;height:9px;background:var(--c);display:inline-block}
.sev.crit{--c:var(--crit)}.sev.high{--c:var(--high)}.sev.med{--c:var(--med)}.sev.low{--c:var(--low)}.sev.info{--c:var(--info)}
.severity td{padding:7px 10px}.severity tr.zero .sev{opacity:.45}.severity tr.zero .num{color:var(--muted)}
.barcell{width:45%;vertical-align:middle}.bar{display:block;height:6px;background:var(--c)}
.bar.crit{--c:var(--crit)}.bar.high{--c:var(--high)}.bar.med{--c:var(--med)}.bar.low{--c:var(--low)}.bar.info{--c:var(--info)}
.ref{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted);white-space:nowrap;width:56px}
.rule{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--muted);white-space:nowrap;width:70px}
.findings td:nth-child(2){width:120px}
.title{color:var(--ink);font-weight:550}
.loc{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--body);margin-top:2px;word-break:break-all}
details summary{cursor:pointer;color:var(--accent);font-size:12px;margin-top:6px;list-style:none}
details summary::-webkit-details-marker{display:none}
details summary:before{content:"+ "}details[open] summary:before{content:"– "}
dl.detail{display:grid;grid-template-columns:110px 1fr;gap:6px 14px;margin:10px 0 4px;font-size:12.5px}
dl.detail dt{color:var(--muted)}dl.detail dd{margin:0}
pre{background:var(--shade);border:1px solid var(--rule);padding:8px 10px;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:0;color:var(--ink)}
.toolbar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:14px 0 10px}
.filter{border:1px solid var(--rule2);background:#fff;color:var(--body);padding:4px 10px;font:inherit;font-size:12.5px;cursor:pointer}
.filter.on{background:var(--accent);border-color:var(--accent);color:#fff}
.search{margin-left:auto;border:1px solid var(--rule2);padding:5px 9px;font:inherit;font-size:13px;min-width:230px}
.status{font-size:12.5px;color:var(--muted);white-space:nowrap}.status.warn{color:var(--high);font-weight:600}
.look code{display:block;margin:0 0 2px}
.req{display:inline-block;margin:2px 16px 2px 0}
ul.notes{margin:10px 0 0;padding-left:18px}ul.notes li{margin:4px 0}
.confidential{margin-top:44px;padding-top:14px;border-top:1px solid var(--rule2);display:flex;justify-content:space-between;gap:16px;font-size:11.5px;color:var(--muted)}
.hidden{display:none}
@media (max-width:760px){.page{margin:0;border:0;padding:28px 18px}.summary{grid-template-columns:1fr}.meta{grid-template-columns:110px 1fr}
.findings td:nth-child(4),.findings th:nth-child(4){display:none}.search{min-width:0;width:100%;margin-left:0}
dl.detail{grid-template-columns:1fr;gap:2px}dl.detail dd{min-width:0;margin-bottom:8px}
table:not(.findings):not(.severity){display:block;overflow-x:auto}}
@media print{
 @page{size:A4;margin:16mm 15mm}
 body{background:#fff;font-size:11px}.page{margin:0;border:0;padding:0;max-width:none}
 section{break-inside:auto}h2,h3{break-after:avoid}tr{break-inside:avoid}
 .toolbar{display:none}details>summary{display:none}details{display:block}details:not([open])>*:not(summary){display:block}
 .bar,.sev i,.rating{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style></head>
<body><div class="page">

<header class="doc-head">
<p class="kicker">Security assessment report · Confidential</p>
<h1>Static security review of ${esc(v.project)}</h1>
<dl class="meta">
<dt>Target</dt><dd>${esc(v.project)}</dd>
<dt>Location</dt><dd class="mono">${esc(result.root)}</dd>
<dt>Date</dt><dd>${esc(date)}</dd>
<dt>Method</dt><dd>Read-only static analysis against 22 SaaS security controls; no code executed, no network access</dd>
<dt>Tool</dt><dd>saas-security-audit v${esc(VERSION)}</dd>
</dl>
</header>

<section>
<h2><span>${no()}</span>Executive summary</h2>
<div class="summary">
<div>
<div class="rating ${v.posture.level}"><div class="label">Overall rating</div><div class="value">${RATING[v.posture.level]}</div><p>${esc(v.posture.headline)}. ${esc(v.posture.detail)}</p></div>
<dl class="facts"><dt>Files analysed</dt><dd>${s.files_scanned}</dd><dt>Controls with leads</dt><dd>${v.controlsWithLeads} of 22</dd>
${v.hidden.length ? `<dt>Leads in test or local env files</dt><dd>${v.hidden.length}</dd>` : ""}${s.suppressed ? `<dt>Suppressed inline</dt><dd>${s.suppressed}</dd>` : ""}
${v.stack.length ? `<dt>Stack detected</dt><dd>${v.stack.map(esc).join(", ")}</dd>` : ""}</dl>
</div>
<div><table class="severity"><thead><tr><th>Severity</th><th class="num">Findings</th><th></th></tr></thead><tbody>${sevRows}
<tr><td class="strong">Total</td><td class="num strong">${total}</td><td></td></tr></tbody></table>
<p class="note small">Findings in application source code. Test files and gitignored local env files are reported separately.</p></div>
</div>
</section>

<section class="findings-section">
<h2><span>${no()}</span>Findings</h2>
<p class="lede">Each finding is a lead to confirm in code, not a confirmed vulnerability. Evidence is redacted; secret values never appear in this report.</p>
${v.shown.length ? `<div class="toolbar">${filters}<input class="search" type="search" placeholder="Filter by rule, file or issue" aria-label="Filter findings"></div>` : ""}
${findingsTable(v.shown, true, "main-findings")}
${v.hidden.length ? `<h3>Test files &amp; local env files (${v.hidden.length})</h3><p class="note">Usually intentional samples (fixtures, mocks) or secrets in gitignored local env files. Not counted in the totals above.</p>
${findingsTable(v.hidden, true, "test-findings")}` : ""}
</section>

${v.guidance.length ? `<section><h2><span>${no()}</span>Remediation plan</h2>
<p class="lede">One action per rule, most severe first, with a manual check that confirms or rules out the lead. ${esc(R.verify_note)}</p>
<table><thead><tr><th>#</th><th>Action</th><th>Rule</th><th class="num">Findings</th></tr></thead><tbody>${plan}</tbody></table></section>` : ""}

<section><h2><span>${no()}</span>Control coverage</h2>
<p class="lede">A control passes only when its enforcement is located in code and proven by a negative test; this scan never marks a control as passed. Signals show where enforcement probably lives (source / test files).</p>
<table><thead><tr><th>Ref.</th><th>Control</th><th>Status</th><th class="num">Leads</th><th class="num">Signals</th><th>Look first</th></tr></thead>
<tbody>${coverage}</tbody></table>
</section>

${vibeHtml(result, no())}

${standardsHtml(result, no())}

<section><h2><span>${no()}</span>Scope, method and limitations</h2>
<ul class="notes">
<li>Read-only static analysis on the local machine. No code was executed and nothing was sent anywhere.</li>
${result.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}
<li>Findings are leads to validate. For verification, fixes and regression tests, run <code>/saas-security-audit:audit</code> in Claude Code.</li>
</ul>
<h3>Inventory</h3>
<dl class="facts"><dt>Dependency manifests</dt><dd>${inv.manifests.map(esc).join(", ") || "None found"}</dd><dt>Test files</dt><dd>${inv.test_files}</dd><dt>CI files</dt><dd>${inv.ci_files.map(esc).join(", ") || "None found"}</dd></dl>
<h3>Recommended tools</h3>
<table><thead><tr><th>Command</th><th>Purpose</th><th>Status</th><th>Network</th></tr></thead><tbody>${tools}</tbody></table>
</section>

<footer class="confidential"><span>Confidential · Prepared with saas-security-audit v${esc(VERSION)} · Secret values redacted</span><span>${esc(date)}</span></footer>
</div>
<script>
(function(){var t=document.getElementById("main-findings");if(!t)return;var rows=[].slice.call(t.querySelectorAll("tr.f")),f="all",q="";
function apply(){rows.forEach(function(r){var ok=(f==="all"||r.dataset.sev===f)&&(!q||r.dataset.q.indexOf(q)>-1);r.classList.toggle("hidden",!ok);});}
[].forEach.call(document.querySelectorAll(".filter"),function(b){b.addEventListener("click",function(){[].forEach.call(document.querySelectorAll(".filter"),function(x){x.classList.remove("on")});b.classList.add("on");f=b.dataset.f;apply();});});
var s=document.querySelector(".search");if(s)s.addEventListener("input",function(){q=s.value.trim().toLowerCase();apply();});
window.addEventListener("beforeprint",function(){[].forEach.call(document.querySelectorAll("details"),function(d){d.open=true});});})();
</script>
</body></html>
`;
}
