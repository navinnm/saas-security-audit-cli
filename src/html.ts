/**
 * Self-contained HTML report: no external fonts, scripts, or images, so it opens offline and
 * never makes a network request. Laid out like a security assessment document (numbered sections,
 * one finding per issue with its locations, restrained type, one accent colour) for screen and for print (A4).
 */
import type { Result } from "./report.js";
import { depsLine } from "./report.js";
import { R, VERSION as RULES_VERSION } from "./rules.js";
import { CLI_VERSION as VERSION } from "./version.js";
import { buildView, checklistLines, controlLabel, coverageLines, formatDate, SEVERITY_ORDER, standardSections, type Issue, type View } from "./view.js";

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
const SEV_KEY: Record<string, string> = { Critical: "crit", High: "high", Medium: "med", Low: "low", Informational: "info" };
const RATING: Record<View["posture"]["level"], string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
/** Locations shown before the rest fold away. */
const OPEN_LOCATIONS = 8;

const sev = (s: string) => `<span class="sev ${SEV_KEY[s]}"><i></i>${esc(s)}</span>`;

function locationRows(i: Issue): string {
  const row = (f: Issue["locations"][number]) => {
    const extra = [i.mixed ? f.severity : "", f.title !== i.title ? f.title : ""].filter(Boolean).join(" · ");
    return `<li><div class="loc">${esc(f.file)}:${f.line}${extra ? ` <span class="muted">${esc(extra)}</span>` : ""}</div><pre>${esc(f.evidence)}</pre></li>`;
  };
  const first = i.locations.slice(0, OPEN_LOCATIONS).map(row).join("");
  const rest = i.locations.slice(OPEN_LOCATIONS);
  return `<ul class="locs">${first}</ul>${rest.length
    ? `<details class="more"><summary>${rest.length} more location${rest.length === 1 ? "" : "s"}</summary><ul class="locs">${rest.map(row).join("")}</ul></details>` : ""}`;
}

function issueCard(i: Issue): string {
  const search = esc(`${i.ref} ${i.id} ${i.title} ${i.locations.map((f) => f.file).join(" ")}`.toLowerCase());
  return `<article class="issue" data-sev="${SEV_KEY[i.severity]}" data-q="${search}" id="${i.ref}">
<header><span class="ref">${i.ref}</span><h3>${esc(i.title)}</h3>${sev(i.severity)}</header>
<p class="facts">Confidence ${esc(i.confidence)} · ${esc(controlLabel(i.controls[0]))} · ${i.locations.length} location${i.locations.length === 1 ? "" : "s"} in ${i.files} file${i.files === 1 ? "" : "s"} · Rule ${esc(i.id)}</p>
${i.risk ? `<h4>Risk</h4><p>${esc(i.risk)}</p>` : ""}
<h4>Affected locations</h4>${locationRows(i)}
<h4>Recommendation</h4><p>${esc(i.guidance)}</p>
${i.verify ? `<h4>How to verify</h4><p>${esc(i.verify)}</p>` : ""}
${i.references.length ? `<p class="refs">${i.references.map(esc).join(" · ")}</p>` : ""}
</article>`;
}

export function renderHtml(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): string {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const inv = result.inventory;
  const own = result.stats.files_scanned - (inv.third_party_files ?? 0);
  const date = formatDate(v.generatedAt);
  const counts = SEVERITY_ORDER.map((x) => [x, v.issues.filter((i) => i.severity === x).length, v.issues.filter((i) => i.severity === x).reduce((a, i) => a + i.locations.length, 0)] as const);
  const sevRows = counts.map(([x, n, locs]) => `<tr${n ? "" : ' class="zero"'}><td>${sev(x)}</td><td class="num">${n}</td><td class="num">${locs}</td></tr>`).join("");
  const keyRows = v.issues.map((i) => `<tr><td class="ref"><a href="#${i.ref}">${i.ref}</a></td><td>${esc(i.title)}</td><td>${sev(i.severity)}</td><td class="num">${i.locations.length}</td></tr>`).join("");
  const filters = v.issues.length > 3 ? [`<button class="filter on" data-f="all">All (${v.issues.length})</button>`,
    ...SEVERITY_ORDER.map((x) => {
      const n = v.issues.filter((i) => i.severity === x).length;
      return n ? `<button class="filter" data-f="${SEV_KEY[x]}">${x} (${n})</button>` : "";
    })].join("") : "";
  const coverage = coverageLines(result, v.issues).map((c) => `<tr><td class="ref">C${c.id}</td><td>${esc(c.name)}</td>
<td>${c.found ? `<span class="status warn">${esc(c.result)}</span>` : `<span class="status">${esc(c.result)}</span>`}</td>
<td>${c.refs.map((r) => `<a href="#${r}">${r}</a>`).join(", ") || `<span class="muted">–</span>`}</td></tr>`).join("");
  const checklist = checklistLines(result, v.issues).map((c) => `<tr><td class="ref">${c.id}</td><td>${esc(c.title)}</td>
<td>${c.refs.length ? `<span class="status warn">Found</span> ${c.refs.map((r) => `<a href="#${r}">${r}</a>`).join(", ")}` : `<span class="status">Not found</span>`}</td></tr>`).join("");
  const standards = standardSections(result, v.issues).filter((sec) => sec.rows.length).map((sec) => `<h3>${esc(sec.title)}</h3>
<table><thead><tr><th>ID</th><th>${sec.kind}</th><th>Findings</th></tr></thead><tbody>
${sec.rows.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.name)}</td><td>${r.refs.map((x) => `<a href="#${x}">${x}</a>`).join(", ")}</td></tr>`).join("")}</tbody></table>`).join("");
  const fws = result.standards.frameworks.filter((fw) => fw.requirements.length).map((fw) => `<tr><td class="strong">${esc(fw.name)}</td><td>${fw.requirements
    .map((r) => `<span class="req">${esc(r.ref)}${r.name ? ` ${esc(r.name)}` : ""}</span>`).join("")}</td></tr>`).join("");
  const libraries = v.libraries.map((l) => `<tr><td><code>${esc(l.path)}</code></td><td class="num">${l.files}</td><td class="num">${l.matches}</td><td class="muted small mono">${esc(l.rules.join(", "))}</td></tr>`).join("");
  const tools = inv.recommended_tools.map((t) => `<tr><td><code>${esc(t.command)}</code></td><td>${esc(t.purpose)}</td>
<td>${t.installed ? "Installed" : `<span class="muted">Not installed</span>`}</td><td class="muted">${t.needs_network ? "Needs network" : "Offline"}</td></tr>`).join("");
  let sectionNo = 0;
  const no = () => ++sectionNo;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security review · ${esc(v.project)}</title>
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
.meta dt{color:var(--muted)}.meta dd{margin:0;color:var(--ink);overflow-wrap:anywhere}
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

.issue{border-top:1px solid var(--rule2);padding:18px 0 6px}
.issue header{display:flex;align-items:baseline;gap:12px}
.issue header h3{margin:0;font-size:15px;flex:1}
.issue h4{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:14px 0 4px}
.issue p{margin:0 0 4px}
.issue .facts{color:var(--muted);font-size:12.5px;margin:4px 0 0}
.issue .refs{color:var(--muted);font-size:12px;margin-top:12px}
ul.locs{list-style:none;margin:0;padding:0}ul.locs li{margin:0 0 8px}
ul.locs pre{margin-top:3px}
.more summary{margin:2px 0 8px}
.summary-text p{margin:0 0 10px;color:var(--ink)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.ref a{color:inherit}
@media print{.more>summary{display:none}.more>*{display:block}.issue{break-inside:auto}.issue header{break-after:avoid}}
</style></head>
<body><div class="page">

<header class="doc-head">
<p class="kicker">Source code security review</p>
<h1>${esc(v.project)}</h1>
<dl class="meta">
<dt>Target</dt><dd class="mono">${esc(result.root)}</dd>
<dt>Date</dt><dd>${esc(date)}</dd>
<dt>Scope</dt><dd>${own} files of application code${inv.third_party_files ? `, ${inv.third_party_files} files in bundled libraries` : ""}; dependencies ${esc(depsLine(result.dependencies))}</dd>
<dt>Method</dt><dd>Static source review: pattern rules plus code-flow analysis for JavaScript/TypeScript. Read-only; no code was run.</dd>
<dt>Tool</dt><dd>saas-security-audit v${esc(VERSION)} (rules ${esc(RULES_VERSION)})</dd>
</dl>
</header>

<section>
<h2><span>${no()}</span>Summary</h2>
<div class="summary">
<div class="summary-text">
<div class="rating ${v.posture.level}"><div class="label">Overall risk</div><div class="value">${RATING[v.posture.level]}</div></div>
${v.summary.map((p) => `<p>${esc(p)}</p>`).join("")}
</div>
<div><table class="severity"><thead><tr><th>Severity</th><th class="num">Issues</th><th class="num">Locations</th></tr></thead><tbody>${sevRows}</tbody></table>
${v.stack.length ? `<p class="note small">Stack: ${v.stack.map(esc).join(", ")}</p>` : ""}</div>
</div>
${v.issues.length ? `<h3>Key findings</h3><table><thead><tr><th>Ref.</th><th>Issue</th><th>Severity</th><th class="num">Locations</th></tr></thead><tbody>${keyRows}</tbody></table>` : ""}
</section>

<section class="findings-section">
<h2><span>${no()}</span>Findings</h2>
${filters ? `<div class="toolbar">${filters}<input class="search" type="search" placeholder="Filter by issue, rule or file" aria-label="Filter findings"></div>` : ""}
<div id="issues">${v.issues.length ? v.issues.map(issueCard).join("\n") : `<p class="note">No issues found in the application's own code.</p>`}</div>
${v.hidden.length ? `<p class="note">${v.hidden.length} further match${v.hidden.length === 1 ? "" : "es"} in test files and gitignored local env files ${v.hidden.length === 1 ? "is" : "are"} not included (<code>--include-tests</code> adds them).</p>` : ""}
</section>

${v.libraries.length ? `<section><h2><span>${no()}</span>Bundled third-party code</h2>
<p class="lede">${v.thirdParty.length} matches are inside libraries copied into the repository. They are not counted as findings: the code belongs to the library, and the fix is to keep the library on a supported, patched release (or install it through a package manager) rather than edit it.</p>
<table><thead><tr><th>Library path</th><th class="num">Files</th><th class="num">Matches</th><th>Rules</th></tr></thead><tbody>${libraries}</tbody></table></section>` : ""}

<section><h2><span>${no()}</span>Control coverage</h2>
<p class="lede">A control passes only when its enforcement is found in code and covered by a test. A scan cannot show that, so no control is marked as passed.</p>
<table><thead><tr><th>Ref.</th><th>Control</th><th>Result</th><th>Findings</th></tr></thead><tbody>${coverage}</tbody></table>
</section>

<section><h2><span>${no()}</span>Common implementation mistakes</h2>
<p class="lede">Twelve mistakes that turn up most often in quickly built SaaS apps. "Not found" means no pattern matched.</p>
<table><thead><tr><th>Ref.</th><th>Check</th><th>Result</th></tr></thead><tbody>${checklist}</tbody></table>
</section>

<section><h2><span>${no()}</span>Standards</h2>
<p class="lede">${esc(result.standards.note)}</p>
${standards || `<p class="note">No findings to map.</p>`}
${fws ? `<h3>Compliance frameworks (related requirements)</h3><table><tbody>${fws}</tbody></table>` : ""}
</section>

<section><h2><span>${no()}</span>Scope and limitations</h2>
<p>This is an automated static review. Each finding marks code that matches a known weak pattern; a reviewer should confirm it before it is treated as a vulnerability, using the "How to verify" step. ${esc(R.verify_note)}</p>
<ul class="notes">${result.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
<dl class="facts"><dt>Dependency manifests</dt><dd>${inv.manifests.map(esc).join(", ") || "None found"}</dd><dt>Test files</dt><dd>${inv.test_files}</dd><dt>CI files</dt><dd>${inv.ci_files.map(esc).join(", ") || "None found"}</dd></dl>
<h3>Further checks worth running</h3>
<table><thead><tr><th>Command</th><th>Purpose</th><th>Status</th><th>Network</th></tr></thead><tbody>${tools}</tbody></table>
</section>

<footer class="confidential"><span>Confidential · saas-security-audit v${esc(VERSION)} · secret values redacted</span><span>${esc(date)}</span></footer>
</div>
<script>
(function(){var box=document.getElementById("issues");if(!box)return;var cards=[].slice.call(box.querySelectorAll(".issue")),f="all",q="";
function apply(){cards.forEach(function(r){var ok=(f==="all"||r.dataset.sev===f)&&(!q||r.dataset.q.indexOf(q)>-1);r.classList.toggle("hidden",!ok);});}
[].forEach.call(document.querySelectorAll(".filter"),function(b){b.addEventListener("click",function(){[].forEach.call(document.querySelectorAll(".filter"),function(x){x.classList.remove("on")});b.classList.add("on");f=b.dataset.f;apply();});});
var s=document.querySelector(".search");if(s)s.addEventListener("input",function(){q=s.value.trim().toLowerCase();apply();});
window.addEventListener("beforeprint",function(){[].forEach.call(document.querySelectorAll("details"),function(d){d.open=true});});})();
</script>
</body></html>
`;
}
