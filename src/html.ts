/**
 * Self-contained HTML report: no external fonts, scripts, or images, so it opens offline and
 * never makes a network request. Designed for screen and for print (A4).
 */
import type { Finding } from "./engine.js";
import type { Result } from "./report.js";
import { CLI_VERSION as VERSION } from "./version.js";
import { buildView, controlLabel, formatDate, SEVERITY_ORDER, type CoverageRow, type View } from "./view.js";

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
const SEV_KEY: Record<string, string> = { Critical: "crit", High: "high", Medium: "med", Low: "low", Informational: "info" };
const SEV_LABEL: Record<string, string> = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low", Informational: "Info" };

const LOGO = `<svg class="logo" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="lg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#22d3ee"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs>
<path d="M32 4 C24 7 16 7 9 6 V30 C9 45 19 54 32 60 C45 54 55 45 55 30 V6 C48 7 40 7 32 4Z" fill="#0d1628" stroke="url(#lg)" stroke-width="4"/>
<rect x="19" y="18" width="11" height="11" rx="2.5" fill="#2b5a80"/><rect x="34" y="18" width="11" height="11" rx="2.5" fill="#2b5a80"/>
<rect x="19" y="33" width="11" height="11" rx="2.5" fill="#2b5a80"/><rect x="34" y="33" width="11" height="11" rx="2.5" fill="#fbb024"/>
<rect x="12" y="37.5" width="40" height="2" rx="1" fill="#7decff"/></svg>`;

function findingRow(f: Finding, withEvidence: boolean): string {
  const k = SEV_KEY[f.severity];
  const ctx = f.context === "source" ? "" : ` <span class="ctx">${esc(f.context)}</span>`;
  const search = esc(`${f.id} ${f.title} ${f.file} ${controlLabel(f.controls[0])}`.toLowerCase());
  const detail = withEvidence
    ? `<details><summary>Evidence &amp; fix</summary><pre>${esc(f.evidence)}</pre><p class="fix"><b>Fix.</b> ${esc(f.guidance)}</p>
       <p class="meta">Confidence: ${esc(f.confidence)} · Controls: ${f.controls.map((c) => esc(controlLabel(c))).join(", ")}</p></details>`
    : "";
  return `<tr class="f" data-sev="${k}" data-q="${search}"><td><span class="pill ${k}">${SEV_LABEL[f.severity]}</span></td>
<td class="mono dim">${esc(f.id)}</td><td class="dim">${esc(controlLabel(f.controls[0]))}</td>
<td class="mono loc">${esc(f.file)}:${f.line}${ctx}</td><td><div class="issue">${esc(f.title)}</div>${detail}</td></tr>`;
}

function findingsTable(findings: Finding[], withEvidence: boolean, id: string): string {
  if (!findings.length) return `<p class="empty">No leads here. That isn't proof of security — verify the controls below.</p>`;
  return `<table class="findings" id="${id}"><thead><tr><th>Severity</th><th>Rule</th><th>Control</th><th>Location</th><th>Issue</th></tr></thead>
<tbody>${findings.map((f) => findingRow(f, withEvidence)).join("\n")}</tbody></table>`;
}

function coverageRow(r: CoverageRow, status: "leads" | "none" | "unverified"): string {
  const chip = { leads: `<span class="chip warn">Leads to verify</span>`, none: `<span class="chip">No signals found</span>`,
    unverified: `<span class="chip">Not verified</span>` }[status];
  const sig = r.signals ? `${r.signals.source_count} / ${r.signals.test_count}` : "—";
  const look = r.id === 17 ? "Independent AI review (Claude Code plugin)" : r.id === 15 ? "Dependency &amp; secret tools"
    : r.signals?.locations.length ? r.signals.locations.slice(0, 3).map((l) => `<code>${esc(l)}</code>`).join(" ") : `<span class="dim">—</span>`;
  return `<tr><td class="mono dim">C${r.id}</td><td>${esc(r.name)}</td><td>${chip}</td><td class="num">${r.leads || "–"}</td><td class="num dim">${sig}</td><td class="look">${look}</td></tr>`;
}

function severityBar(v: View): string {
  const total = SEVERITY_ORDER.reduce((a, s) => a + (v.sourceCounts[s] ?? 0), 0);
  if (!total) return `<div class="bar empty-bar"><span style="width:100%"></span></div>`;
  return `<div class="bar">${SEVERITY_ORDER.filter((s) => v.sourceCounts[s]).map((s) =>
    `<span class="${SEV_KEY[s]}" style="width:${(100 * v.sourceCounts[s]) / total}%" title="${s}: ${v.sourceCounts[s]}"></span>`).join("")}</div>`;
}

export function renderHtml(result: Result, opts: { includeTests?: boolean; now?: Date } = {}): string {
  const v = buildView(result, Boolean(opts.includeTests), opts.now);
  const s = result.stats;
  const inv = result.inventory;
  const cards = SEVERITY_ORDER.map((sev) => `<div class="card ${SEV_KEY[sev]}${v.sourceCounts[sev] ? "" : " zero"}">
<div class="n">${v.sourceCounts[sev] ?? 0}</div><div class="l">${SEV_LABEL[sev]}</div></div>`).join("");
  const chips = [`<button class="chip-btn on" data-f="all">All <b>${v.shown.length}</b></button>`,
    ...SEVERITY_ORDER.map((sev) => {
      const n = v.shown.filter((f) => f.severity === sev).length;
      return n ? `<button class="chip-btn" data-f="${SEV_KEY[sev]}">${SEV_LABEL[sev]} <b>${n}</b></button>` : "";
    })].join("");
  const coverage = ([
    ...v.coverage.leads.map((r) => [r, "leads"] as const),
    ...v.coverage.noSignals.map((r) => [r, "none"] as const),
    ...v.coverage.notVerified.map((r) => [r, "unverified"] as const),
  ]).sort((x, y) => x[0].id - y[0].id).map(([r, st]) => coverageRow(r, st)).join("\n");
  const fixes = v.guidance.map((g) => `<li><span class="mono dim">${esc(g.id)}</span> <b>${esc(g.title)}</b>${g.count > 1 ? ` <span class="dim">×${g.count}</span>` : ""}<p>${esc(g.guidance)}</p></li>`).join("");
  const tools = inv.recommended_tools.map((t) => `<tr><td><code>${esc(t.command)}</code></td><td>${esc(t.purpose)}</td>
<td>${t.installed ? `<span class="chip ok">Installed</span>` : `<span class="chip">Not installed</span>`}</td><td class="dim">${t.needs_network ? "Needs network" : "Offline"}</td></tr>`).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Audit · ${esc(v.project)}</title>
<style>
:root{--bg:#f6f7fb;--panel:#fff;--ink:#0f172a;--dim:#64748b;--line:#e2e8f0;--soft:#f1f5f9;
--crit:#dc2626;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--info:#64748b;--brand1:#22d3ee;--brand2:#8b5cf6;--ok:#16a34a}
@media (prefers-color-scheme:dark){:root{--bg:#0b1020;--panel:#111a2e;--ink:#e2e8f0;--dim:#94a3b8;--line:#1f2a44;--soft:#0f1729}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif}
.mono,code,pre{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
code{font-size:12px;background:var(--soft);padding:1px 5px;border-radius:5px;word-break:break-all}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
.hero{background:#0b1020;color:#e2e8f0;padding:32px 0 28px;border-bottom:3px solid transparent;border-image:linear-gradient(90deg,var(--brand1),var(--brand2)) 1}
.hero .wrap{display:flex;gap:20px;align-items:center}
.logo{width:56px;height:56px;flex:none}
.hero h1{margin:0;font-size:26px;letter-spacing:-.02em}
.hero h1 span{background:linear-gradient(90deg,var(--brand1),var(--brand2));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero .meta{color:#94a3b8;font-size:13px;margin-top:4px}
.hero .meta b{color:#e2e8f0;font-weight:600}
main.wrap{padding-top:28px;padding-bottom:48px}
section{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-bottom:18px}
h2{font-size:16px;margin:0 0 14px;letter-spacing:-.01em}
h2 small{color:var(--dim);font-weight:500;margin-left:6px}
.posture{border-left:5px solid var(--ok)}
.posture.critical{border-left-color:var(--crit)}.posture.high{border-left-color:var(--high)}.posture.medium{border-left-color:var(--med)}
.posture h2{font-size:20px;margin-bottom:6px}.posture p{margin:0;color:var(--dim)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-top:18px}
.card{border-radius:12px;padding:14px 16px;border:1px solid var(--line);background:var(--soft);position:relative;overflow:hidden}
.card:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--c)}
.card .n{font-size:30px;font-weight:750;letter-spacing:-.03em;color:var(--c)}.card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card.zero .n{color:var(--dim);opacity:.6}
.crit{--c:var(--crit)}.high{--c:var(--high)}.med{--c:var(--med)}.low{--c:var(--low)}.info{--c:var(--info)}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--soft);margin-top:18px}
.bar span{display:block;background:var(--c)}.empty-bar span{background:var(--ok);opacity:.5}
.facts{display:flex;flex-wrap:wrap;gap:8px 22px;margin-top:14px;color:var(--dim);font-size:13px}.facts b{color:var(--ink)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.chip-btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:99px;padding:5px 12px;font:inherit;font-size:12.5px;cursor:pointer}
.chip-btn b{color:var(--dim);font-weight:600;margin-left:3px}.chip-btn.on{background:var(--ink);color:var(--panel);border-color:var(--ink)}.chip-btn.on b{color:inherit}
.search{margin-left:auto;border:1px solid var(--line);border-radius:9px;padding:6px 10px;font:inherit;font-size:13px;min-width:220px;background:var(--panel);color:var(--ink)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
.findings td:nth-child(1){width:86px}.findings td:nth-child(2){width:70px}.findings td:nth-child(3){width:190px}
.loc{word-break:break-all;max-width:280px}
.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;padding:2px 8px;border-radius:99px;color:#fff;background:var(--c)}
.pill.med{color:#1f1300}.dim{color:var(--dim)}.num{text-align:right;font-variant-numeric:tabular-nums}
.issue{font-weight:550}
.ctx{font-family:inherit;font-size:11px;color:var(--dim);background:var(--soft);border-radius:5px;padding:0 5px;margin-left:4px}
details summary{cursor:pointer;color:var(--dim);font-size:12px;margin-top:3px;list-style:none}
details summary::-webkit-details-marker{display:none}details summary:before{content:"▸ "}details[open] summary:before{content:"▾ "}
pre{background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:8px 0}
.fix{margin:6px 0 2px}.meta{margin:0;color:var(--dim);font-size:12px}
.chip{display:inline-block;font-size:11.5px;padding:2px 9px;border-radius:99px;background:var(--soft);color:var(--dim);border:1px solid var(--line);white-space:nowrap}
.chip.warn{background:#fef3c7;color:#92400e;border-color:#fde68a}.chip.ok{background:#dcfce7;color:#166534;border-color:#bbf7d0}
@media (prefers-color-scheme:dark){.chip.warn{background:#3b2a07;color:#fcd34d;border-color:#5b420e}.chip.ok{background:#0b3320;color:#86efac;border-color:#14532d}}
.fixes{list-style:none;margin:0;padding:0;display:grid;gap:12px}.fixes p{margin:3px 0 0;color:var(--dim)}
.tests>summary{font-size:16px;font-weight:650;color:var(--ink);margin:0}
.tests>summary .dim{font-weight:500;font-size:14px}
.tests[open]>summary{margin-bottom:12px}
.look code{margin-right:4px}
.empty{color:var(--dim);margin:0}
.notes{color:var(--dim);margin:0;padding-left:18px}
footer{color:var(--dim);font-size:12px;text-align:center;padding:0 0 40px}
.hidden{display:none}
@media (max-width:760px){.cards{grid-template-columns:repeat(3,1fr)}.findings td:nth-child(3),.findings th:nth-child(3){display:none}.search{min-width:0;width:100%}}
@media print{
 @page{size:A4;margin:14mm}
 body{background:#fff;color:#0f172a;font-size:11.5px}
 .hero{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 section{break-inside:avoid-page;border-color:#e2e8f0}section.findings-section,section.coverage{break-inside:auto}
 tr{break-inside:avoid}.toolbar{display:none}details>summary{display:none}details{display:block}
 details:not([open])>*:not(summary){display:block}.wrap{max-width:none;padding:0}
 .card,.pill,.bar span,.chip{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style></head>
<body>
<header class="hero"><div class="wrap">${LOGO}<div>
<h1><span>SaaS Security Audit</span> Report</h1>
<div class="meta"><b>${esc(v.project)}</b> · ${esc(result.root)}<br>${esc(formatDate(v.generatedAt))} · saas-security-audit v${esc(VERSION)} · offline static analysis</div>
</div></div></header>
<main class="wrap">

<section class="posture ${v.posture.level}">
<h2>${esc(v.posture.headline)}</h2><p>${esc(v.posture.detail)}</p>
<div class="cards">${cards}</div>
${severityBar(v)}
<div class="facts"><span><b>${s.files_scanned}</b> files analysed</span><span><b>${v.controlsWithLeads}</b>/22 controls with leads</span>
${v.hidden.length ? `<span><b>${v.hidden.length}</b> leads in test / local env files</span>` : ""}${s.suppressed ? `<span><b>${s.suppressed}</b> suppressed inline</span>` : ""}
${v.stack.length ? `<span>Stack: <b>${v.stack.map(esc).join(" · ")}</b></span>` : ""}</div>
</section>

<section class="findings-section">
<h2>Findings in source code <small>${v.shown.length}</small></h2>
${v.shown.length ? `<div class="toolbar">${chips}<input class="search" type="search" placeholder="Search rule, file, issue…" aria-label="Search findings"></div>` : ""}
${findingsTable(v.shown, true, "main-findings")}
</section>

${v.guidance.length ? `<section><h2>How to fix <small>${v.guidance.length} rules</small></h2><ul class="fixes">${fixes}</ul></section>` : ""}

${v.hidden.length ? `<section><details class="tests"><summary>Test files &amp; local env files <span class="dim">${v.hidden.length} leads — usually intentional samples</span></summary>
${findingsTable(v.hidden, true, "test-findings")}</details></section>` : ""}

<section class="coverage"><h2>Control coverage <small>22 controls</small></h2>
<table><thead><tr><th></th><th>Control</th><th>Status</th><th class="num">Leads</th><th class="num">Signals src / test</th><th>Look first</th></tr></thead>
<tbody>${coverage}</tbody></table>
<p class="empty" style="margin-top:10px">PASS is never automatic: a control passes only when enforcement is located in code and proven by a negative test.</p>
</section>

<section><h2>Inventory &amp; recommended tools</h2>
<div class="facts" style="margin:0 0 12px"><span>Manifests: <b>${inv.manifests.map(esc).join(", ") || "none found"}</b></span><span>Test files: <b>${inv.test_files}</b></span><span>CI files: <b>${inv.ci_files.map(esc).join(", ") || "none found"}</b></span></div>
<table><thead><tr><th>Command</th><th>Purpose</th><th>Status</th><th>Network</th></tr></thead><tbody>${tools}</tbody></table>
</section>

<section><h2>Method &amp; limitations</h2><ul class="notes">
<li>Read-only static analysis on the local machine. No code was executed and nothing was sent anywhere.</li>
${result.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}
<li>Every finding is a lead to validate in code, not a confirmed vulnerability. For verification, fixes, and regression tests, run <code>/saas-security-audit:audit</code> in Claude Code.</li>
</ul></section>
</main>
<footer>Generated by saas-security-audit v${esc(VERSION)} · Secret values are redacted · ${esc(formatDate(v.generatedAt))}</footer>
<script>
(function(){var t=document.getElementById("main-findings");if(!t)return;var rows=[].slice.call(t.querySelectorAll("tr.f")),f="all",q="";
function apply(){rows.forEach(function(r){var ok=(f==="all"||r.dataset.sev===f)&&(!q||r.dataset.q.indexOf(q)>-1);r.classList.toggle("hidden",!ok);});}
[].forEach.call(document.querySelectorAll(".chip-btn"),function(b){b.addEventListener("click",function(){[].forEach.call(document.querySelectorAll(".chip-btn"),function(x){x.classList.remove("on")});b.classList.add("on");f=b.dataset.f;apply();});});
var s=document.querySelector(".search");if(s)s.addEventListener("input",function(){q=s.value.trim().toLowerCase();apply();});
window.addEventListener("beforeprint",function(){[].forEach.call(document.querySelectorAll("details"),function(d){d.open=true});});})();
</script>
</body></html>
`;
}
