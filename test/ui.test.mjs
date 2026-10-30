// Redesigned terminal UI: CI text, GitHub annotations, verdicts, fix plan, file roles, show, prompts.
// Tests never reach the network: the dependency check (deps.ts) is tested with a fake fetch in deps.test.mjs.
process.env.SAAS_AUDIT_OFFLINE = "1";
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURES } from "./fixtures.mjs";
import { newState, scan } from "../dist/engine.js";
import { buildResult } from "../dist/report.js";
import { fixPlan, pathRole, verdict, whereWorst } from "../dist/view.js";
import { ciText, githubAnnotations, showRule } from "../dist/ui/screens.js";
import { collapsed } from "../dist/ui/prompt.js";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "../dist/cli.js");
// eslint-disable-next-line no-control-regex
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

async function withResult(files, fn) {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-ui-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    const state = newState();
    const findings = await scan(root, state);
    return await fn(buildResult(root, findings, state), root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("CI text format (screen 6)", async () => {
  await withResult(FIXTURES.vulnerableSaas, (result) => {
    const t = ciText(result, { version: "9.9.9", project: "acme", elapsed: 1.23, filesWalked: 10, failOn: "high", gateTripped: true, report: "r.md" });
    const lines = t.split("\n");
    assert.match(lines[0], /^saas-audit  9\.9\.9 · acme · offline · read-only$/);
    assert.match(t, /^result {6}FAIL  gate=high$/m);
    assert.match(t, /^counts {6}crit=\d+ high=\d+ med=\d+ low=\d+ info=\d+$/m);
    assert.match(t, /^controls {4}leads=\d+ no_signal=\d+ not_verified=\d+ passed=0$/m);
    assert.match(t, /BLOCKING · CRITICAL AND HIGH, BY RULE\nhigh {2}SEC0\d\d/);
    assert.match(t, /^exit {8}1$/m);
    assert.ok(!/\x1b\[/.test(t), "no colour codes in CI text");
    assert.match(ciText(result, { version: "1", project: "p", elapsed: 0, filesWalked: 1, failOn: "none", gateTripped: false, report: null }), /^result {6}DONE  gate=none$/m);
  });
});

test("GitHub annotations: levels and escaping", async () => {
  await withResult({ "src/a,b:c.js": "el.innerHTML = x\n", "api.py": "eval(x)\n" }, (result) => {
    const out = githubAnnotations(result).trim().split("\n");
    assert.ok(out.some((l) => l.startsWith("::error file=api.py,line=1,") && l.includes("SEC002")));
    const warn = out.find((l) => l.startsWith("::warning"));
    assert.ok(warn.includes("file=src/a%2Cb%3Ac.js"), "commas and colons in properties are escaped");
  });
});

test("verdicts", () => {
  assert.equal(verdict({ Critical: 1, High: 2 }, "high", true).kind, "blocked");
  assert.equal(verdict({ Critical: 1, High: 2 }, "high", true).exit, 1);
  assert.equal(verdict({ High: 2 }, "none", false).kind, "risk");
  assert.equal(verdict({ Medium: 3 }, "high", false).kind, "passed");
  assert.equal(verdict({ Medium: 3 }, "none", false).kind, "review");
  assert.equal(verdict({}, "none", false).kind, "clean");
  assert.match(verdict({ Critical: 12, High: 90 }, "high", true).detail, /^12 critical and 90 high-severity leads in source code\./);
});

test("file roles and where-the-worst grouping", () => {
  const f = (file, context = "source", severity = "Critical") => ({ id: "SEC012", file, line: 1, context, severity, controls: [15], title: "t", guidance: "g" });
  assert.equal(pathRole(f("frontend/.next-e2e/dev/chunks/a.js")), "build");
  assert.equal(pathRole(f("dist/app.js")), "build");
  assert.equal(pathRole(f(".claude/skills/x/SKILL.md")), "docs");
  assert.equal(pathRole(f("app/Models/Key.php")), "source");
  assert.equal(pathRole(f("tests/a.py", "test")), "test");
  const w = whereWorst([f("src/vault/a.ts"), f("src/vault/b.ts"), f(".next-e2e/chunks/x.js")]);
  assert.equal(w.severity, "Critical");
  assert.deepEqual(w.groups.map((g) => [g.dir, g.count, g.role]), [["src/vault/", 2, "source"], [".next-e2e/chunks/", 1, "build"]]);
  assert.match(w.groups[0].label, /rotate the keys now/);
});

test("fix plan: criticals first, webhook merge, build-copy note", () => {
  const mk = (id, severity, file, extra = {}) => ({ id, severity, file, line: 1, context: "source", controls: [15], title: id, guidance: `fix ${id}.`, ...extra });
  const plan = fixPlan([
    mk("SEC031", "High", "app/hooks/stripe.ts"), mk("SEC034", "Low", "app/hooks/stripe.ts"),
    mk("SEC012", "Critical", "src/vault/key.ts"), mk("SEC012", "Critical", "dist/chunks/key.js"),
    mk("SEC032", "High", ".env.optimized"), mk("SEC006", "Low", "a.ts"),
  ]);
  assert.equal(plan[0].severity, "Critical");
  assert.match(plan[0].title, /^Rotate the exposed secrets in key\.ts$/);
  assert.match(plan[0].detail, /Rebuild so the 1 copy in dist\/chunks\/ disappear/);
  assert.deepEqual(plan[0].tags, ["SEC012 ×2", "2 crit"]);
  assert.equal(plan[0].when, "do today");
  const hook = plan.find((a) => a.tags[0] === "SEC031");
  assert.equal(hook.title, "Verify webhook signatures and make handlers idempotent");
  assert.deepEqual(hook.tags, ["SEC031", "SEC034"]);
  assert.equal(plan.find((a) => a.tags[0] === "SEC032").command, "git log --all -- .env.optimized");
  assert.ok(!plan.some((a) => a.tags[0] === "SEC006"), "low-severity rules are not fix actions");
});

test("show <rule> lists every location with evidence", async () => {
  await withResult(FIXTURES.injection, (result, root) => {
    const lines = plain(showRule("sec003", result.findings, 120).join("\n"));
    assert.match(lines, /SEC003 +SQL built with string interpolation/);
    assert.match(lines, /injection|a\.py:2/);
    assert.match(lines, /→ Use bound parameters/);
    assert.match(plain(showRule("SEC999", result.findings, 120).join("\n")), /No findings for SEC999/);
    const cli = spawnSync("node", [CLI, "show", "SEC003", root], { encoding: "utf8" });
    assert.equal(cli.status, 0);
    assert.match(cli.stdout, /SEC003/);
    assert.equal(spawnSync("node", [CLI, "show"], { encoding: "utf8" }).status, 2, "show needs a rule");
  });
});

test("collapsed prompt lines", () => {
  assert.equal(plain(collapsed("Start the scan now?", "Yes")), "✓ Start the scan now? Yes");
  assert.equal(plain(collapsed("Open report.md now?", null, "--yes")), "– Open report.md now? skipped · --yes");
});

test("pretty format without a TTY: all screens, no prompts, no colour", async () => {
  await withResult(FIXTURES.vulnerableSaas, (_r, root) => {
    const r = spawnSync("node", [CLI, root, "--format", "pretty", "--no-update-check"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
    assert.equal(r.status, 0, r.stderr);
    for (const s of ["OVERALL", "Scan complete", "WHERE THE", "SEVERITY SHAPE", "BY AREA", "CONTROL COVERAGE", "FINDINGS", "FIX ORDER", "NEXT"]) {
      assert.ok(r.stdout.includes(s), `missing ${s}`);
    }
    assert.ok(!r.stdout.includes("Start the scan now?"), "no welcome prompt without a TTY");
    assert.ok(!/\x1b\[/.test(r.stdout));
  });
});

test("repository profile: languages, folder roles, skipped dirs", async () => {
  const { profile, folderRole, languageOf } = await import("../dist/profile.js");
  const { preflight } = await import("../dist/engine.js");
  const root = mkdtempSync(join(tmpdir(), "saas-audit-profile-"));
  try {
    const files = { "app/a.ts": "", "app/b.tsx": "", "app/c.php": "", "resources/views/x.blade.php": "", "tests/t.py": "",
      "docs/readme.md": "", "README.md": "", "node_modules/x/index.js": "", "Dockerfile": "", "LICENSE": "" };
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    const p = profile(root, preflight(root).files);
    assert.deepEqual(p.languages.slice(0, 2), [
      { name: "Markdown", files: 2, share: 2 / 8 }, { name: "TypeScript", files: 2, share: 2 / 8 },
    ], "ties sort by name; shares are of files with a known language");
    assert.ok(p.languages.some((l) => l.name === "Blade"));
    assert.equal(p.otherFiles, 1, "LICENSE has no language");
    assert.deepEqual(p.folders.map((f) => [f.name, f.files, f.role]), [["app", 3, "source"], ["docs", 1, "docs"], ["resources", 1, "source"], ["tests", 1, "tests"]]);
    assert.equal(p.rootFiles, 3);
    assert.deepEqual(p.skippedDirs, ["node_modules"]);
    assert.equal(folderRole(".next-e2e"), "build output");
    assert.equal(languageOf("Dockerfile"), "Docker");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("standards and vibe review in terminal, CI text, HTML and PDF", async () => {
  const { renderHtml } = await import("../dist/html.js");
  const { renderPdf } = await import("../dist/pdf.js");
  await withResult({ ...FIXTURES.vulnerableSaas, ...FIXTURES.vibeCoded }, (result, root) => {
    assert.equal(result.standards.owasp_top10_2021.length, 10);
    assert.ok(result.findings.every((f) => f.standards && "cwe" in f.standards));
    assert.equal(result.vibe_review.length, 12);
    assert.equal(result.vibe_review.find((v) => v.id === "V3").status, "found", "client-side admin check found");
    const ci = ciText(result, { version: "1", project: "p", elapsed: 0, filesWalked: 1, failOn: "none", gateTripped: false, report: null });
    assert.match(ci, /^owasp {7}A01=\d+/m);
    assert.match(ci, /^vibe {8}\d+\/12 found: V1/m);
    const pretty = spawnSync("node", [CLI, root, "--format", "pretty", "--no-update-check"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }).stdout;
    for (const s of ["VIBE-CODE REVIEW", "STANDARDS", "API Top 10", "LLM Top 10", "ATT&CK", "Frameworks", "OWASP A03:2021 · CWE-89"]) assert.ok(pretty.includes(s), `missing ${s}`);
    const html = renderHtml(result);
    for (const s of ["Vibe-code review", "OWASP Top 10 (2021)", "OWASP API Security Top 10 (2023)", "Compliance frameworks", "does not demonstrate compliance"]) {
      assert.ok(html.includes(s), `html missing ${s}`);
    }
    const pdf = renderPdf(result).toString("latin1");
    assert.ok(pdf.startsWith("%PDF-") && pdf.trimEnd().endsWith("%%EOF"));
  });
});

test("MITRE ATT&CK, ATLAS, D3FEND and NIST CSF mappings, and the Navigator layer", async () => {
  const { renderHtml } = await import("../dist/html.js");
  const { markdown } = await import("../dist/report.js");
  const { R } = await import("../dist/rules.js");
  // Every rule's IDs resolve to a name, so no report shows a bare, unknown ID.
  for (const [rid, s] of Object.entries(R.standards)) {
    for (const t of s.attack) assert.match(t, /^T\d{4}(\.\d{3})?$/, rid), assert.ok(R.attack_techniques[t], `${rid}: ${t} unnamed`);
    for (const t of s.atlas) assert.match(t, /^AML\.T\d{4}(\.\d{3})?$/, rid), assert.ok(R.atlas_techniques[t], `${rid}: ${t} unnamed`);
    for (const t of s.d3fend) assert.match(t, /^D3-[A-Z]+$/, rid), assert.ok(R.d3fend_techniques[t], `${rid}: ${t} unnamed`);
  }
  await withResult({ ...FIXTURES.vulnerableSaas, ...FIXTURES.vibeCoded }, (result, root) => {
    const sqli = result.findings.find((f) => f.id === "SEC003");
    assert.deepEqual(sqli.standards.attack, ["T1190"]);
    assert.ok(sqli.standards.d3fend.includes("D3-DQSA"));
    const t1190 = result.standards.mitre_attack.find((t) => t.id === "T1190");
    assert.ok(t1190.leads > 0 && t1190.found.includes("SEC003"));
    assert.equal(result.standards.mitre_attack[0].leads >= result.standards.mitre_attack.at(-1).leads, true, "leads first");
    assert.ok(result.standards.frameworks.some((f) => f.id === "nist_csf" && f.requirements.length));
    const md = markdown(result);
    for (const s of ["### MITRE ATT&CK (v", "### MITRE ATLAS (", "### MITRE D3FEND (", "**NIST CSF 2.0:**", "· T1190"]) assert.ok(md.includes(s), `md missing ${s}`);
    const html = renderHtml(result);
    for (const s of ["MITRE ATT&amp;CK (v", "ATT&amp;CK T1190", "D3FEND D3-"]) assert.ok(html.includes(s), `html missing ${s}`);

    const out = join(root, "out", "layer.json");
    const run = spawnSync("node", [CLI, root, "--format", "text", "--no-update-check", "--attack-layer", out], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const layer = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(layer.domain, "enterprise-attack");
    assert.equal(layer.versions.layer, "4.5");
    assert.equal(layer.techniques.length, result.standards.mitre_attack.length);
    const hit = layer.techniques.find((t) => t.techniqueID === "T1190");
    assert.ok(hit.score > 0 && /from .*SEC003/.test(hit.comment) && !hit.color);
    const miss = layer.techniques.find((t) => t.score === 0);
    assert.ok(miss && miss.color && /no leads/.test(miss.comment));
  });
});

test("every rule has a manual verify step, shown in Markdown, HTML, PDF plan and show <rule>", async () => {
  const { renderHtml } = await import("../dist/html.js");
  const { markdown } = await import("../dist/report.js");
  const { R } = await import("../dist/rules.js");
  for (const rid of Object.keys(R.standards)) assert.ok(R.verify[rid]?.length > 40, `${rid} has no verify step`);
  await withResult({ ...FIXTURES.vulnerableSaas, ...FIXTURES.vibeCoded }, (result) => {
    assert.ok(result.findings.every((f) => f.verify === R.verify[f.id]));
    const md = markdown(result);
    assert.ok(md.includes(`Verify: ${R.verify.SEC003}`));
    assert.ok(md.includes(R.verify_note));
    const html = renderHtml(result);
    assert.ok(html.includes('<div class="verify"><b>Verify:</b>'));
    const show = plain(showRule("SEC003", result.findings, 100).join("\n"));
    assert.match(show, /✓ Verify: On staging, put a single quote/);
  });
});
