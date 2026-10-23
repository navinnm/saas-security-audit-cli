// Redesigned terminal UI: CI text, GitHub annotations, verdicts, fix plan, file roles, show, prompts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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
    for (const s of ["OVERALL", "Scan complete", "WHERE THE", "SEVERITY SHAPE", "BY AREA", "CONTROL COVERAGE · 22", "FINDINGS", "FIX ORDER", "NEXT"]) {
      assert.ok(r.stdout.includes(s), `missing ${s}`);
    }
    assert.ok(!r.stdout.includes("Start the scan now?"), "no welcome prompt without a TTY");
    assert.ok(!/\x1b\[/.test(r.stdout));
  });
});
