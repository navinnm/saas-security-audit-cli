// Parity with the Claude Code plugin's Python scanner (scripts/scan.py 0.4.0). Since rules 0.5.0 the CLI
// is its own source of truth and goes further (fewer false positives, code-flow analysis), so this only
// runs on request: SAAS_AUDIT_PARITY=1 npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXTURES } from "./fixtures.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(here, "../dist/cli.js");
const PLUGIN = process.env.SAAS_AUDIT_PLUGIN ?? resolve(here, "../../saas-security-audit/scripts/scan.py");
const havePython = spawnSync("python3", ["--version"]).status === 0;
const skip = process.env.SAAS_AUDIT_PARITY !== "1" ? "CLI ahead of the plugin; set SAAS_AUDIT_PARITY=1 to compare"
  : !havePython || !existsSync(PLUGIN) ? "python3 or plugin scan.py not available" : false;

function py(root, ...args) {
  const r = spawnSync("python3", ["-I", PLUGIN, "--root", root, ...args], { encoding: "utf8" });
  return { out: r.stdout, code: r.status };
}
function js(root, ...args) {
  const r = spawnSync("node", [CLI, root, "--no-animation", ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { out: r.stdout, code: r.status };
}

function makeRepo(files) {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-parity-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

function assertSame(root, label) {
  const p = JSON.parse(py(root, "--format", "json").out);
  const j = JSON.parse(js(root, "--format", "json").out);
  assert.deepEqual(j.findings, p.findings, `${label}: findings differ`);
  assert.deepEqual(j.suppressed, p.suppressed, `${label}: suppressed differ`);
  assert.deepEqual(j.controls, p.controls, `${label}: controls/signals differ`);
  assert.deepEqual(j.stats, p.stats, `${label}: stats differ`);
  assert.deepEqual(j.inventory, p.inventory, `${label}: inventory differs`);
  assert.deepEqual(j, p, `${label}: full JSON differs`);
  const pm = py(root, "--format", "markdown").out;
  const jm = js(root, "--format", "markdown").out;
  assert.equal(jm, pm, `${label}: markdown differs`);
}

test("parity on every fixture repo", { skip }, () => {
  for (const [name, files] of Object.entries(FIXTURES)) {
    const root = makeRepo(files);
    try {
      assertSame(root, name);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("parity on real codebases (plugin repo and this repo)", { skip }, () => {
  assertSame(resolve(dirname(PLUGIN), ".."), "plugin repo");
  assertSame(resolve(here, ".."), "cli repo");
});

test("parity on exit codes, filters and baseline", { skip }, () => {
  const root = makeRepo(FIXTURES.vulnerableSaas);
  const base = join(root, "..", `base-${Date.now()}.json`);
  try {
    for (const args of [["--fail-on", "high"], ["--fail-on", "critical"], ["--min-severity", "medium"]]) {
      assert.equal(js(root, "--format", "json", ...args).code, py(root, "--format", "json", ...args).code, args.join(" "));
      if (args[0] === "--min-severity") {
        assert.deepEqual(JSON.parse(js(root, "--format", "json", ...args).out), JSON.parse(py(root, "--format", "json", ...args).out));
      }
    }
    execFileSync("python3", ["-I", PLUGIN, "--root", root, "--format", "json", "--output", base]);
    writeFileSync(join(root, "server.js"), "// fixed\n");
    assert.deepEqual(JSON.parse(js(root, "--format", "json", "--baseline", base).out).comparison,
      JSON.parse(py(root, "--format", "json", "--baseline", base).out).comparison);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(base, { force: true });
  }
});
