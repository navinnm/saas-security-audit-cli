// Standalone engine tests (no Python needed). Mirrors the plugin's tests/test_scan.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FAKE, FIXTURES, jwt } from "./fixtures.mjs";
import { fnmatch, gateCounts, newState, scan, splitlines } from "../dist/engine.js";
import { buildResult, markdown } from "../dist/report.js";

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), "../dist/cli.js");

async function withRepo(files, fn) {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-test-"));
  try {
    for (const [rel, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    }
    return await fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const ids = (findings, file) => findings.filter((f) => !file || f.file === file).map((f) => f.id).sort();

test("detects the planted SaaS vulnerabilities", async () => {
  await withRepo(FIXTURES.vulnerableSaas, async (root) => {
    const found = await scan(root);
    for (const id of ["SEC003", "SEC005", "SEC013", "SEC015", "SEC016", "SEC019", "SEC021", "SEC022", "SEC023", "SEC027", "SEC030", "SEC031", "SEC032", "SEC034"]) {
      assert.ok(found.some((f) => f.id === id), `missing ${id}`);
    }
    assert.ok(!found.some((f) => f.file === "server.js" && f.line === 12), "regex .exec() must not be flagged");
  });
});

test("secrets are detected and never echoed", async () => {
  await withRepo(FIXTURES.secrets, async (root) => {
    const found = await scan(root);
    const all = JSON.stringify(found);
    for (const v of [FAKE.api, FAKE.stripeLive, FAKE.aws, FAKE.dbPass, FAKE.gh]) assert.ok(!all.includes(v), `leaked ${v.slice(0, 6)}…`);
    const live = found.find((f) => f.file === ".env.production" && f.line === 1);
    assert.equal(live.severity, "Critical");
    assert.equal(found.find((f) => f.file === ".env.production" && f.line === 3).severity, "Low");
    assert.deepEqual(ids(found, ".env.example"), []);
    const staging = found.find((f) => f.file === ".env.staging");
    assert.equal(staging.context, "ignored-local-env");
    assert.equal(gateCounts(staging), false);
    const jwts = found.filter((f) => f.file === "a.ts");
    assert.equal(jwts.find((f) => f.line === 2).severity, "Critical");
    assert.ok(!jwts.some((f) => f.line === 1), "anon JWT is public by design");
  });
});

test("parameterized and tagged queries are clean", async () => {
  await withRepo({ "a.py": 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n',
    "b.ts": "await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;\n" }, async (root) => {
    assert.deepEqual(await scan(root), []);
  });
});

test("modern controls 20-22 map correctly", async () => {
  await withRepo(FIXTURES.injection, async (root) => {
    const found = await scan(root);
    assert.equal(found.find((f) => f.id === "SEC020").controls[0], 20);
    assert.equal(found.find((f) => f.id === "SEC037").controls[0], 21);
    assert.deepEqual(ids(found, "h.ts"), ["SEC035", "SEC036"]);
  });
});

test("tenant schema checks: SQL, Drizzle, Prisma", async () => {
  await withRepo(FIXTURES.schemas, async (root) => {
    const found = await scan(root);
    assert.ok(found.some((f) => f.id === "SEC030" && f.title.includes("projects")));
    assert.ok(!found.some((f) => f.id === "SEC030" && f.title.includes("orgs")));
    assert.ok(found.some((f) => f.id === "SEC038" && f.title.includes("notes")));
    assert.ok(!found.some((f) => f.id === "SEC038" && f.title.includes("docs")));
    assert.deepEqual(found.filter((f) => f.id === "SEC039").map((f) => f.title), ["Prisma model 'AuditEvent' has no tenant key"]);
    assert.ok(found.some((f) => f.id === "SEC026" && f.file === "main.tf"));
  });
});

test("suppression, test context, skipped files", async () => {
  await withRepo(FIXTURES.edgeCases, async (root) => {
    const state = newState();
    const found = await scan(root, state);
    assert.deepEqual(state.suppressed.map((f) => [f.line, f.suppressed]), [[1, "constant expression only"], [3, "no reason given"]]);
    assert.ok(found.some((f) => f.file === "suppressed.py" && f.line === 4), "wrong-id suppression must not hide a lead");
    assert.ok(!found.some((f) => f.file === "bundle.min.js" || f.file === "bin.png"));
    assert.equal(state.skipped_large_lines, 1);
    assert.equal(state.signals[2].source[0], "src/middleware.ts:1");
    assert.equal(state.signals[2].test_count, 1);
  });
});

test("node_modules is skipped and controls stay NOT VERIFIED", async () => {
  await withRepo({ "node_modules/bad.js": "eval(userInput)\n" }, async (root) => {
    const state = newState();
    const found = await scan(root, state);
    assert.deepEqual(found, []);
    const md = markdown(buildResult(root, found, state));
    assert.ok(md.includes("does **not** mean the project is secure"));
    assert.ok(md.includes("| 22 | AI/LLM security and prompt injection | NOT VERIFIED |"));
    assert.ok(!md.includes("| PASS |"));
  });
});

test("python helper ports", () => {
  assert.deepEqual(splitlines("a\r\nb\rc\nd\n"), ["a", "b", "c", "d"]);
  assert.deepEqual(splitlines(""), []);
  assert.ok(fnmatch(".env.local", ".env*"));
  assert.ok(fnmatch("dist/app.js", "dist/*"));
  assert.ok(!fnmatch("Env", "env"));
  assert.ok(fnmatch("a.log", "*.[lL]og"));
});

test("CLI: json output, fail-on exit codes, bad args", async () => {
  await withRepo({ "a.py": "eval(x)\n" }, async (root) => {
    const run = (...args) => spawnSync("node", [CLI, root, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
    const json = JSON.parse(run("--json").stdout);
    assert.equal(json.findings[0].id, "SEC002");
    assert.equal(json.controls.length, 22);
    assert.equal(run("--json", "--fail-on", "high").status, 1);
    assert.equal(run("--json", "--fail-on", "critical").status, 0);
    assert.equal(run("--fail-on", "nope").status, 2);
    assert.equal(spawnSync("node", [CLI, join(root, "missing")]).status, 2);
    const md = run();
    assert.equal(md.status, 0);
    assert.ok(md.stdout.startsWith("# Local SaaS Security Heuristic Scan"), "non-TTY defaults to Markdown");
  });
});

test("own reports are not re-scanned", async () => {
  await withRepo({ "a.py": "eval(x)\n" }, async (root) => {
    const run = (...args) => spawnSync("node", [CLI, root, "--no-animation", ...args], { encoding: "utf8" });
    run("--json", "--output", join(root, "baseline.json"));
    run("--output", join(root, "security-report.md"));
    const state = newState();
    const found = await scan(root, state);
    assert.deepEqual([...new Set(found.map((f) => f.file))], ["a.py"]);
    assert.equal(state.files_scanned, 1);
  });
});

test("summary separates source from tests", async () => {
  await withRepo({ "app.py": "eval(x)\n", "tests/test_app.py": "eval(y)\nexec(z)\n" }, async (root) => {
    const state = newState();
    const result = buildResult(root, await scan(root, state), state);
    assert.equal(result.stats.by_severity.High, 3);
    assert.equal(result.stats.by_severity_source.High, 1);
    const md = markdown(result);
    assert.ok(md.includes("| High | 1 | 3 |"));
    assert.ok(md.includes("excludes 2 lead(s) in test paths"));
  });
});
