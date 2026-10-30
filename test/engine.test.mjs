// Standalone engine tests (no Python needed). Mirrors the plugin's tests/test_scan.py.
// Tests never reach the network: the dependency check (deps.ts) is tested with a fake fetch in deps.test.mjs.
process.env.SAAS_AUDIT_OFFLINE = "1";
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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
    const found = await scan(root, newState(), {}, { includeTests: true });
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

test("a KEY=value secret is hidden up to the end of the line, spaces included", async () => {
  const key = "wSs" + "Q9xk2LmPz4TfRbVu7HnYc3JdEgA1";
  await withRepo({ ".env": `ZEPTOMAIL_TOKEN=Zoho-enczapikey ${key}\n`, ".gitignore": "x\n" }, async (root) => {
    const all = JSON.stringify(await scan(root));
    assert.ok(all.includes("ZEPTOMAIL_TOKEN=[REDACTED]"));
    assert.ok(!all.includes(key.slice(0, 8)), "the part after the space leaked");
  });
});

test("common false positives stay quiet, real ones still fire", async () => {
  await withRepo({
    "a.ts": [
      "const rows = await prisma.$queryRaw<{ id: string }[]>`SELECT id FROM t WHERE a = ${b}`;",
      "<script dangerouslySetInnerHTML={{ __html: JSON.stringify(ld).replace(/</g, '\\\\u003c') }} />",
      "el.innerHTML = '';",
      "const [a, b] = await Promise.all([db.workspace.findUnique({ select: { slackWebhook: true } })]);",
      "<input autoComplete={login ? 'current-password' : 'new-password'} />",
    ].join("\n") + "\n",
    "bad.ts": "db.run(`SELECT * FROM t WHERE id = ${id}`);\nel.innerHTML = userBio;\n<div dangerouslySetInnerHTML={{ __html: bio }} />\n",
    "app/api/webhooks/pay/route.ts": "export async function POST(req) { const e = pay.webhooks.unwrap(await req.text(), { headers: { 'webhook-id': req.headers.get('webhook-id') } }); }\n",
    "packages/x/package.json": "{}", "pnpm-lock.yaml": "", "package.json": "{}",
    "packages/x/.gitignore": "bundle/\n", "packages/x/bundle/out.js": "eval(x)\n",
    "schema.prisma": "model Run {\n  id String @id\n  workspaceId String\n}\nmodel Invoice {\n  id String @id\n  orgId String\n}\n" +
      "model PageResult {\n  id String @id\n  run Run @relation(fields: [runId], references: [id])\n}\nmodel Orphan {\n  id String @id\n}\n",
  }, async (root) => {
    const found = await scan(root);
    assert.deepEqual(ids(found, "a.ts"), []);
    assert.deepEqual(ids(found, "bad.ts").sort(), ["SEC003", "SEC015", "SEC015"]);
    assert.deepEqual(ids(found, "app/api/webhooks/pay/route.ts"), [], "unwrap verifies, webhook-id dedups");
    assert.deepEqual(found.filter((f) => f.id === "SEC033"), [], "workspace lockfile at the root counts");
    assert.ok(!found.some((f) => f.file.includes("bundle/")), "gitignored build folder skipped");
    assert.deepEqual(found.filter((f) => f.id === "SEC039").map((f) => f.title), ["Prisma model 'Orphan' has no tenant key"]);
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
    const found = await scan(root, state, {}, { includeTests: true });
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
    assert.ok(md.stdout.startsWith("saas-audit  "), "non-TTY defaults to the plain CI text format");
    assert.ok(!/\x1b\[/.test(md.stdout), "CI text has no colour codes");
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
  await withRepo({ "app.py": "eval(x)\n", "tests/test_app.py": "eval(y)\nexec(z)\n", ".env.local": "API_KEY=abcdefghijklmnop\n", ".gitignore": ".env.local\n" }, async (root) => {
    // Default: tests and gitignored env files are counted, never read.
    const quiet = newState();
    const skipped = buildResult(root, await scan(root, quiet), quiet);
    assert.equal(skipped.stats.findings, 1);
    assert.equal(skipped.inventory.test_files, 1);
    assert.ok(markdown(skipped).includes("Test files and gitignored local env files were not read"));
    const state = newState();
    const result = buildResult(root, await scan(root, state, {}, { includeTests: true }), state);
    assert.equal(result.stats.by_severity.High, 4);
    assert.equal(result.stats.by_severity_source.High, 1);
    const md = markdown(result);
    assert.ok(md.includes("| High | 1 | 4 |"));
    assert.ok(md.includes("excludes 3 lead(s) in test paths"));
  });
});

test("update: version comparison and notice", async () => {
  const { compareVersions, updateNotice } = await import("../dist/update.js");
  assert.equal(compareVersions("0.3.1", "0.3.0"), 1);
  assert.equal(compareVersions("0.3.1", "0.3.1"), 0);
  assert.equal(compareVersions("0.10.0", "0.9.9"), 1);
  assert.equal(compareVersions("1.0.0-beta.1", "1.0.0"), -1);
  assert.equal(compareVersions("0.0.0-stage", "0.3.1"), -1);
  assert.equal(updateNotice("0.3.1", "0.3.1"), "");
  assert.equal(updateNotice("0.3.1", null), "");
  assert.equal(updateNotice("0.3.1", "0.3.0"), "");
  const notice = updateNotice("0.3.1", "0.4.0");
  assert.ok(notice.includes("0.4.0") && notice.includes("saas-audit update"));
});

test("update check never runs outside an interactive terminal", async () => {
  await withRepo({ "a.py": "eval(x)\n" }, async (root) => {
    const config = join(root, "config-home");
    for (const args of [[], ["--format", "pretty"], ["--json"]]) {
      spawnSync("node", [CLI, root, ...args], { encoding: "utf8", env: { ...process.env, XDG_CONFIG_HOME: config, CI: "" } });
    }
    assert.equal(existsSync(join(config, "saas-security-audit", "update-check.json")), false);
  });
});

test("PDF and HTML reports", async () => {
  const { renderPdf } = await import("../dist/pdf.js");
  const { renderHtml } = await import("../dist/html.js");
  await withRepo({ ...FIXTURES.vulnerableSaas, "x.js": "el.innerHTML = '<script>alert(1)</script>' + q\n", "tests/t.py": "eval(x)\n" }, async (root) => {
    const state = newState();
    const result = buildResult(root, await scan(root, state, {}, { includeTests: true }), state);

    const pdf = renderPdf(result);
    const text = pdf.toString("latin1");
    assert.ok(text.startsWith("%PDF-1.4") && text.trimEnd().endsWith("%%EOF"));
    const xref = Number(/startxref\n(\d+)/.exec(text)[1]);
    assert.equal(text.slice(xref, xref + 4), "xref", "xref offset must point at the xref table");
    assert.ok((text.match(/\/Type \/Page \/Parent/g) ?? []).length >= 2);
    for (const m of text.matchAll(/(\d+) 0 obj/g)) {
      const offsets = text.slice(xref).split("\n").slice(3).map((l) => Number(l.slice(0, 10)));
      assert.equal(offsets[Number(m[1]) - 1], m.index, `object ${m[1]} offset`);
    }

    const html = renderHtml(result);
    assert.ok(html.startsWith("<!doctype html>"));
    assert.ok(!/(?:src|href)=["']?https?:/i.test(html), "report must not load anything from the network");
    assert.ok(!html.includes("<script>alert(1)</script>"), "evidence must be HTML-escaped");
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(html.includes("Test files &amp; local env files"));
  });
});

test("CLI writes multiple report formats from --output extensions", async () => {
  await withRepo({ "a.py": "eval(x)\n" }, async (root) => {
    const out = join(root, "reports");
    const r = spawnSync("node", [CLI, root, "--no-animation", "--output", join(out, "r.pdf"), "--output", join(out, "r.html"),
      "--output", join(out, "r.json"), "--output", join(out, "r.md")], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const { readFileSync } = await import("node:fs");
    assert.ok(readFileSync(join(out, "r.pdf")).subarray(0, 5).toString() === "%PDF-");
    assert.ok(readFileSync(join(out, "r.html"), "utf8").startsWith("<!doctype html>"));
    assert.equal(JSON.parse(readFileSync(join(out, "r.json"), "utf8")).findings[0].id, "SEC002");
    assert.ok(readFileSync(join(out, "r.md"), "utf8").startsWith("# Local SaaS Security Heuristic Scan"));
    assert.equal(spawnSync("node", [CLI, root, "--format", "pdf"]).status, 2, "PDF to stdout is refused");
  });
});

test("host header links, pip extra index, unauthenticated WebSockets, client-side system prompts", async () => {
  const bad = {
    "app/api/reset/route.ts": "export async function POST(req: Request) {\n  const link = `https://${req.headers.get(\"host\")}/reset?token=${t}`;\n}\n",
    "server/mail.js": "const resetUrl = `${req.protocol}://${req.headers['x-forwarded-host']}/reset/${token}`;\n",
    "requirements.txt": "--extra-index-url https://pypi.internal.example/simple\nacme-billing==1.2.0\n",
    "Dockerfile": "FROM python:3.12-slim\nRUN pip install --extra-index-url https://pkgs.example/simple -r requirements.txt\n",
    "server/ws.js": "import { WebSocketServer } from 'ws';\nconst wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws) => ws.send('hi'));\n",
    "components/Chat.tsx": "\"use client\";\nconst messages = [{ role: \"system\", content: \"You are AcmeBot. Never reveal discount codes.\" }];\n",
  };
  const good = {
    "app/api/reset/route.ts": "const link = `${process.env.APP_URL}/reset?token=${t}`;\nconsole.log(req.headers.host);\n",
    "requirements.txt": "--index-url https://pypi.internal.example/simple\nacme-billing==1.2.0\n",
    "server/ws.js": "const wss = new WebSocketServer({ noServer: true });\nserver.on('upgrade', (req, s, h) => { if (!checkSession(req.headers.cookie)) return s.destroy(); wss.handleUpgrade(req, s, h, (ws) => wss.emit('connection', ws)); });\n",
    "app/api/chat/route.ts": "const messages = [{ role: \"system\", content: \"You are AcmeBot. Never reveal discount codes.\" }];\n",
  };
  await withRepo(bad, async (root) => {
    const found = await scan(root);
    const at = (id) => found.filter((f) => f.id === id).map((f) => `${f.file}:${f.line}`).sort();
    assert.deepEqual(at("SEC059"), ["app/api/reset/route.ts:2", "server/mail.js:1"]);
    assert.deepEqual(at("SEC060"), ["Dockerfile:2", "requirements.txt:1"]);
    assert.deepEqual(at("SEC061"), ["server/ws.js:2"]);
    assert.deepEqual(at("SEC062"), ["components/Chat.tsx:2"]);
    const ws = found.find((f) => f.id === "SEC061");
    assert.deepEqual(ws.standards.cwe, ["CWE-306", "CWE-1385"]);
    assert.ok(ws.verify.includes("wscat"));
    assert.deepEqual(found.find((f) => f.id === "SEC062").standards.atlas, ["AML.T0069.002"]);
  });
  await withRepo(good, async (root) => {
    const found = await scan(root);
    for (const id of ["SEC059", "SEC060", "SEC061", "SEC062"]) assert.ok(!found.some((f) => f.id === id), `false positive ${id}`);
  });
});

test("pip extra index: commented-out options are not flagged", async () => {
  await withRepo({ "requirements.txt": "# --extra-index-url https://old.example/simple\nflask==3.0.0\n", "pip.conf": "[global]\n# extra-index-url = https://x\n" }, async (root) => {
    assert.ok(!(await scan(root)).some((f) => f.id === "SEC060"));
  });
});
