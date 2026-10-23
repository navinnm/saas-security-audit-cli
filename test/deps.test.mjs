// Dependency check (src/deps.ts) with a fake network: lockfile parsing, OSV advisories, outdated majors.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkDependencies, cmpVersion, lockedPackages } from "../dist/deps.js";

function repo(files) {
  const root = mkdtempSync(join(tmpdir(), "saas-audit-deps-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const PKG = JSON.stringify({ dependencies: { next: "^14.0.0", "@babel/parser": "7.20.0" }, devDependencies: { lodash: "^4" } }, null, 2);
const NPM_LOCK = JSON.stringify({ lockfileVersion: 3, packages: {
  "": { name: "app" },
  "node_modules/next": { version: "14.1.0" },
  "node_modules/@babel/parser": { version: "7.20.0" },
  "node_modules/lodash": { version: "4.17.20", dev: true },
  "node_modules/next/node_modules/semver": { version: "5.7.1" },
} }, null, 2);
const PNPM_LOCK = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: ^14\n        version: 14.1.0\n\npackages:\n\n  '@babel/parser@7.20.0':\n    resolution: {integrity: x}\n\n  next@14.1.0:\n    resolution: {integrity: y}\n\nsnapshots:\n\n  next@14.1.0(react@18.3.1):\n    dependencies: {}\n";
const YARN_LOCK = '# yarn lockfile v1\n\n"@babel/parser@^7.20.0", "@babel/parser@7.20.0":\n  version "7.20.0"\n\nnext@^14:\n  version "14.1.0"\n';

test("versions compare like semver", () => {
  assert.ok(cmpVersion("14.2.25", "14.1.0") > 0);
  assert.ok(cmpVersion("1.0.0-beta.1", "1.0.0") < 0);
  assert.equal(cmpVersion("2.0.0", "2.0.0"), 0);
});

test("reads npm, pnpm and yarn lockfiles", () => {
  for (const [lock, text] of [["package-lock.json", NPM_LOCK], ["pnpm-lock.yaml", PNPM_LOCK], ["yarn.lock", YARN_LOCK]]) {
    const root = repo({ "package.json": PKG, [lock]: text });
    try {
      const { packages } = lockedPackages(root, ["package.json", lock]);
      const got = packages.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort();
      assert.ok(got.includes("next@14.1.0*"), `${lock}: ${got}`);
      assert.ok(got.includes("@babel/parser@7.20.0*"), `${lock}: ${got}`);
      if (lock === "package-lock.json") assert.ok(got.includes("semver@5.7.1") && got.includes("lodash@4.17.20*"));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("known vulnerabilities with the fixed version, and majors behind", async () => {
  const root = repo({ "package.json": PKG, "package-lock.json": NPM_LOCK });
  const sent = [];
  const fakeFetch = async (url, init) => {
    sent.push(init?.body ? JSON.parse(init.body) : url);
    const json = (data, ok = true) => ({ ok, status: ok ? 200 : 500, json: async () => data });
    if (url.endsWith("/querybatch")) {
      const queries = JSON.parse(init.body).queries;
      return json({ results: queries.map((q) => ({ vulns: q.package.name === "next" ? [{ id: "GHSA-f82v-jwr5-mffw" }] : q.package.name === "lodash" ? [{ id: "GHSA-35jh-r3h4-6jhm" }] : [] })) });
    }
    if (url.includes("/vulns/GHSA-f82v")) return json({ id: "GHSA-f82v-jwr5-mffw", aliases: ["CVE-2025-29927"], summary: "Authorization bypass in Next.js middleware", published: "2025-03-21T00:00:00Z",
      database_specific: { severity: "CRITICAL" }, affected: [{ package: { ecosystem: "npm", name: "next" }, ranges: [{ type: "SEMVER", events: [{ introduced: "13.0.0" }, { fixed: "14.2.25" }] }] }] });
    if (url.includes("/vulns/GHSA-35jh")) return json({ id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command injection in lodash", published: "2021-02-15T00:00:00Z",
      database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] });
    if (url.includes("registry.npmjs.org/next/")) return json({ version: "16.4.2" });
    if (url.includes("registry.npmjs.org/@babel%2Fparser/")) return json({ version: "7.29.8" });
    if (url.includes("registry.npmjs.org/lodash/")) return json({ version: "4.17.21" });
    return json({}, false);
  };
  try {
    const { hits, status } = await checkDependencies(root, ["package.json", "package-lock.json"], { fetch: fakeFetch });
    const next = hits.find((h) => h.id === "SEC050" && h.title.startsWith("next@"));
    assert.equal(next.severity, "Critical");
    assert.equal(next.rel, "package.json", "direct dependency points at its package.json line");
    assert.match(next.evidence, /CVE-2025-29927 \(2025-03-21\) · fixed in 14\.2\.25/);
    const lodash = hits.find((h) => h.title.startsWith("lodash@"));
    assert.equal(lodash.severity, "Medium", "dev-only dependency counts one step lower");
    const behind = hits.find((h) => h.id === "SEC051");
    assert.match(behind.title, /next is 2 major versions behind \(14\.1\.0 → 16\.4\.2\)/);
    assert.equal(hits.filter((h) => h.id === "SEC051").length, 1, "same major (babel, lodash) is not reported");
    assert.deepEqual([status.packages, status.vulnerable, status.outdated], [4, 2, 1]);
    // Only package names and versions leave the machine.
    const batch = sent.find((x) => x?.queries);
    assert.deepEqual(Object.keys(batch.queries[0]).sort(), ["package", "version"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("no network: reported, never fatal", async () => {
  const root = repo({ "package.json": PKG, "package-lock.json": NPM_LOCK });
  try {
    const { hits, status } = await checkDependencies(root, ["package.json", "package-lock.json"], { fetch: async () => { throw new Error("getaddrinfo ENOTFOUND"); } });
    assert.deepEqual(hits, []);
    assert.match(status.error, /vulnerability lookup failed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
