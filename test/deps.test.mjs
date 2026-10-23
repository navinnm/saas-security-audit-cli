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

const ECOSYSTEMS = {
  // PHP
  "composer.json": JSON.stringify({ require: { "laravel/framework": "^10.0", php: "^8.2" }, "require-dev": { "phpunit/phpunit": "^10" } }, null, 2),
  "composer.lock": JSON.stringify({ packages: [{ name: "laravel/framework", version: "v10.1.0" }, { name: "guzzlehttp/psr7", version: "2.4.0" }],
    "packages-dev": [{ name: "phpunit/phpunit", version: "10.0.0" }] }, null, 2),
  // Python: PEP 621 + Poetry lock, uv lock, Pipfile, requirements
  "api/pyproject.toml": '[project]\nname = "api"\ndependencies = ["django>=4.2", "requests[socks]==2.25.0"]\n',
  "api/poetry.lock": '[[package]]\nname = "Django"\nversion = "4.2.1"\ncategory = "main"\n\n[[package]]\nname = "requests"\nversion = "2.25.0"\n\n[[package]]\nname = "urllib3"\nversion = "1.26.4"\n',
  "worker/uv.lock": 'version = 1\n\n[[package]]\nname = "worker"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "celery"\nversion = "5.3.0"\nsource = { registry = "https://pypi.org/simple" }\n',
  "ml/Pipfile": '[packages]\nnumpy = "*"\n\n[dev-packages]\npytest = "*"\n',
  "ml/Pipfile.lock": JSON.stringify({ default: { numpy: { version: "==1.24.0" } }, develop: { pytest: { version: "==7.0.0" } } }),
  "scripts/requirements.txt": "# tools\nflask==2.0.1  # web\nJinja2[i18n]==3.0.0 ; python_version >= '3.8'\nclick>=8\n",
  // Go, with the toolchain version
  "svc/go.mod": "module example.com/svc\n\ngo 1.21.3\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.10.0 // indirect\n)\n\nrequire github.com/google/uuid v1.3.0\n",
  // Ruby
  "web/Gemfile": "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
  "web/Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.15.0-x86_64-linux)\n      racc (~> 1.4)\n    rails (7.0.4)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  rails (~> 7.0)\n",
  // Rust
  "rs/Cargo.toml": '[package]\nname = "rs"\n\n[dependencies]\ntokio = "1"\n',
  "rs/Cargo.lock": '[[package]]\nname = "rs"\nversion = "0.1.0"\n\n[[package]]\nname = "tokio"\nversion = "1.20.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  // .NET
  "dotnet/packages.lock.json": JSON.stringify({ version: 1, dependencies: { "net8.0": { "Newtonsoft.Json": { type: "Direct", resolved: "12.0.1" }, "System.Text.Json": { type: "Transitive", resolved: "6.0.0" } } } }),
  "dotnet2/App.csproj": '<Project><ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup></Project>',
  // Java
  "java/pom.xml": "<project><properties><jackson.version>2.13.0</jackson.version></properties><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency></dependencies></project>",
  "kt/gradle.lockfile": "org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=\n",
  // Dart
  "app/pubspec.lock": 'packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n    source: hosted\n    version: "0.13.0"\n  meta:\n    dependency: transitive\n    source: hosted\n    version: "1.8.0"\n',
};

test("reads Composer, Python, Go, Ruby, Rust, .NET, Java and Dart dependencies", () => {
  const root = repo(ECOSYSTEMS);
  try {
    const { packages, lockfiles } = lockedPackages(root, Object.keys(ECOSYSTEMS));
    const got = new Set(packages.map((p) => `${p.ecosystem} ${p.name}@${p.version}${p.direct ? "*" : ""}${p.dev ? " dev" : ""}`));
    for (const want of [
      "Packagist laravel/framework@10.1.0*", "Packagist guzzlehttp/psr7@2.4.0", "Packagist phpunit/phpunit@10.0.0* dev",
      "PyPI Django@4.2.1*", "PyPI requests@2.25.0*", "PyPI urllib3@1.26.4", "PyPI celery@5.3.0",
      "PyPI numpy@1.24.0*", "PyPI pytest@7.0.0* dev", "PyPI flask@2.0.1*", "PyPI Jinja2@3.0.0*",
      "Go stdlib@1.21.3*", "Go github.com/gin-gonic/gin@1.9.0*", "Go golang.org/x/net@0.10.0", "Go github.com/google/uuid@1.3.0*",
      "RubyGems nokogiri@1.15.0", "RubyGems rails@7.0.4*", "crates.io tokio@1.20.0*",
      "NuGet Newtonsoft.Json@12.0.1*", "NuGet System.Text.Json@6.0.0", "NuGet Serilog@2.10.0*",
      "Maven com.fasterxml.jackson.core:jackson-databind@2.13.0*", "Maven junit:junit@4.12* dev", "Maven org.apache.logging.log4j:log4j-core@2.14.1",
      "Pub http@0.13.0*", "Pub meta@1.8.0",
    ]) assert.ok(got.has(want), `missing ${want}\n${[...got].join("\n")}`);
    assert.ok(![...got].some((g) => /\b(?:worker|rs)@0\.1\.0/.test(g)), "the project's own package is not a dependency");
    assert.ok(![...got].some((g) => g.includes("click")), "unpinned requirement (click>=8) is not a version");
    assert.equal(lockfiles.length, 13);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("each package is asked about under its own OSV ecosystem", async () => {
  const root = repo(ECOSYSTEMS);
  let batch;
  try {
    const { hits } = await checkDependencies(root, Object.keys(ECOSYSTEMS), { maxLatestLookups: 0, fetch: async (url, init) => {
      if (url.endsWith("/querybatch")) {
        batch = JSON.parse(init.body).queries;
        return { ok: true, status: 200, json: async () => ({ results: batch.map((q) => ({ vulns: q.package.name === "guzzlehttp/psr7" ? [{ id: "GHSA-wxmh-65f7-jcvw" }] : [] })) }) };
      }
      return { ok: true, status: 200, json: async () => ({ id: "GHSA-wxmh-65f7-jcvw", aliases: ["CVE-2023-29197"], summary: "Improper header validation", published: "2023-04-17T00:00:00Z",
        database_specific: { severity: "MODERATE" }, affected: [{ package: { ecosystem: "Packagist", name: "guzzlehttp/psr7" }, ranges: [{ events: [{ introduced: "2.0.0" }, { fixed: "2.4.5" }] }] }] }) };
    } });
    const eco = new Set(batch.map((q) => q.package.ecosystem));
    for (const e of ["npm", "PyPI", "Go", "RubyGems", "Packagist", "crates.io", "NuGet", "Maven", "Pub"].filter((x) => x !== "npm")) assert.ok(eco.has(e), `no ${e} query`);
    const guzzle = hits.find((h) => h.title.startsWith("guzzlehttp/psr7@2.4.0"));
    assert.equal(guzzle.severity, "Medium");
    assert.match(guzzle.evidence, /\(Packagist, indirect\): CVE-2023-29197 \(2023-04-17\) · fixed in 2\.4\.5/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
