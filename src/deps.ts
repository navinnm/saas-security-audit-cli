/**
 * Dependency check for every common ecosystem: exact versions from lockfiles and manifests, known
 * vulnerabilities from OSV.dev (GitHub advisories, PyPA, Go, RustSec, RubySec, … with CVE aliases, dates
 * and the version that fixes each), and how far each direct dependency is behind its latest stable release.
 *
 *   npm        package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock
 *   PyPI       poetry.lock, uv.lock, pdm.lock, Pipfile.lock, requirements*.txt (== pins)
 *   Go         go.mod (+ the Go version itself, as "stdlib")
 *   RubyGems   Gemfile.lock
 *   Packagist  composer.lock
 *   crates.io  Cargo.lock
 *   NuGet      packages.lock.json, *.csproj / Directory.Packages.props (literal versions)
 *   Maven      pom.xml (literal or ${property} versions), gradle.lockfile, build.gradle(.kts) literals
 *   Pub        pubspec.lock
 *
 * Network: only package names and versions are sent (api.osv.dev and each ecosystem's public registry).
 * Turned off with --offline or SAAS_AUDIT_OFFLINE=1; any network failure is reported, never fatal.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export type Ecosystem = "npm" | "PyPI" | "Go" | "RubyGems" | "Packagist" | "crates.io" | "NuGet" | "Maven" | "Pub";

export interface DepPackage {
  ecosystem: Ecosystem; name: string; version: string; lockfile: string; line: number; direct: boolean; dev: boolean;
}
export interface DepVuln {
  id: string; aliases: string[]; summary: string; severity: "Critical" | "High" | "Medium" | "Low";
  published: string | null; fixed: string | null; url: string;
}
export interface DepHit {
  id: "SEC050" | "SEC051"; title: string; severity: string; confidence: string; controls: number[];
  rel: string; line: number; evidence: string; guidance: string;
}
export interface DepStatus {
  lockfiles: string[]; ecosystems: string[]; packages: number; vulnerable: number; advisories: number; outdated: number;
  checked_at: string; error?: string;
}

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

const OSV = "https://api.osv.dev/v1";
const UA = "saas-security-audit (dependency check; sends package names and versions only)";

// ---------- versions ----------

const parseVer = (v: string) => {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)*(?:[-.+]?([A-Za-z][0-9A-Za-z.-]*))?/.exec(String(v).trim());
  if (!m) return null;
  // Maven's 1.2.3.RELEASE / .Final / .GA are releases, not pre-releases.
  const pre = m[4] && !/^(?:RELEASE|Final|GA|jre\d*|android)$/i.test(m[4]) ? m[4] : "";
  return { major: +m[1], minor: +(m[2] ?? 0), patch: +(m[3] ?? 0), pre };
};
export function cmpVersion(a: string, b: string): number {
  const x = parseVer(a), y = parseVer(b);
  if (!x || !y) return a < b ? -1 : a > b ? 1 : 0;
  for (const k of ["major", "minor", "patch"] as const) if (x[k] !== y[k]) return x[k] - y[k];
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

// ---------- reading files ----------

const lineOf = (text: string, needle: string) => {
  const i = text.indexOf(needle);
  return i < 0 ? 1 : text.slice(0, i).split("\n").length;
};
const pyName = (n: string) => n.toLowerCase().replace(/[_.]+/g, "-");
const base = (rel: string) => rel.slice(rel.lastIndexOf("/") + 1);
const dirOf = (rel: string) => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/") + 1) : "");

/** Names a project's own manifest asks for (direct dependencies), per ecosystem. */
type Direct = Map<string, { rel: string; line: number }>;
const key = (eco: Ecosystem, name: string) => `${eco}:${eco === "PyPI" ? pyName(name) : eco === "NuGet" ? name.toLowerCase() : name}`;

function readDirect(root: string, files: string[]): Direct {
  const direct: Direct = new Map();
  const add = (eco: Ecosystem, name: string, rel: string, text: string, needle = name) => {
    const k = key(eco, name);
    if (!direct.has(k)) direct.set(k, { rel, line: lineOf(text, needle) });
  };
  for (const rel of files) {
    const name = base(rel);
    let text: string;
    if (!/^(?:package\.json|pyproject\.toml|Pipfile|composer\.json|Cargo\.toml|Gemfile|pubspec\.yaml|requirements.*\.txt)$/.test(name)) continue;
    try { text = readFileSync(join(root, rel), "utf8"); } catch { continue; }
    try {
      if (name === "package.json") {
        const d = JSON.parse(text);
        for (const k of ["dependencies", "devDependencies", "optionalDependencies"]) {
          for (const [n, r] of Object.entries<string>(d?.[k] ?? {})) {
            if (typeof r === "string" && /^(?:workspace|file|link|git|https?):/.test(r)) continue;
            add("npm", n, rel, text, `"${n}"`);
          }
        }
      } else if (name === "composer.json") {
        const d = JSON.parse(text);
        for (const k of ["require", "require-dev"]) for (const n of Object.keys(d?.[k] ?? {})) if (n.includes("/")) add("Packagist", n, rel, text, `"${n}"`);
      } else if (name === "pyproject.toml") {
        // PEP 621 dependencies = ["requests>=2", …] and Poetry [tool.poetry.*dependencies] tables.
        for (const m of text.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:[<>=!~;]|["'])/g)) add("PyPI", m[1], rel, text, m[1]);
        for (const sec of text.matchAll(/^\[tool\.poetry\.(?:group\.\w+\.)?(?:dev-)?dependencies\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/gm)) {
          for (const m of sec[1].matchAll(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/gm)) if (m[1] !== "python") add("PyPI", m[1], rel, text, m[1]);
        }
      } else if (name === "Pipfile") {
        for (const sec of text.matchAll(/^\[(?:dev-)?packages\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/gm)) {
          for (const m of sec[1].matchAll(/^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/gm)) add("PyPI", m[1], rel, text, m[1]);
        }
      } else if (name.startsWith("requirements")) {
        for (const m of text.matchAll(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/gm)) add("PyPI", m[1], rel, text, m[1]);
      } else if (name === "Cargo.toml") {
        for (const sec of text.matchAll(/^\[(?:[\w.-]+\.)?(?:dev-|build-)?dependencies\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/gm)) {
          for (const m of sec[1].matchAll(/^([A-Za-z0-9_-]+)\s*=/gm)) add("crates.io", m[1], rel, text, m[1]);
        }
      } else if (name === "Gemfile") {
        for (const m of text.matchAll(/^\s*gem\s+["']([^"']+)["']/gm)) add("RubyGems", m[1], rel, text, m[1]);
      } else if (name === "pubspec.yaml") {
        for (const sec of text.matchAll(/^(?:dev_)?dependencies:\s*\n((?:[ \t]+.*\n?)*)/gm)) {
          for (const m of sec[1].matchAll(/^ {2}([a-z0-9_]+):/gm)) add("Pub", m[1], rel, text, m[1]);
        }
      }
    } catch { /* malformed manifest */ }
  }
  return direct;
}

type Reader = (rel: string, text: string, direct: Direct) => DepPackage[];
const pkg = (ecosystem: Ecosystem, name: string, version: string, lockfile: string, line: number, direct: Direct, dev = false, isDirect?: boolean): DepPackage =>
  ({ ecosystem, name, version, lockfile, line, direct: isDirect ?? direct.has(key(ecosystem, name)), dev });

const npmLock: Reader = (rel, text, direct) => {
  let data: any;
  try { data = JSON.parse(text); } catch { return []; }
  const out: DepPackage[] = [];
  if (data.packages && typeof data.packages === "object") {
    for (const [path, info] of Object.entries<any>(data.packages)) {
      if (!path || !info?.version || info.link) continue;
      const name = info.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push(pkg("npm", name, info.version, rel, lineOf(text, `"${path}"`), direct, Boolean(info.dev), direct.has(key("npm", name)) && path === `node_modules/${name}`));
    }
  } else if (data.dependencies) {
    const walk = (deps: Record<string, any>, top: boolean) => {
      for (const [name, info] of Object.entries<any>(deps)) {
        if (info?.version && !/^(?:file|link|git)/.test(info.version)) out.push(pkg("npm", name, info.version, rel, lineOf(text, `"${name}"`), direct, Boolean(info.dev), top && direct.has(key("npm", name))));
        if (info?.dependencies) walk(info.dependencies, false);
      }
    };
    walk(data.dependencies, true);
  }
  return out;
};

const pnpmLock: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  let inPackages = false;
  text.split(/\r?\n/).forEach((line, i) => {
    if (/^\S/.test(line)) inPackages = /^packages:\s*$/.test(line);
    if (!inPackages) return;
    // v9: `  next@16.4.2:` / `  '@babel/parser@7.29.8':`; v5/v6: `  /next@16.4.2:` / `  /next/13.0.0:`
    const m = /^ {2}'?\/?((?:@[^@/\s']+\/)?[^@/\s'(]+)[@/](\d[^(':\s]*)/.exec(line);
    if (m) out.push(pkg("npm", m[1], m[2], rel, i + 1, direct));
  });
  return out;
};

const yarnLock: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const head = lines[i];
    if (!head || /^\s|^#/.test(head) || !head.trimEnd().endsWith(":")) continue;
    const spec = head.split(",")[0].replace(/^"|":?$|:$/g, "").trim();
    const at = spec.lastIndexOf("@");
    if (at <= 0) continue;
    const name = spec.slice(0, at).replace(/^"/, "").replace(/@npm$/, "");
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]); j++) {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j]);
      if (v) { out.push(pkg("npm", name, v[1], rel, i + 1, direct)); break; }
    }
  }
  return out;
};

/** TOML [[package]] blocks with name / version (poetry.lock, uv.lock, pdm.lock, Cargo.lock). */
const tomlPackages = (eco: Ecosystem): Reader => (rel, text, direct) => {
  const out: DepPackage[] = [];
  const blocks = text.split(/^\[\[package\]\]\s*$/m).slice(1);
  let offset = text.indexOf("[[package]]");
  for (const b of blocks) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(b)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(b)?.[1];
    const local = /^source\s*=\s*\{\s*(?:editable|virtual|path|directory)\s*=/m.test(b) || (eco === "crates.io" && !/^source\s*=/m.test(b));
    if (name && version && !local) out.push(pkg(eco, name, version, rel, text.slice(0, offset).split("\n").length, direct, /^category\s*=\s*"dev"/m.test(b)));
    offset = text.indexOf("[[package]]", offset + 1);
  }
  return out;
};

const pipfileLock: Reader = (rel, text, direct) => {
  let d: any;
  try { d = JSON.parse(text); } catch { return []; }
  const out: DepPackage[] = [];
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    for (const [name, info] of Object.entries<any>(d?.[section] ?? {})) {
      const v = /^==\s*(.+)$/.exec(String(info?.version ?? ""))?.[1];
      if (v) out.push(pkg("PyPI", name, v, rel, lineOf(text, `"${name}"`), direct, dev));
    }
  }
  return out;
};

const requirements: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)/.exec(line);
    if (m) out.push(pkg("PyPI", m[1], m[2], rel, i + 1, direct, /dev|test/i.test(base(rel)), true));
  });
  return out;
};

const goMod: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  let block = false;
  text.split(/\r?\n/).forEach((line, i) => {
    const goVer = /^(?:go|toolchain\s+go)\s*(\d+\.\d+(?:\.\d+)?)\s*$/.exec(line.trim());
    if (goVer) { out.push(pkg("Go", "stdlib", goVer[1], rel, i + 1, direct, false, true)); return; }
    if (/^require\s*\($/.test(line.trim())) { block = true; return; }
    if (block && line.trim() === ")") { block = false; return; }
    const m = (block ? /^\s*([^\s]+)\s+(v[^\s]+)(.*)$/ : /^require\s+([^\s]+)\s+(v[^\s]+)(.*)$/).exec(line);
    if (m) out.push(pkg("Go", m[1], m[2].replace(/^v/, "").replace(/\+incompatible$/, ""), rel, i + 1, direct, false, !/\/\/\s*indirect/.test(m[3])));
  });
  return out;
};

const gemfileLock: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  const lines = text.split(/\r?\n/);
  const directNames = new Set<string>();
  let inDeps = false;
  for (const line of lines) {
    if (/^\S/.test(line)) inDeps = line.trim() === "DEPENDENCIES";
    else if (inDeps) { const m = /^ {2}([^\s!(]+)/.exec(line); if (m) directNames.add(m[1]); }
  }
  let inSpecs = false;
  lines.forEach((line, i) => {
    if (/^\S/.test(line)) inSpecs = false;
    if (/^ {2}specs:\s*$/.test(line)) { inSpecs = true; return; }
    if (!inSpecs) return;
    const m = /^ {4}([^\s(]+) \(([^)]+)\)$/.exec(line);
    if (m) out.push(pkg("RubyGems", m[1], m[2].replace(/-(?:x86|arm|aarch|java|universal|x64|mingw|darwin|linux).*$/i, ""), rel, i + 1, direct, false, directNames.has(m[1]) || direct.has(key("RubyGems", m[1]))));
  });
  return out;
};

const composerLock: Reader = (rel, text, direct) => {
  let d: any;
  try { d = JSON.parse(text); } catch { return []; }
  const out: DepPackage[] = [];
  for (const [section, dev] of [["packages", false], ["packages-dev", true]] as const) {
    for (const p of d?.[section] ?? []) {
      if (p?.name && p?.version && !/^dev-/.test(p.version)) out.push(pkg("Packagist", p.name, String(p.version).replace(/^v/, ""), rel, lineOf(text, `"name": "${p.name}"`), direct, dev));
    }
  }
  return out;
};

const nugetLock: Reader = (rel, text, direct) => {
  let d: any;
  try { d = JSON.parse(text); } catch { return []; }
  const out: DepPackage[] = [];
  for (const fw of Object.values<any>(d?.dependencies ?? {})) {
    for (const [name, info] of Object.entries<any>(fw ?? {})) {
      if (info?.resolved && info.type !== "Project") out.push(pkg("NuGet", name, info.resolved, rel, lineOf(text, `"${name}"`), direct, false, info.type === "Direct"));
    }
  }
  return out;
};

const csproj: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  for (const m of text.matchAll(/<Package(?:Reference|Version)\s+Include="([^"]+)"\s+Version="([0-9][^"]*)"/g)) {
    out.push(pkg("NuGet", m[1], m[2], rel, lineOf(text, m[0]), direct, false, true));
  }
  return out;
};

const pomXml: Reader = (rel, text, direct) => {
  const props = new Map<string, string>();
  const propsBlock = /<properties>([\s\S]*?)<\/properties>/.exec(text)?.[1] ?? "";
  for (const m of propsBlock.matchAll(/<([\w.-]+)>([^<]+)<\/\1>/g)) props.set(m[1], m[2].trim());
  const out: DepPackage[] = [];
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = /<groupId>([^<]+)<\/groupId>/.exec(m[1])?.[1]?.trim();
    const a = /<artifactId>([^<]+)<\/artifactId>/.exec(m[1])?.[1]?.trim();
    let v = /<version>([^<]+)<\/version>/.exec(m[1])?.[1]?.trim();
    if (v?.startsWith("${")) v = props.get(v.slice(2, -1));
    const scope = /<scope>([^<]+)<\/scope>/.exec(m[1])?.[1]?.trim();
    if (g && a && v && /^\d/.test(v)) out.push(pkg("Maven", `${g}:${a}`, v, rel, lineOf(text, `<artifactId>${a}</artifactId>`), direct, scope === "test", true));
  }
  return out;
};

const gradle: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  const lock = rel.endsWith(".lockfile");
  text.split(/\r?\n/).forEach((line, i) => {
    const m = lock ? /^([\w.-]+):([\w.-]+):([0-9][^=\s]*)=/.exec(line)
      : /\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*["']([\w.-]+):([\w.-]+):([0-9][^"'@:]*)["']/.exec(line);
    if (m) out.push(pkg("Maven", `${m[1]}:${m[2]}`, m[3], rel, i + 1, direct, /test/i.test(line), !lock));
  });
  return out;
};

const pubspecLock: Reader = (rel, text, direct) => {
  const out: DepPackage[] = [];
  const lines = text.split(/\r?\n/);
  let cur: { name: string; line: number; dep?: string } | null = null;
  lines.forEach((line, i) => {
    const n = /^ {2}([a-z0-9_]+):\s*$/.exec(line);
    if (n) { cur = { name: n[1], line: i + 1 }; return; }
    if (!cur) return;
    const d = /^ {4}dependency:\s*"?([^"]+)"?/.exec(line);
    if (d) cur.dep = d[1];
    const v = /^ {4}version:\s*"?([^"\s]+)"?/.exec(line);
    if (v) { out.push(pkg("Pub", cur.name, v[1], rel, cur.line, direct, /dev/.test(cur.dep ?? ""), /direct/.test(cur.dep ?? ""))); cur = null; }
  });
  return out;
};

const READERS: [RegExp, Reader][] = [
  [/^(?:package-lock|npm-shrinkwrap)\.json$/, npmLock],
  [/^pnpm-lock\.yaml$/, pnpmLock],
  [/^yarn\.lock$/, yarnLock],
  [/^(?:poetry|uv|pdm)\.lock$/, tomlPackages("PyPI")],
  [/^Pipfile\.lock$/, pipfileLock],
  [/^requirements[\w.-]*\.txt$/, requirements],
  [/^go\.mod$/, goMod],
  [/^Gemfile\.lock$/, gemfileLock],
  [/^composer\.lock$/, composerLock],
  [/^Cargo\.lock$/, tomlPackages("crates.io")],
  [/^packages\.lock\.json$/, nugetLock],
  [/\.(?:csproj|fsproj|vbproj)$|^Directory\.Packages\.props$/, csproj],
  [/^pom\.xml$/, pomXml],
  [/^gradle\.lockfile$|^build\.gradle(?:\.kts)?$/, gradle],
  [/^pubspec\.lock$/, pubspecLock],
];

/** Every package the repo pins, deduplicated per ecosystem × name × version; direct = named in a manifest. */
export function lockedPackages(root: string, files: string[]): { packages: DepPackage[]; lockfiles: string[]; manifests: Direct } {
  const direct = readDirect(root, files);
  const seen = new Map<string, DepPackage>();
  const lockfiles: string[] = [];
  // A requirements.txt next to a real lockfile adds nothing; same for a build.gradle next to gradle.lockfile.
  const has = new Set(files);
  for (const rel of files) {
    const name = base(rel);
    const reader = READERS.find(([re]) => re.test(name))?.[1];
    if (!reader) continue;
    const dir = dirOf(rel);
    if (/^requirements/.test(name) && ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"].some((l) => has.has(dir + l))) continue;
    if (/^build\.gradle/.test(name) && has.has(dir + "gradle.lockfile")) continue;
    if (/\.(?:cs|fs|vb)proj$/.test(name) && has.has(dir + "packages.lock.json")) continue;
    let text: string;
    try { text = readFileSync(join(root, rel), "utf8"); } catch { continue; }
    const found = reader(rel, text, direct);
    if (!found.length) continue;
    lockfiles.push(rel);
    for (const p of found) {
      const k = `${p.ecosystem}|${key(p.ecosystem, p.name)}@${p.version}`;
      const prev = seen.get(k);
      if (!prev || (p.direct && !prev.direct)) seen.set(k, p);
    }
  }
  return { packages: [...seen.values()], lockfiles, manifests: direct };
}

// ---------- OSV ----------

function severityOf(v: any): DepVuln["severity"] {
  const s = String(v?.database_specific?.severity ?? "").toUpperCase();
  if (s === "CRITICAL") return "Critical";
  if (s === "HIGH") return "High";
  if (s === "LOW") return "Low";
  if (s === "MODERATE" || s === "MEDIUM") return "Medium";
  // CVSS vector only: a rough bucket from network reach, privileges and impact.
  const vec = String(v?.severity?.find((x: any) => /CVSS/.test(x?.type))?.score ?? "");
  const high = (vec.match(/[CIA]:H/g) ?? []).length;
  if (/AV:N/.test(vec) && /PR:N/.test(vec) && high >= 2) return "Critical";
  if (high >= 1) return "High";
  return "Medium";
}

function fixedFor(v: any, p: DepPackage): string | null {
  const fixes: string[] = [];
  for (const a of v?.affected ?? []) {
    if (a?.package?.ecosystem !== p.ecosystem) continue;
    if (key(p.ecosystem, a?.package?.name ?? "") !== key(p.ecosystem, p.name)) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed && cmpVersion(e.fixed, p.version) > 0) fixes.push(e.fixed);
  }
  return fixes.sort(cmpVersion)[0] ?? null;
}

async function limitMap<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

// ---------- latest stable version per registry ----------

const goEscape = (mod: string) => mod.replace(/[A-Z]/g, (c) => "!" + c.toLowerCase());
const LATEST: Partial<Record<Ecosystem, { url: (name: string) => string; pick: (data: any) => string | undefined }>> = {
  npm: { url: (n) => `https://registry.npmjs.org/${n.replace("/", "%2F")}/latest`, pick: (d) => d?.version },
  PyPI: { url: (n) => `https://pypi.org/pypi/${encodeURIComponent(n)}/json`, pick: (d) => d?.info?.version },
  RubyGems: { url: (n) => `https://rubygems.org/api/v1/versions/${encodeURIComponent(n)}/latest.json`, pick: (d) => d?.version },
  "crates.io": { url: (n) => `https://crates.io/api/v1/crates/${encodeURIComponent(n)}`, pick: (d) => d?.crate?.max_stable_version },
  Packagist: { url: (n) => `https://repo.packagist.org/p2/${n}.json`, pick: (d) => {
    const list = Object.values<any>(d?.packages ?? {})[0] ?? [];
    return list.map((x: any) => String(x.version ?? "").replace(/^v/, "")).find((v: string) => /^\d/.test(v) && !parseVer(v)?.pre);
  } },
  Go: { url: (n) => `https://proxy.golang.org/${goEscape(n)}/@latest`, pick: (d) => String(d?.Version ?? "").replace(/^v/, "") },
  NuGet: { url: (n) => `https://api.nuget.org/v3-flatcontainer/${n.toLowerCase()}/index.json`, pick: (d) => (d?.versions ?? []).filter((v: string) => !parseVer(v)?.pre).pop() },
  Maven: { url: (n) => { const [g, a] = n.split(":"); return `https://search.maven.org/solrsearch/select?q=g:%22${encodeURIComponent(g)}%22+AND+a:%22${encodeURIComponent(a)}%22&rows=1&wt=json`; },
    pick: (d) => d?.response?.docs?.[0]?.latestVersion },
  Pub: { url: (n) => `https://pub.dev/api/packages/${encodeURIComponent(n)}`, pick: (d) => d?.latest?.version },
};

export interface DepOptions { fetch?: Fetch; timeoutMs?: number; maxLatestLookups?: number }

export async function checkDependencies(root: string, files: string[], opts: DepOptions = {}): Promise<{ hits: DepHit[]; status: DepStatus }> {
  const doFetch: Fetch = opts.fetch ?? (globalThis.fetch as unknown as Fetch);
  const timeout = opts.timeoutMs ?? 15000;
  const { packages, lockfiles, manifests } = lockedPackages(root, files);
  const status: DepStatus = {
    lockfiles, ecosystems: [...new Set(packages.map((p) => p.ecosystem))].sort(), packages: packages.length,
    vulnerable: 0, advisories: 0, outdated: 0, checked_at: new Date().toISOString(),
  };
  const hits: DepHit[] = [];
  if (!packages.length) return { hits, status };
  const errors: string[] = [];

  // 1. Which pinned versions have advisories (batch: ids only), 1000 per request.
  const vulnIds = new Map<DepPackage, Set<string>>();
  for (let k = 0; k < packages.length; k += 1000) {
    const chunk = packages.slice(k, k + 1000);
    try {
      const res = await doFetch(`${OSV}/querybatch`, {
        method: "POST", headers: { "content-type": "application/json", "user-agent": UA },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) throw new Error(`OSV answered ${res.status}`);
      const data = await res.json();
      (data?.results ?? []).forEach((r: any, i: number) => {
        const ids = (r?.vulns ?? []).map((v: any) => v.id).filter(Boolean);
        if (ids.length) vulnIds.set(chunk[i], new Set(ids));
      });
    } catch (e) {
      errors.push(`vulnerability lookup failed (${(e as Error).message})`);
      break;
    }
  }

  // 2. Details of each advisory (severity, summary, CVE alias, fixed version, date).
  const allIds = [...new Set([...vulnIds.values()].flatMap((s) => [...s]))];
  const details = new Map<string, any>();
  await limitMap(allIds, 8, async (id) => {
    try {
      const res = await doFetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { headers: { "user-agent": UA }, signal: AbortSignal.timeout(timeout) });
      if (res.ok) details.set(id, await res.json());
    } catch { /* counted below */ }
  });
  if (allIds.length && details.size < allIds.length) errors.push(`${allIds.length - details.size} advisory detail(s) could not be read`);

  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  for (const [p, ids] of vulnIds) {
    const raw: DepVuln[] = [...ids].map((id) => {
      const v = details.get(id);
      return {
        id, aliases: (v?.aliases ?? []).filter((a: string) => /^CVE-/.test(a)), summary: String(v?.summary ?? v?.details ?? "").split("\n")[0].slice(0, 140),
        severity: v ? severityOf(v) : "Medium", published: v?.published ? String(v.published).slice(0, 10) : null,
        fixed: v ? fixedFor(v, p) : null, url: `https://osv.dev/vulnerability/${id}`,
      };
    });
    // GitHub and the ecosystem's own database often publish the same CVE: one entry per CVE.
    const byCve = new Map<string, DepVuln>();
    for (const v of raw) {
      const k = v.aliases[0] ?? v.id;
      const prev = byCve.get(k);
      if (!prev) { byCve.set(k, v); continue; }
      byCve.set(k, {
        ...prev, severity: rank[v.severity] > rank[prev.severity] ? v.severity : prev.severity,
        fixed: [prev.fixed, v.fixed].filter((f): f is string => Boolean(f)).sort(cmpVersion).pop() ?? null,
        published: [prev.published, v.published].filter(Boolean).sort()[0] ?? null,
      });
    }
    const vulns = [...byCve.values()].sort((a, b) => rank[b.severity] - rank[a.severity] || String(b.published).localeCompare(String(a.published)));
    status.vulnerable++;
    status.advisories += vulns.length;
    const worst = vulns.reduce((a, b) => (rank[b.severity] > rank[a.severity] ? b : a));
    const fixes = vulns.map((v) => v.fixed).filter((f): f is string => Boolean(f)).sort(cmpVersion);
    const upgrade = fixes.length ? fixes[fixes.length - 1] : null;
    const manifest = p.direct ? manifests.get(key(p.ecosystem, p.name)) : undefined;
    const at = manifest ?? { rel: p.lockfile, line: p.line };
    const label = p.name === "stdlib" && p.ecosystem === "Go" ? `Go ${p.version} (standard library)` : `${p.name}@${p.version}`;
    const names = vulns.slice(0, 5).map((v) => `${v.aliases[0] ?? v.id}${v.published ? ` (${v.published})` : ""}`).join(", ") +
      (vulns.length > 5 ? `, +${vulns.length - 5} more` : "");
    hits.push({
      id: "SEC050",
      title: `${label} has ${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"}${worst.summary ? `: ${worst.summary}` : ""}`,
      severity: p.dev ? (worst.severity === "Critical" ? "High" : worst.severity === "High" ? "Medium" : "Low") : worst.severity,
      confidence: "high", controls: [15], rel: at.rel, line: at.line,
      evidence: `${label}${p.name === "stdlib" ? "" : ` (${p.ecosystem}${p.direct ? "" : ", indirect"}${p.dev ? ", dev" : ""})`}: ${names}${upgrade ? ` · fixed in ${upgrade}` : " · no fixed version yet"}`,
      guidance: upgrade
        ? `Upgrade ${p.name === "stdlib" ? "Go" : p.name} to ${upgrade} or later${p.direct ? "" : " (it comes in through another package: update that one, or pin it with your package manager's override)"}. Details: ${vulns.slice(0, 5).map((v) => v.url).join(" ")}`
        : `No fixed release yet: check whether the vulnerable code path is used, and replace or isolate the package. Details: ${vulns.slice(0, 5).map((v) => v.url).join(" ")}`,
    });
  }

  // 3. How far direct dependencies are behind (latest stable release on each registry).
  const directPkgs = [...new Map(packages.filter((p) => p.direct && p.name !== "stdlib" && LATEST[p.ecosystem])
    .map((p) => [key(p.ecosystem, p.name), p])).values()].slice(0, opts.maxLatestLookups ?? 300);
  let registryFailed = 0;
  await limitMap(directPkgs, 8, async (p) => {
    const reg = LATEST[p.ecosystem]!;
    try {
      const res = await doFetch(reg.url(p.name), { headers: { accept: "application/json", "user-agent": UA }, signal: AbortSignal.timeout(timeout) });
      if (!res.ok) { registryFailed++; return; }
      const latest = String(reg.pick(await res.json()) ?? "");
      const cur = parseVer(p.version), next = parseVer(latest);
      // A pre-release tagged latest (8.0.0-rc.27) is not something to upgrade to yet.
      if (!cur || !next || next.pre || next.major <= cur.major) return;
      status.outdated++;
      const behind = next.major - cur.major;
      const at = manifests.get(key(p.ecosystem, p.name)) ?? { rel: p.lockfile, line: p.line };
      hits.push({
        id: "SEC051", title: `${p.name} is ${behind} major version${behind === 1 ? "" : "s"} behind (${p.version} → ${latest})`,
        severity: behind >= 2 ? "Low" : "Informational", confidence: "high", controls: [15], rel: at.rel, line: at.line,
        evidence: `${p.name} (${p.ecosystem}): using ${p.version}, latest ${latest}`,
        guidance: "Old major versions stop getting security fixes. Plan the upgrade (read the changelog for breaking changes) before an advisory forces it.",
      });
    } catch { registryFailed++; }
  });
  if (registryFailed) errors.push(`latest version unknown for ${registryFailed} package(s)`);
  if (errors.length) status.error = errors.join("; ");
  hits.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : a.line - b.line));
  return { hits, status };
}
