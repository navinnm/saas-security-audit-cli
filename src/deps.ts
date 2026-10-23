/**
 * Dependency check: exact versions from the lockfiles (package-lock.json, pnpm-lock.yaml, yarn.lock),
 * known vulnerabilities from OSV.dev (GitHub advisories, npm, CVE aliases, the version that fixes each),
 * and how far each direct dependency is behind its latest release on the npm registry.
 *
 * Network: only package names and versions are sent, to api.osv.dev and registry.npmjs.org.
 * Turned off with --offline or SAAS_AUDIT_OFFLINE=1; any network failure is reported, never fatal.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface DepPackage { name: string; version: string; lockfile: string; line: number; direct: boolean; dev: boolean }
export interface DepVuln {
  id: string; aliases: string[]; summary: string; severity: "Critical" | "High" | "Medium" | "Low";
  published: string | null; fixed: string | null; url: string;
}
export interface DepHit {
  id: "SEC050" | "SEC051"; title: string; severity: string; confidence: string; controls: number[];
  rel: string; line: number; evidence: string; guidance: string;
}
export interface DepStatus {
  lockfiles: string[]; packages: number; vulnerable: number; advisories: number; outdated: number;
  checked_at: string; error?: string;
}

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<any> }>;

const OSV = "https://api.osv.dev/v1";
const REGISTRY = "https://registry.npmjs.org";
const UA = "saas-security-audit (dependency check; sends package names and versions only)";

// ---------- versions ----------

const parseVer = (v: string) => {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v.trim());
  return m ? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ?? "" } : null;
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

// ---------- lockfiles ----------

const lineOf = (text: string, needle: string) => {
  const i = text.indexOf(needle);
  return i < 0 ? 1 : text.slice(0, i).split("\n").length;
};

function fromPackageLock(rel: string, text: string, direct: Set<string>): DepPackage[] {
  let data: any;
  try { data = JSON.parse(text); } catch { return []; }
  const out: DepPackage[] = [];
  if (data.packages && typeof data.packages === "object") {
    for (const [path, info] of Object.entries<any>(data.packages)) {
      if (!path || !info?.version || info.link) continue;
      const name = info.name ?? path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ name, version: info.version, lockfile: rel, line: lineOf(text, `"${path}"`), direct: direct.has(name) && path === `node_modules/${name}`, dev: Boolean(info.dev) });
    }
  } else if (data.dependencies) {
    const walk = (deps: Record<string, any>, top: boolean) => {
      for (const [name, info] of Object.entries<any>(deps)) {
        if (info?.version && !/^(?:file|link|git)/.test(info.version)) {
          out.push({ name, version: info.version, lockfile: rel, line: lineOf(text, `"${name}"`), direct: top && direct.has(name), dev: Boolean(info.dev) });
        }
        if (info?.dependencies) walk(info.dependencies, false);
      }
    };
    walk(data.dependencies, true);
  }
  return out;
}

function fromPnpmLock(rel: string, text: string, direct: Set<string>): DepPackage[] {
  const out: DepPackage[] = [];
  let inPackages = false;
  text.split(/\r?\n/).forEach((line, i) => {
    if (/^\S/.test(line)) inPackages = /^packages:\s*$/.test(line);
    if (!inPackages) return;
    // v9: `  next@16.4.2:` / `  '@babel/parser@7.29.8':`; v5/v6: `  /next@16.4.2:` / `  /next/13.0.0:`
    const m = /^ {2}'?\/?((?:@[^@/\s']+\/)?[^@/\s'(]+)[@/](\d[^(':\s]*)/.exec(line);
    if (m) out.push({ name: m[1], version: m[2], lockfile: rel, line: i + 1, direct: direct.has(m[1]), dev: false });
  });
  return out;
}

function fromYarnLock(rel: string, text: string, direct: Set<string>): DepPackage[] {
  const out: DepPackage[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const head = lines[i];
    if (!head || /^\s|^#/.test(head) || !head.trimEnd().endsWith(":")) continue;
    const spec = head.split(",")[0].replace(/^"|":?$|:$/g, "").trim();
    const at = spec.lastIndexOf("@");
    if (at <= 0) continue;
    const name = spec.slice(0, at).replace(/^"/, "");
    for (let j = i + 1; j < lines.length && /^\s/.test(lines[j]); j++) {
      const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(lines[j]);
      if (v) { out.push({ name, version: v[1], lockfile: rel, line: i + 1, direct: direct.has(name), dev: false }); break; }
    }
  }
  return out;
}

const LOCKFILES: Record<string, typeof fromPackageLock> = {
  "package-lock.json": fromPackageLock, "npm-shrinkwrap.json": fromPackageLock, "pnpm-lock.yaml": fromPnpmLock, "yarn.lock": fromYarnLock,
};

/** Every package (name@version) the repo's lockfiles pin, deduplicated; direct = named in a package.json. */
export function lockedPackages(root: string, files: string[]): { packages: DepPackage[]; lockfiles: string[]; manifests: Map<string, { rel: string; line: number }> } {
  const direct = new Set<string>();
  const manifests = new Map<string, { rel: string; line: number }>();
  for (const rel of files.filter((f) => f === "package.json" || f.endsWith("/package.json"))) {
    try {
      const text = readFileSync(join(root, rel), "utf8");
      const data = JSON.parse(text);
      for (const key of ["dependencies", "devDependencies", "optionalDependencies"]) {
        for (const [name, range] of Object.entries<string>(data?.[key] ?? {})) {
          if (typeof range === "string" && /^(?:workspace|file|link|git|https?):/.test(range)) continue;
          direct.add(name);
          if (!manifests.has(name)) manifests.set(name, { rel, line: lineOf(text, `"${name}"`) });
        }
      }
    } catch { /* not JSON */ }
  }
  const seen = new Map<string, DepPackage>();
  const lockfiles: string[] = [];
  for (const rel of files) {
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    const parse = LOCKFILES[base];
    if (!parse) continue;
    let text: string;
    try { text = readFileSync(join(root, rel), "utf8"); } catch { continue; }
    lockfiles.push(rel);
    for (const p of parse(rel, text, direct)) {
      const key = `${p.name}@${p.version}`;
      const prev = seen.get(key);
      if (!prev) seen.set(key, p);
      else if (p.direct && !prev.direct) seen.set(key, { ...p });
    }
  }
  return { packages: [...seen.values()], lockfiles, manifests };
}

// ---------- OSV ----------

function severityOf(v: any): DepVuln["severity"] {
  const s = String(v?.database_specific?.severity ?? "").toUpperCase();
  if (s === "CRITICAL") return "Critical";
  if (s === "HIGH") return "High";
  if (s === "LOW") return "Low";
  if (s === "MODERATE" || s === "MEDIUM") return "Medium";
  // CVSS vector only: estimate from impact letters (no full calculator needed for a rough bucket).
  const vec = String(v?.severity?.find((x: any) => /CVSS/.test(x?.type))?.score ?? "");
  const high = (vec.match(/[CIA]:H/g) ?? []).length;
  if (/AV:N/.test(vec) && /PR:N/.test(vec) && high >= 2) return "Critical";
  if (high >= 1) return "High";
  return "Medium";
}

function fixedFor(v: any, name: string, version: string): string | null {
  const fixes: string[] = [];
  for (const a of v?.affected ?? []) {
    if (a?.package?.ecosystem !== "npm" || a?.package?.name !== name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed && cmpVersion(e.fixed, version) > 0) fixes.push(e.fixed);
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

export interface DepOptions { fetch?: Fetch; timeoutMs?: number }

export async function checkDependencies(root: string, files: string[], opts: DepOptions = {}): Promise<{ hits: DepHit[]; status: DepStatus }> {
  const doFetch: Fetch = opts.fetch ?? (globalThis.fetch as unknown as Fetch);
  const timeout = opts.timeoutMs ?? 15000;
  const { packages, lockfiles, manifests } = lockedPackages(root, files);
  const status: DepStatus = { lockfiles, packages: packages.length, vulnerable: 0, advisories: 0, outdated: 0, checked_at: new Date().toISOString() };
  const hits: DepHit[] = [];
  if (!packages.length) return { hits, status };
  const errors: string[] = [];

  // 1. Which pinned versions have advisories (batch: ids only), 1000 per request.
  const vulnIds = new Map<string, Set<string>>();
  for (let k = 0; k < packages.length; k += 1000) {
    const chunk = packages.slice(k, k + 1000);
    try {
      const res = await doFetch(`${OSV}/querybatch`, {
        method: "POST", headers: { "content-type": "application/json", "user-agent": UA },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })) }),
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) throw new Error(`OSV answered ${res.status}`);
      const data = await res.json();
      (data?.results ?? []).forEach((r: any, i: number) => {
        const ids = (r?.vulns ?? []).map((v: any) => v.id).filter(Boolean);
        if (ids.length) vulnIds.set(`${chunk[i].name}@${chunk[i].version}`, new Set(ids));
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

  for (const p of packages) {
    const ids = vulnIds.get(`${p.name}@${p.version}`);
    if (!ids) continue;
    const vulns: DepVuln[] = [...ids].map((id) => {
      const v = details.get(id);
      return {
        id, aliases: (v?.aliases ?? []).filter((a: string) => /^CVE-/.test(a)), summary: String(v?.summary ?? v?.details ?? "").split("\n")[0].slice(0, 140),
        severity: v ? severityOf(v) : "Medium", published: v?.published ? String(v.published).slice(0, 10) : null,
        fixed: v ? fixedFor(v, p.name, p.version) : null, url: `https://osv.dev/vulnerability/${id}`,
      };
    });
    status.vulnerable++;
    status.advisories += vulns.length;
    const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    const worst = vulns.reduce((a, b) => (rank[b.severity] > rank[a.severity] ? b : a));
    const fixes = vulns.map((v) => v.fixed).filter((f): f is string => Boolean(f)).sort(cmpVersion);
    const upgrade = fixes.length ? fixes[fixes.length - 1] : null;
    const at = p.direct && manifests.get(p.name) ? manifests.get(p.name)! : { rel: p.lockfile, line: p.line };
    const names = vulns.map((v) => `${v.aliases[0] ?? v.id}${v.published ? ` (${v.published})` : ""}`).join(", ");
    hits.push({
      id: "SEC050",
      title: `${p.name}@${p.version} has ${vulns.length} known vulnerabilit${vulns.length === 1 ? "y" : "ies"}${worst.summary ? `: ${worst.summary}` : ""}`,
      severity: p.dev ? (worst.severity === "Critical" ? "High" : worst.severity === "High" ? "Medium" : "Low") : worst.severity,
      confidence: "high", controls: [15], rel: at.rel, line: at.line,
      evidence: `${p.name}@${p.version}${p.direct ? "" : " (indirect)"}${p.dev ? " (dev)" : ""}: ${names}${upgrade ? ` · fixed in ${upgrade}` : " · no fixed version yet"}`,
      guidance: upgrade
        ? `Upgrade ${p.name} to ${upgrade} or later${p.direct ? "" : " (it comes in through another package: update that one, or pin it with overrides / pnpm.overrides / resolutions)"}. Details: ${vulns.map((v) => v.url).join(" ")}`
        : `No fixed release yet: check whether the vulnerable code path is used, and replace or isolate the package. Details: ${vulns.map((v) => v.url).join(" ")}`,
    });
  }

  // 3. How far direct dependencies are behind (latest on npm).
  const directPkgs = [...new Map(packages.filter((p) => p.direct).map((p) => [p.name, p])).values()];
  let registryFailed = 0;
  await limitMap(directPkgs, 8, async (p) => {
    try {
      const res = await doFetch(`${REGISTRY}/${p.name.replace("/", "%2F")}/latest`, { headers: { accept: "application/json", "user-agent": UA }, signal: AbortSignal.timeout(timeout) });
      if (!res.ok) { registryFailed++; return; }
      const latest = String((await res.json())?.version ?? "");
      const cur = parseVer(p.version), next = parseVer(latest);
      // A pre-release tagged latest (8.0.0-rc.27) is not something to upgrade to yet.
      if (!cur || !next || next.pre || next.major <= cur.major) return;
      status.outdated++;
      const behind = next.major - cur.major;
      const at = manifests.get(p.name) ?? { rel: p.lockfile, line: p.line };
      hits.push({
        id: "SEC051", title: `${p.name} is ${behind} major version${behind === 1 ? "" : "s"} behind (${p.version} → ${latest})`,
        severity: behind >= 2 ? "Low" : "Informational", confidence: "high", controls: [15], rel: at.rel, line: at.line,
        evidence: `${p.name}: using ${p.version}, latest ${latest}`,
        guidance: "Old major versions stop getting security fixes. Plan the upgrade (read the changelog for breaking changes) before an advisory forces it.",
      });
    } catch { registryFailed++; }
  });
  if (registryFailed) errors.push(`latest version unknown for ${registryFailed} package(s)`);
  if (errors.length) status.error = errors.join("; ");
  hits.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : a.line - b.line));
  return { hits, status };
}
