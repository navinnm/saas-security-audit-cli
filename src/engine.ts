/**
 * Read-only scan engine — a faithful port of the plugin's scripts/scan.py `scan()`.
 * Never executes target code and makes no network requests.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { standardsFor, type FindingStandards } from "./standards.js";
import { analyzeFlows, FLOW_EXTS, type FlowFile } from "./flow.js";
import { checkDependencies, type DepStatus } from "./deps.js";
import { analyzeInfra } from "./infra.js";
import {
  R, RULES, SECRET_FORMATS, RE, CONTROL_SIGNALS, SECRET_GUIDANCE, SKIP_DIRS, CODE_EXTS, CONFIG_EXTS,
  SQL_EXTS, DOC_EXTS, CONFIG_NAMES, LOCKFILES,
} from "./rules.js";

export interface Finding {
  id: string; title: string; severity: string; confidence: string; controls: number[];
  status: string; file: string; line: number; evidence: string; guidance: string; context: string;
  fingerprint: string; suppressed?: string; standards?: FindingStandards;
}

export interface Signal { source: string[]; source_count: number; test_count: number }

export interface ScanState {
  files_scanned: number; skipped_large_lines: number; suppressed: Finding[];
  signals: Record<number, Signal>; manifests: string[];
  env_files: { file: string; gitignored: boolean; example: boolean }[];
  test_files: number; ci_files: string[]; packages: Record<string, [number, string]>;
  /** Dependency check (deps.ts): what was checked online, or why it wasn't. */
  deps?: DepStatus | { skipped: string };
  /** Whether test files and gitignored env files were read (--include-tests). */
  tests_read?: boolean;
}

export interface ScanEvents {
  onDiscover?(total: number): void;
  /** After discovery: files that will be analysed vs skipped by type and ignore rules. */
  onClassify?(analysable: number, skipped: number): void;
  onFile?(rel: string, index: number, total: number): void;
  /** Progress through the analysable files only. */
  onAnalyse?(rel: string, done: number, total: number): void;
  onFinding?(f: Finding): void;
  onPhase?(phase: string): void;
}

export interface ScanOptions {
  /** Files from an earlier preflight(), so the tree isn't walked twice. */
  files?: WalkedFile[];
  /** Set `aborted` to stop analysing; the scan returns what it found so far. */
  signal?: { aborted: boolean };
  /** Also read test files and gitignored local env files (skipped by default: not shipped). */
  includeTests?: boolean;
  /** Skip the online dependency check (also SAAS_AUDIT_OFFLINE=1). */
  offline?: boolean;
}

export type WalkedFile = { abs: string; rel: string; name: string };

export interface Preflight {
  files: WalkedFile[];
  total: number;
  analysable: number;
  skipped: number;
  /** Security-relevant packages found in manifests: name → [control, role]. */
  packages: Record<string, [number, string]>;
}

const COMMENT_PREFIXES = R.comment_prefixes;
const CI_NAMES = new Set([".gitlab-ci.yml", "Jenkinsfile", "bitbucket-pipelines.yml", ".circleci"]);

// ---------- Python compatibility helpers ----------

/** pathlib.PurePath.suffix */
export function pySuffix(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 && i < name.length - 1 ? name.slice(i) : "";
}

/** str.splitlines() */
export function splitlines(text: string): string[] {
  const parts = text.split(/\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/);
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  return parts;
}

const PY_WS = /^[\s\x1c-\x1f\x85]+|[\s\x1c-\x1f\x85]+$/g;
const pyStrip = (s: string) => s.replace(PY_WS, "");
const pyLstrip = (s: string) => s.replace(/^[\s\x1c-\x1f\x85]+/, "");
const cpLen = (s: string) => (s.length <= R.max_line ? s.length : [...s].length);
const cpSlice = (s: string, n: number) => (s.length <= n ? s : [...s].slice(0, n).join(""));

/** fnmatch.fnmatch (POSIX: case-sensitive, '*' matches '/'). */
export function fnmatch(name: string, pat: string): boolean {
  let re = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      let j = i + 1;
      if (j < pat.length && pat[j] === "!") j++;
      if (j < pat.length && pat[j] === "]") j++;
      while (j < pat.length && pat[j] !== "]") j++;
      if (j >= pat.length) re += "\\[";
      else {
        let stuff = pat.slice(i + 1, j).replace(/\\/g, "\\\\");
        if (stuff.startsWith("!")) stuff = "^" + stuff.slice(1);
        else if (stuff.startsWith("^")) stuff = "\\" + stuff;
        re += `[${stuff}]`;
        i = j;
      }
    } else re += c.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
  }
  return new RegExp(`^(?:${re})$`, "s").test(name);
}

/** Python `rx.sub(lambda m: <prefix> + "[REDACTED]" + <suffix>)` that blanks one named group. */
function subWithGroup(re: RegExp, text: string, group: string, keepAfter: boolean): string {
  let out = "";
  let last = 0;
  for (const m of text.matchAll(re)) {
    const start = m.index!;
    const end = start + m[0].length;
    const span = m.indices?.groups?.[group];
    out += text.slice(last, start);
    out += span ? text.slice(start, span[0]) + "[REDACTED]" + (keepAfter ? text.slice(span[1], end) : "") : m[0];
    last = end;
  }
  return out + text.slice(last);
}

// ---------- secrets ----------

export function isPlaceholder(value: string): boolean {
  return RE.placeholder.test(value) || ["process.env", "os.environ", "env(", "ENV["].some((p) => value.startsWith(p));
}

export function jwtRole(payload: string): unknown {
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data.role ?? null : null;
  } catch {
    return null;
  }
}

const ENV_CRED_D = new RegExp(RE.envCred.source, RE.envCred.flags + "d");

export function redact(line: string): string {
  for (const fmt of SECRET_FORMATS) {
    line = fmt.groups.has("v") ? subWithGroup(fmt.re, line, "v", true) : line.replace(fmt.re, "[REDACTED_TOKEN]");
  }
  line = subWithGroup(RE.quotedCredAll, line, "v", true);
  // KEY=value lines: hide everything after the "=", not only up to the first space
  // (a ZeptoMail token is "Zoho-enczapikey <key>": the key itself comes after the space).
  const env = ENV_CRED_D.exec(line)?.indices?.groups?.v;
  if (env) line = line.slice(0, env[0]) + "[REDACTED]";
  line = line.replace(RE.bearerAll, "Bearer [REDACTED]");
  return cpSlice(pyStrip(line), 240);
}

type Hit = [string, string, string, string];

export function secretHits(line: string, category: string): Hit[] {
  for (const fmt of SECRET_FORMATS) {
    for (const m of line.matchAll(fmt.re)) {
      let sev = fmt.severity;
      let label = fmt.title;
      const gr = m.groups ?? {};
      if (fmt.groups.has("v") && isPlaceholder(gr.v ?? "")) continue;
      if (fmt.groups.has("host") && RE.localHost.test(gr.host ?? "")) {
        sev = "Low";
        label = fmt.title + " (local/dev host)";
      }
      if (fmt.groups.has("payload")) {
        const role = jwtRole(gr.payload ?? "");
        if (role === "anon") continue;
        if (role === "service_role") {
          sev = "Critical";
          label = "Supabase service_role JWT";
        }
      }
      return [["SEC012", "Known-format secret: " + label, sev, "high"]];
    }
  }
  const m = (category === "env" ? RE.envCred : RE.quotedCred).exec(line);
  if (m && !isPlaceholder(m.groups?.v ?? "")) return [["SEC001", "Possible hardcoded credential", "High", "medium"]];
  return [];
}

// ---------- findings ----------

export function fingerprint(f: Pick<Finding, "id" | "file" | "evidence">): string {
  const basis = [f.id, f.file, f.evidence.replace(/\s+/g, " ")].join("|");
  return createHash("sha256").update(basis, "utf8").digest("hex").slice(0, 16);
}

export function makeFinding(id: string, title: string, severity: string, confidence: string, controls: number[],
  file: string, line: number, evidence: string, guidance: string, context: string): Finding {
  const f = { id, title, severity, confidence, controls: [...controls], status: "NEEDS_REVIEW", file, line, evidence, guidance, context,
    standards: standardsFor(id) } as Finding;
  f.fingerprint = fingerprint(f);
  return f;
}

export const gateCounts = (f: Finding) => f.context === "source" || (f.context === "test" && f.id === "SEC012");

// ---------- files ----------

export function classify(name: string, suffix: string): string | null {
  if (LOCKFILES.has(name) || name.endsWith(".min.js") || name.endsWith(".min.css") || name.endsWith(".map")) return null;
  if (name === ".env" || name.startsWith(".env.") || name.endsWith(".env")) return "env";
  if (CODE_EXTS.has(suffix)) return "code";
  if (CONFIG_EXTS.has(suffix) || CONFIG_NAMES.has(name) || name.startsWith("Dockerfile")) return "config";
  if (SQL_EXTS.has(suffix)) return "sql";
  if (DOC_EXTS.has(suffix)) return "doc";
  return null;
}

function readLines(path: string): string[] | null {
  let data: Buffer;
  try {
    if (statSync(path).size > R.max_bytes) return null;
    data = readFileSync(path);
  } catch {
    return null;
  }
  if (data.subarray(0, 8192).includes(0)) return null;
  return splitlines(new TextDecoder("utf-8", { fatal: false }).decode(data));
}

function parseGitignore(root: string): string[] {
  try {
    const lines = splitlines(new TextDecoder().decode(readFileSync(join(root, ".gitignore"))));
    return lines.map(pyStrip).filter((l) => l && !l.startsWith("#") && !l.startsWith("!"));
  } catch {
    return [];
  }
}

export function isIgnored(rel: string, patterns: string[]): boolean {
  const name = rel.split("/").pop() as string;
  for (const pat of patterns) {
    let p = pat.replace(/\/+$/, "");
    if (p.startsWith("/") || p.includes("/")) {
      p = p.replace(/^\/+/, "");
      if (fnmatch(rel, p) || rel.startsWith(p + "/")) return true;
    } else if (fnmatch(name, p) || rel.split("/").slice(0, -1).some((part) => fnmatch(part, p))) return true;
  }
  return false;
}

function recordPackages(name: string, lines: string[], packages: ScanState["packages"]) {
  const found = new Set<string>();
  if (name === "package.json" || name === "composer.json") {
    try {
      const data = JSON.parse(lines.join("\n"));
      for (const key of ["dependencies", "devDependencies", "require", "require-dev"]) {
        const v = data?.[key];
        if (v && typeof v === "object" && !Array.isArray(v)) Object.keys(v).forEach((k) => found.add(k.toLowerCase()));
      }
    } catch { /* not JSON */ }
  } else {
    for (const line of lines) {
      const m = /^\s*(?:gem\s+["']|require\s+)?["']?([A-Za-z0-9_.@/-]+)/.exec(line);
      if (m) found.add(m[1].toLowerCase());
    }
  }
  for (const pkg of found) {
    const sp = R.security_packages[pkg];
    if (sp) packages[pkg] = [sp.control, sp.role];
  }
}

/**
 * os.walk(top-down, followlinks=False) order: files of a directory, then its subdirectories, both sorted.
 * Folders that a .gitignore (the root one or one further down) leaves out are skipped: build output,
 * generated clients and bundles are not the app's own source. Ignored files are still read (env files).
 */
function walk(root: string): WalkedFile[] {
  const out: { abs: string; rel: string; name: string }[] = [];
  const ignores: { base: string; pats: string[] }[] = [];
  const dirIgnored = (rel: string) => ignores.some(({ base, pats }) =>
    (base === "" || rel.startsWith(base + "/")) && isIgnored(base ? rel.slice(base.length + 1) : rel, pats));
  const visit = (dir: string, relDir: string) => {
    const pats = parseGitignore(dir);
    if (pats.length) ignores.push({ base: relDir, pats });
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const dirs: string[] = [];
    const files: string[] = [];
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !dirIgnored(relDir ? `${relDir}/${e.name}` : e.name)) dirs.push(e.name);
      } else if (e.isFile()) files.push(e.name);
    }
    const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
    for (const name of files.sort(cmp)) out.push({ abs: join(dir, name), rel: relDir ? `${relDir}/${name}` : name, name });
    for (const name of dirs.sort(cmp)) visit(join(dir, name), relDir ? `${relDir}/${name}` : name);
  };
  visit(root, "");
  return out;
}

/** A report this scanner wrote (Markdown or JSON); re-scanning it would flag quoted evidence. */
export function isOwnReport(lines: string[]): boolean {
  const head = lines.slice(0, 4).join("\n");
  return head.startsWith(R.report_markdown_header) || head.includes(R.report_json_marker);
}

export function newState(): ScanState {
  const signals: Record<number, Signal> = {};
  for (const [cid] of CONTROL_SIGNALS) signals[cid] = { source: [], source_count: 0, test_count: 0 };
  return { files_scanned: 0, skipped_large_lines: 0, suppressed: [], signals, manifests: [], env_files: [],
    test_files: 0, ci_files: [], packages: {} };
}

const isDir = (p: string) => { try { return statSync(p).isDirectory(); } catch { return false; } };
const tick = () => new Promise<void>((r) => setImmediate(r));

const isAnalysable = (name: string) => classify(name, pySuffix(name).toLowerCase()) !== null;

/** Fast pre-pass for the welcome screen: walk the tree, classify files, read manifests for the stack. */
export function preflight(root: string): Preflight {
  const files = walk(root);
  const analysable = files.filter((f) => isAnalysable(f.name)).length;
  const packages: Preflight["packages"] = {};
  for (const f of files) {
    if (!R.manifests[f.name]) continue;
    const lines = readLines(f.abs);
    if (lines) recordPackages(f.name, lines, packages);
  }
  return { files, total: files.length, analysable, skipped: files.length - analysable, packages };
}

export async function scan(root: string, state: ScanState = newState(), ev: ScanEvents = {}, opts: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const emit = (f: Finding) => { findings.push(f); ev.onFinding?.(f); };
  const ignorePats = parseGitignore(root);
  const schemaFiles: [string, string, string[], boolean][] = [];
  const webhookFiles: [string, number, boolean, boolean][] = [];
  /** JS/TS application source for the code-flow analysis (flow.ts). */
  const flowFiles: (FlowFile & { lines: string[] })[] = [];
  const supabase = isDir(join(root, "supabase"));

  ev.onPhase?.("discover");
  const files = opts.files ?? walk(root);
  state.tests_read = Boolean(opts.includeTests);
  ev.onDiscover?.(files.length);
  ev.onPhase?.("classify");
  const analysableTotal = files.filter((f) => isAnalysable(f.name)).length;
  ev.onClassify?.(analysableTotal, files.length - analysableTotal);
  ev.onPhase?.("scan");
  let lastYield = Date.now();
  let analysed = 0;

  for (let idx = 0; idx < files.length; idx++) {
    if (opts.signal?.aborted) break;
    const { abs, rel, name } = files[idx];
    ev.onFile?.(rel, idx, files.length);
    if (isAnalysable(name)) ev.onAnalyse?.(rel, ++analysed, analysableTotal);
    if (Date.now() - lastYield > 12) {
      await tick();
      lastYield = Date.now();
    }
    if (R.manifests[name]) state.manifests.push(rel);
    if (rel.startsWith(".github/workflows/") || CI_NAMES.has(name)) state.ci_files.push(rel);
    const ext = pySuffix(name).toLowerCase();
    const category = classify(name, ext);
    if (category === null) continue;
    const inTest = RE.testPath.test(rel);
    // Tests and gitignored local env files don't ship: counted, not read (unless asked for).
    const localEnv = category === "env" && !RE.exampleEnv.test(name) && isIgnored(rel, ignorePats);
    if (!opts.includeTests && (inTest || localEnv)) {
      if (inTest && category === "code") state.test_files++;
      if (localEnv) state.env_files.push({ file: rel, gitignored: true, example: false });
      continue;
    }
    const lines = readLines(abs);
    if (lines === null || isOwnReport(lines)) continue;
    state.files_scanned++;
    if (inTest && category === "code") state.test_files++;
    if (category === "code" && !inTest && FLOW_EXTS.has(ext)) flowFiles.push({ rel, ext, text: lines.join("\n"), lines });
    let context = inTest ? "test" : "source";
    if (category === "env") {
      const example = RE.exampleEnv.test(name);
      const ignored = isIgnored(rel, ignorePats);
      state.env_files.push({ file: rel, gitignored: ignored, example });
      if (ignored && !example) context = "ignored-local-env";
    }
    if (R.manifests[name]) recordPackages(name, lines, state.packages);
    let firstWebhookLine: number | null = category === "code" && !inTest && rel.toLowerCase().includes("webhook") ? 1 : null;

    for (let i = 0; i < lines.length; i++) {
      const number = i + 1;
      const line = lines[i];
      if (cpLen(line) > R.max_line) {
        state.skipped_large_lines++;
        continue;
      }
      const isComment = COMMENT_PREFIXES.some((p) => pyLstrip(line).startsWith(p)) && category !== "env";
      const hits: [string, string, string, string, number[], string][] =
        secretHits(line, category).map(([id, title, sev, conf]) => [id, title, sev, conf, [15], SECRET_GUIDANCE[id]]);
      for (const rule of RULES) {
        if (rule.scope.has(category) && !(isComment && rule.skipComments) &&
            rule.patterns.some((p) => (p.exts === null || p.exts.has(ext)) && p.re.test(line))) {
          hits.push([rule.id, rule.title, rule.severity, rule.confidence, rule.controls, rule.guidance]);
        }
      }
      if (hits.length) {
        const sup = RE.suppress.exec(line) ?? (number > 1 ? RE.suppress.exec(lines[number - 2]) : null);
        const evidence = redact(line);
        const ids = sup ? (sup.groups?.ids ?? "").split(",").map(pyStrip).filter(Boolean) : [];
        for (const [id, title, sev, conf, controls, guidance] of hits) {
          const f = makeFinding(id, title, sev, conf, controls, rel, number, evidence, guidance, context);
          if (sup && (!ids.length || ids.includes(id))) {
            f.suppressed = pyStrip(sup.groups?.reason ?? "") || "no reason given";
            state.suppressed.push(f);
          } else emit(f);
        }
      }
      if ((category === "code" || category === "config" || category === "sql") && !isComment) {
        for (const [cid, re] of CONTROL_SIGNALS) {
          if (re.test(line)) {
            const sig = state.signals[cid];
            if (inTest) sig.test_count++;
            else {
              sig.source_count++;
              if (sig.source.length < R.max_signal_locations && !sig.source.some((s) => s.startsWith(rel + ":"))) {
                sig.source.push(`${rel}:${number}`);
              }
            }
          }
        }
      }
      if (category === "code" && !inTest && firstWebhookLine === null && RE.webhookRoute.test(line)) firstWebhookLine = number;
    }
    if (category === "sql" || ext === ".prisma" || (category === "code" && lines.some((l) => l.includes("pgTable(")))) {
      schemaFiles.push([rel, ext, lines, inTest]);
    }
    if (firstWebhookLine !== null) {
      const text = lines.join("\n");
      webhookFiles.push([rel, firstWebhookLine, RE.webhookVerify.test(text), RE.webhookIdempotency.test(text)]);
    }
  }

  ev.onPhase?.("analyze");
  // Code-flow analysis (SEC044–SEC049). SAAS_AUDIT_ENGINE=regex turns it off (line rules only).
  if (process.env.SAAS_AUDIT_ENGINE !== "regex" && !opts.signal?.aborted) {
    const byRel = new Map(flowFiles.map((f) => [f.rel, f.lines]));
    for (const h of analyzeFlows(root, flowFiles)) {
      const src = byRel.get(h.rel) ?? [];
      const at = src[h.line - 1] ?? "";
      const f = makeFinding(h.id, h.title, h.severity, h.confidence, h.controls, h.rel, h.line, redact(at), h.guidance, "source");
      const sup = RE.suppress.exec(at) ?? (h.line > 1 ? RE.suppress.exec(src[h.line - 2] ?? "") : null);
      const ids = sup ? (sup.groups?.ids ?? "").split(",").map(pyStrip).filter(Boolean) : [];
      if (sup && (!ids.length || ids.includes(h.id))) {
        f.suppressed = pyStrip(sup.groups?.reason ?? "") || "no reason given";
        state.suppressed.push(f);
      } else emit(f);
    }
  }
  const rlsApp = supabase || Object.keys(state.packages).some((p) => p.startsWith("@supabase/"));
  analyzeSchemaFiles(schemaFiles, rlsApp).forEach(emit);
  // Architecture: Dockerfiles, compose, Kubernetes, CI workflows, Terraform, database configs.
  if (!opts.signal?.aborted) {
    const cache = new Map<string, string[]>();
    for (const h of analyzeInfra(root, files.map((f) => f.rel).filter((r) => !RE.testPath.test(r)))) {
      if (!cache.has(h.rel)) cache.set(h.rel, readLines(join(root, h.rel)) ?? []);
      const src = cache.get(h.rel)!;
      const at = src[h.line - 1] ?? "";
      const f = makeFinding(h.id, h.title, h.severity, h.confidence, h.controls, h.rel, h.line, redact(at), h.guidance, "source");
      const sup = RE.suppress.exec(at) ?? (h.line > 1 ? RE.suppress.exec(src[h.line - 2] ?? "") : null);
      const ids = sup ? (sup.groups?.ids ?? "").split(",").map(pyStrip).filter(Boolean) : [];
      if (sup && (!ids.length || ids.includes(h.id))) {
        f.suppressed = pyStrip(sup.groups?.reason ?? "") || "no reason given";
        state.suppressed.push(f);
      } else emit(f);
    }
  }
  // Dependencies: known vulnerabilities (OSV.dev) and major versions behind (each registry).
  if (opts.offline || process.env.SAAS_AUDIT_OFFLINE === "1") state.deps = { skipped: "offline" };
  else if (!opts.signal?.aborted) {
    try {
      const { hits, status } = await checkDependencies(root, files.map((f) => f.rel).filter((r) => !RE.testPath.test(r)));
      state.deps = status;
      for (const h of hits) emit(makeFinding(h.id, h.title, h.severity, h.confidence, h.controls, h.rel, h.line, h.evidence, h.guidance, "source"));
    } catch (e) {
      state.deps = { skipped: `dependency check failed: ${(e as Error).message}` };
    }
  }
  for (const [rel, number, verified, idempotent] of webhookFiles) {
    if (!verified) {
      emit(makeFinding("SEC031", "Webhook handler without visible signature verification", "High", "low", [19],
        rel, number, "No signature/HMAC verification call found in this file",
        "Verify the provider signature over the raw request body with a constant-time comparison before parsing. " +
        "Verification may live in shared middleware; confirm before reporting.", "source"));
    } else if (!idempotent) {
      emit(makeFinding("SEC034", "Webhook handler without visible idempotency handling", "Low", "low", [19],
        rel, number, "Signature check found; no event-ID deduplication found in this file",
        "Persist processed event IDs (unique constraint) so retries and replays cannot apply side effects twice.", "source"));
    }
  }
  for (const env of state.env_files) {
    if (!env.gitignored && !env.example) {
      emit(makeFinding("SEC032", "Environment file not covered by root .gitignore", "High", "medium", [15],
        env.file, 1, "File name not matched by any root .gitignore pattern",
        "Add the file to .gitignore, check whether it was ever committed (git log --all -- <file>), and rotate any secrets in it.",
        "source"));
    }
  }
  const manifestDirs = new Map<string, Set<string>>();
  for (const m of state.manifests) {
    const cut = m.lastIndexOf("/");
    const d = cut >= 0 ? m.slice(0, cut) : "";
    const n = cut >= 0 ? m.slice(cut + 1) : m;
    if (!manifestDirs.has(d)) manifestDirs.set(d, new Set());
    manifestDirs.get(d)!.add(n);
  }
  for (const d of [...manifestDirs.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
    const present = manifestDirs.get(d)!;
    for (const [manifest, locks] of Object.entries(R.lock_for)) {
      // Workspaces (pnpm, yarn, npm) keep one lockfile at the top: a lockfile in any parent folder counts.
      const up = d ? d.split("/").map((_, k, parts) => parts.slice(0, parts.length - k).join("/")).concat("") : [""];
      if (present.has(manifest) && !up.some((dir) => locks.some((l) => existsSync(join(root, dir, l))))) {
        const rel = d ? `${d}/${manifest}` : manifest;
        if (RE.testPath.test(rel)) continue;
        emit(makeFinding("SEC033", "Dependency manifest without a lockfile", "Low", "medium", [15], rel, 1,
          "No lockfile next to this manifest",
          "Commit a lockfile so builds are reproducible and dependency audits reflect what ships.", "source"));
      }
    }
  }
  ev.onPhase?.("done");
  return findings;
}

// ---------- tenant schema analysis (SQL / Drizzle / Prisma) ----------

function normTable(name: string): string {
  const parts = name.split(".").map((p) => p.replace(/^"+|"+$/g, "").toLowerCase());
  return `${parts.length === 2 ? parts[0] : "public"}\u0000${parts[parts.length - 1]}`;
}

function analyzeSchemaFiles(files: [string, string, string[], boolean][], rlsApp: boolean): Finding[] {
  const findings: Finding[] = [];
  const tables = new Map<string, [string, number, string, string]>();
  const rlsTables = new Set<string>();
  const policies = new Set<string>();
  let rlsSeen = false;
  const drizzle: [string, string, number, boolean, string, string][] = [];
  let drizzleRlsUsed = false;
  const prisma: [string, string, number, boolean, string][] = [];
  /** Model → the models its relation fields point at (`run Run @relation(...)`). */
  const parents = new Map<string, Set<string>>();

  for (const [rel, ext, lines, inTest] of files) {
    const context = inTest ? "test" : "source";
    if (ext === ".sql") {
      lines.forEach((line, i) => {
        if (pyLstrip(line).startsWith("--")) return;
        for (const m of line.matchAll(RE.createTableAll)) tables.set(normTable(m.groups!.name!), [rel, i + 1, redact(line), context]);
        for (const m of line.matchAll(RE.enableRlsAll)) { rlsTables.add(normTable(m.groups!.name!)); rlsSeen = true; }
        for (const m of line.matchAll(RE.policyAll)) policies.add(normTable(m.groups!.name!));
        for (const m of line.matchAll(RE.dropTableAll)) tables.delete(normTable(m.groups!.name!));
      });
    } else if (ext === ".prisma") {
      let current: [string, string, number, boolean, string] | null = null;
      lines.forEach((line, i) => {
        const m = RE.prismaModel.exec(line);
        if (m) current = [m.groups!.name!, rel, i + 1, false, context];
        else if (current) {
          if (pyStrip(line) === "}") { prisma.push(current); current = null; }
          else if (RE.tenantField.test(line)) current[3] = true;
          else {
            const rel2 = /^\s*\w+\s+(\w+)\??\s[^\n]*@relation\b/.exec(line);
            if (rel2) {
              const own = current[0];
              if (!parents.has(own)) parents.set(own, new Set());
              parents.get(own)!.add(rel2[1]);
            }
          }
        }
      });
    } else {
      const text = lines.join("\n");
      drizzleRlsUsed = drizzleRlsUsed || RE.drizzleRls.test(text) || text.includes(".withRLS");
      const starts = [...text.matchAll(RE.drizzleTableAll)];
      starts.forEach((m, i) => {
        const pos = m.index!;
        const end = i + 1 < starts.length ? starts[i + 1].index! : text.length;
        const body = text.slice(pos, end);
        const number = text.slice(0, pos).split("\n").length;
        const hasRls = Boolean(m.groups!.rls) || RE.drizzleRls.test(body);
        drizzle.push([m.groups!.name!, rel, number, hasRls, redact(lines[number - 1]), context]);
      });
    }
  }
  if (rlsApp || rlsSeen) {
    const keys = [...tables.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const key of keys) {
      const [schema, table] = key.split("\u0000");
      if (schema !== "public") continue;
      const [rel, number, evidence, context] = tables.get(key)!;
      if (!rlsTables.has(key)) {
        findings.push(makeFinding("SEC030", `Table '${table}' created without ENABLE ROW LEVEL SECURITY`, "High", "medium", [1],
          rel, number, evidence,
          "In an RLS-based app, any exposed table without RLS is readable/writable across tenants. " +
          "Enable RLS and add tenant-scoped policies, or move the table to a non-exposed schema.", context));
      } else if (!policies.has(key)) {
        findings.push(makeFinding("SEC038", `Table '${table}' has RLS enabled but no policies`, "Low", "medium", [1], rel, number, evidence,
          "Deny-all is safe, but it often pushes app code to the service-role key, which bypasses RLS entirely. " +
          "Confirm how the app reads this table.", context));
      }
    }
  }
  if (rlsApp || drizzleRlsUsed) {
    for (const [name, rel, number, hasRls, evidence, context] of drizzle) {
      if (!hasRls) {
        findings.push(makeFinding("SEC030", `Drizzle table '${name}' defined without RLS`, "High", "low", [1], rel, number, evidence,
          "Use pgTable.withRLS / .enableRLS() and pgPolicy for tenant-owned tables, or confirm RLS is applied in SQL migrations.",
          context));
      }
    }
  }
  const tenantModels = prisma.filter((m) => m[3]);
  if (tenantModels.length >= 2) {
    // A model reached through a tenant-scoped (or global) parent is scoped by that parent:
    // PageResult → Run (workspaceId), FeedbackMessage → Feedback. Followed transitively.
    const scoped = new Set(prisma.filter((m) => m[3] || RE.prismaGlobal.test(m[0])).map((m) => m[0]));
    for (let grew = true; grew;) {
      grew = false;
      for (const [name] of prisma) {
        if (!scoped.has(name) && [...(parents.get(name) ?? [])].some((p) => scoped.has(p))) { scoped.add(name); grew = true; }
      }
    }
    for (const [name, rel, number, hasTenant, context] of prisma) {
      if (!hasTenant && !scoped.has(name)) {
        findings.push(makeFinding("SEC039", `Prisma model '${name}' has no tenant key`, "Informational", "low", [1, 9], rel, number,
          `model ${name} lacks a tenant/org field while ${tenantModels.length} models have one`,
          "Confirm this model is global or always reached through a tenant-scoped parent; otherwise add a tenant key " +
          "and scope every query (Prisma has no RLS; consider a client extension that injects the tenant filter).",
          context));
      }
    }
  }
  return findings;
}

