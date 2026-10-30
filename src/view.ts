/** Presentation helpers shared by the terminal summary, HTML report, and PDF report. */
import { basename } from "node:path";
import type { Finding } from "./engine.js";
import type { Result } from "./report.js";
import { R, RULE_TITLES, SEVERITY_RANK } from "./rules.js";
import { standardsLabels } from "./standards.js";

/**
 * Shown by default: findings in the project's own source code, plus real-format secrets wherever
 * they are (a live key in a test fixture is still a leaked key).
 */
export const shownByDefault = (f: Finding) => f.context === "source" || ((f.context === "test" || f.context === "third-party") && f.id === "SEC012");

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;

export const CONTROL_SHORT = [
  "Tenant isolation / RLS", "Route authN / authZ", "Server-side enforcement", "Rate limiting",
  "Input validation & encoding", "Parameterized queries", "CORS policy", "HTTPS & cookies",
  "IDOR / BOLA", "Debug & error handling", "Anti-automation", "Audit logging",
  "Private storage", "Admin protection", "Dependencies & secrets", "File uploads",
  "Independent review", "Security headers", "Webhook security", "SSRF & egress",
  "JWT & sessions", "AI / LLM security",
];

/** One reported issue: every location one rule matched, with the risk, the fix and the manual check. */
export interface Issue {
  ref: string; id: string; title: string; severity: string; confidence: string; controls: number[];
  risk: string; guidance: string; verify: string; references: string[];
  locations: Finding[]; files: number; mixed: boolean;
}

/** A bundled library and what matched inside it. */
export interface LibraryGroup { path: string; files: number; matches: number; rules: string[] }

export interface View {
  project: string;
  generatedAt: Date;
  shown: Finding[];
  /** Test files and gitignored local env files (not counted). */
  hidden: Finding[];
  /** Matches inside bundled libraries (not counted). */
  thirdParty: Finding[];
  issues: Issue[];
  libraries: LibraryGroup[];
  /** Executive-summary paragraphs, plain text. */
  summary: string[];
  sourceCounts: Record<string, number>;
  stack: string[];
  posture: { level: "critical" | "high" | "medium" | "low"; headline: string; detail: string };
  controlsWithLeads: number;
  guidance: { id: string; title: string; guidance: string; verify: string; count: number }[];
  coverage: { leads: CoverageRow[]; noSignals: CoverageRow[]; notVerified: CoverageRow[] };
}

export interface CoverageRow {
  id: number; name: string; short: string; leads: number;
  signals: { source_count: number; test_count: number; locations: string[] } | null;
}

const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line);

export function buildView(result: Result, includeTests = false, now = new Date()): View {
  const shown = (includeTests ? [...result.findings] : result.findings.filter(shownByDefault)).sort(bySeverity);
  const notShown = includeTests ? [] : result.findings.filter((f) => !shownByDefault(f)).sort(bySeverity);
  const hidden = notShown.filter((f) => f.context !== "third-party");
  const thirdParty = notShown.filter((f) => f.context === "third-party");
  const sourceCounts = result.stats.by_severity_source;

  const stack = [...new Set(result.inventory.security_packages.map((p) => STACK_NAMES[p.package]).filter((n): n is string => Boolean(n)))];

  const crit = sourceCounts.Critical ?? 0;
  const high = sourceCounts.High ?? 0;
  const med = sourceCounts.Medium ?? 0;
  const posture: View["posture"] = crit ? {
    level: "critical", headline: "Critical issues need immediate attention",
    detail: `${crit} critical and ${high} high-severity lead${crit + high === 1 ? "" : "s"} in source code. Verify and fix these before the next release.`,
  } : high ? {
    level: "high", headline: "High-risk leads to verify",
    detail: `${high} high-severity lead${high === 1 ? "" : "s"} in source code. Confirm each one in code; most SaaS breaches start here.`,
  } : med ? {
    level: "medium", headline: "No high-risk leads in source code",
    detail: `${med} medium-severity lead${med === 1 ? "" : "s"} to review. Remember: no findings is not proof of security.`,
  } : {
    level: "low", headline: "No significant leads in source code",
    detail: "Heuristics found nothing serious. Controls still need verification with tests — absence of findings is not proof of security.",
  };

  const guidanceMap = new Map<string, View["guidance"][number]>();
  for (const f of shown) {
    const g = guidanceMap.get(f.id);
    if (g) g.count++;
    else guidanceMap.set(f.id, { id: f.id, title: RULE_TITLES[f.id] ?? f.title, guidance: f.guidance, verify: f.verify ?? "", count: 1 });
  }
  const guidance = [...guidanceMap.values()].sort((a, b) => {
    const worst = (id: string) => Math.max(...shown.filter((f) => f.id === id).map((f) => SEVERITY_RANK[f.severity]));
    return worst(b.id) - worst(a.id) || (a.id < b.id ? -1 : 1);
  });

  const rows: CoverageRow[] = result.controls.map((c) => ({
    id: c.id, name: c.name, short: CONTROL_SHORT[c.id - 1],
    leads: shown.filter((f) => f.controls[0] === c.id).length, signals: c.signals,
  }));
  const coverage = {
    leads: rows.filter((r) => r.leads > 0),
    noSignals: rows.filter((r) => !r.leads && r.signals !== null && r.signals.source_count === 0),
    notVerified: rows.filter((r) => !r.leads && !(r.signals !== null && r.signals.source_count === 0)),
  };

  const issues = groupIssues(shown);
  const libraries = libraryGroups(result, thirdParty);
  const project = basename(result.root) || result.root;
  return {
    project, generatedAt: now, shown, hidden, thirdParty, issues, libraries,
    summary: summaryText(result, issues, libraries, thirdParty.length, hidden.length),
    sourceCounts, stack, posture, controlsWithLeads: coverage.leads.length, guidance, coverage,
  };
}

const plural = (n: number, one: string, many = one + "s") => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** One issue per rule, worst first, then the most widespread. */
export function groupIssues(shown: Finding[]): Issue[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of shown) byRule.set(f.id, [...(byRule.get(f.id) ?? []), f]);
  const worst = (l: Finding[]) => Math.max(...l.map((f) => SEVERITY_RANK[f.severity]));
  const groups = [...byRule.entries()].sort((a, b) => worst(b[1]) - worst(a[1]) || b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const width = Math.max(2, String(groups.length).length);
  return groups.map(([id, list], i) => {
    const locations = [...list].sort(bySeverity);
    const first = locations[0];
    return {
      ref: `F-${String(i + 1).padStart(width, "0")}`, id, title: RULE_TITLES[id] ?? first.title,
      severity: first.severity, confidence: first.confidence, controls: first.controls,
      risk: R.risk[id] ?? "", guidance: first.guidance, verify: first.verify ?? "",
      references: standardsLabels(first.standards), locations,
      files: new Set(list.map((f) => f.file)).size, mixed: new Set(list.map((f) => f.severity)).size > 1,
    };
  });
}

function libraryGroups(result: Result, thirdParty: Finding[]): LibraryGroup[] {
  const roots = result.inventory.third_party ?? [];
  const rootOf = (file: string) => roots.find((r) => file === r.path || file.startsWith(r.path + "/"))?.path ?? file;
  const map = new Map<string, LibraryGroup>(roots.map((r) => [r.path, { path: r.path, files: r.files, matches: 0, rules: [] }]));
  for (const f of thirdParty) {
    const key = rootOf(f.file);
    const g = map.get(key) ?? { path: key, files: 1, matches: 0, rules: [] };
    g.matches++;
    if (!g.rules.includes(f.id)) g.rules.push(f.id);
    map.set(key, g);
  }
  return [...map.values()].filter((g) => g.matches).map((g) => ({ ...g, rules: g.rules.sort() }))
    .sort((a, b) => b.matches - a.matches || (a.path < b.path ? -1 : 1));
}

/** File names for a sentence: "Users.php, Profile.php and 3 other files". */
export function fileNames(list: Finding[], max = 3): string {
  const names = [...new Set(list.map((f) => f.file.split("/").pop() || f.file))];
  if (names.length <= max) return names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0] ?? "";
  return `${names.slice(0, max).join(", ")} and ${plural(names.length - max, "other file")}`;
}

function summaryText(result: Result, issues: Issue[], libraries: LibraryGroup[], vendorMatches: number, hidden: number): string[] {
  const out: string[] = [];
  const own = result.stats.files_scanned - (result.inventory.third_party_files ?? 0);
  const bySev = SEVERITY_ORDER.map((s) => [s, issues.filter((i) => i.severity === s).length] as const).filter(([, n]) => n);
  const locations = issues.reduce((a, i) => a + i.locations.length, 0);
  out.push(issues.length
    ? `The review read ${plural(own, "file")} of the application's own code and found ${plural(issues.length, "issue")} ` +
      `(${bySev.map(([s, n]) => `${n} ${s.toLowerCase()}`).join(", ")}) at ${plural(locations, "location")}.`
    : `The review read ${plural(own, "file")} of the application's own code and found no issues. ` +
      "That does not show the code is secure: a pattern scan cannot see every flaw (see Scope and limitations).");
  const urgent = issues.filter((i) => SEVERITY_RANK[i.severity] >= SEVERITY_RANK.High);
  const lead = (urgent.length ? urgent : issues).slice(0, 2);
  if (lead.length) {
    out.push((urgent.length ? "Fix first: " : "The most widespread: ") + lead.map((i) =>
      `${i.title.charAt(0).toLowerCase()}${i.title.slice(1)} (${i.ref}) in ${fileNames(i.locations)}`).join("; and ") + "." +
      (urgent.length > lead.length ? ` ${plural(urgent.length - lead.length, "more high-severity issue")} follow${urgent.length - lead.length === 1 ? "s" : ""} in section 2.` : ""));
  }
  if (vendorMatches) {
    out.push(`A further ${plural(vendorMatches, "match", "matches")} ${vendorMatches === 1 ? "is" : "are"} inside ${plural(libraries.length, "bundled library", "bundled libraries")} ` +
      `(${libraries.slice(0, 3).map((l) => l.path).join(", ")}${libraries.length > 3 ? ", …" : ""}). They are not counted above. ` +
      "Keep those libraries on a supported, patched release, or install them through a package manager, instead of editing them.");
  }
  if (hidden) out.push(`${plural(hidden, "match", "matches")} in test files and gitignored local env files ${hidden === 1 ? "is" : "are"} not counted either.`);
  return out;
}

/** Frameworks and platforms worth naming in a report header (security helper libraries are not "stack"). */
const STACK_NAMES: Record<string, string> = {
  next: "Next.js", express: "Express", "@nestjs/core": "NestJS", fastify: "Fastify", hono: "Hono",
  django: "Django", djangorestframework: "Django REST", flask: "Flask", fastapi: "FastAPI", rails: "Rails", "laravel/framework": "Laravel",
  "@supabase/supabase-js": "Supabase", "@supabase/ssr": "Supabase", firebase: "Firebase", "firebase-admin": "Firebase",
  prisma: "Prisma", "@prisma/client": "Prisma", "drizzle-orm": "Drizzle", sequelize: "Sequelize", typeorm: "TypeORM",
  mongoose: "MongoDB", sqlalchemy: "SQLAlchemy", stripe: "Stripe", "@clerk/nextjs": "Clerk", "next-auth": "NextAuth",
  "@auth/core": "Auth.js", passport: "Passport", "better-auth": "Better Auth", lucia: "Lucia",
  openai: "OpenAI", "@anthropic-ai/sdk": "Anthropic", anthropic: "Anthropic", ai: "Vercel AI SDK", langchain: "LangChain",
  "@aws-sdk/client-s3": "AWS S3", boto3: "AWS",
};

/** Stack names from a set of package names (frameworks and platforms only). */
export const stackOf = (packages: string[]) => [...new Set(packages.map((p) => STACK_NAMES[p]).filter((n): n is string => Boolean(n)))];

export const controlLabel = (id: number) => `C${id} ${CONTROL_SHORT[id - 1]}`;

export function formatDate(d: Date): string {
  return d.toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ---------- terminal redesign: areas, roles, verdict, fix plan ----------

/** Short rule names for dense columns ("driven by", live feed). */
export const RULE_SHORT: Record<string, string> = {
  SEC001: "hardcoded cred", SEC002: "eval", SEC003: "SQL interpolation", SEC004: "debug mode", SEC005: "permissive CORS",
  SEC006: "plain HTTP", SEC007: "cookie flags", SEC011: "sensitive logs", SEC012: "secret", SEC013: "shell exec",
  SEC014: "unsafe deserialize", SEC015: "raw HTML sink", SEC016: "TLS verify off", SEC017: "JWT verify", SEC018: "CSRF off",
  SEC019: "mass assignment", SEC020: "SSRF", SEC021: "weak random", SEC022: "permissive RLS", SEC023: "public env secret",
  SEC024: "weak hashing", SEC025: "stack trace", SEC026: "public ACL", SEC027: "open redirect", SEC028: "path traversal",
  SEC029: "NoSQL injection", SEC030: "missing RLS", SEC031: "webhook signature", SEC032: "env not ignored",
  SEC033: "no lockfile", SEC034: "webhook idempotency", SEC035: "prompt injection", SEC036: "LLM output sink",
  SEC037: "long-lived token", SEC038: "RLS without policies", SEC039: "no tenant key",
  SEC044: "no login check", SEC045: "IDOR", SEC046: "mass assignment", SEC047: "owner from request",
  SEC048: "traced injection", SEC049: "traced SSRF/redirect", SEC050: "vulnerable dependency", SEC051: "outdated dependency",
  SEC052: "container as root", SEC053: "secret in image/manifest", SEC054: "unpinned image/action", SEC055: "open to internet",
  SEC056: "exposed database", SEC057: "CI runs untrusted code", SEC058: "privileged container",
};

export type PathRole = "source" | "build" | "docs" | "test" | "local env" | "third-party";
const BUILD_SEGMENT = /^(?:\.next(?:-.+)?|dist|build|out|\.output|\.nuxt|\.svelte-kit|\.vercel|\.turbo|\.parcel-cache|storybook-static|chunks|\.expo|\.angular)$/;
const DOCS_SEGMENT = /^(?:docs?|\.agents|\.claude|\.cursor|\.github|examples?|samples?)$/i;

/** What a file is for: application source, generated build output, docs/agent files, tests, or local env. */
export function pathRole(f: Finding): PathRole {
  if (f.context === "test") return "test";
  if (f.context === "ignored-local-env") return "local env";
  if (f.context === "third-party") return "third-party";
  const parts = f.file.split("/");
  if (parts.slice(0, -1).some((p) => BUILD_SEGMENT.test(p))) return "build";
  if (parts.slice(0, -1).some((p) => DOCS_SEGMENT.test(p)) || /\.(?:md|mdx|rst|txt)$/i.test(f.file)) return "docs";
  return "source";
}

export interface Area {
  label: string; controls: number[]; total: number;
  bySeverity: Record<string, number>; topRules: { id: string; count: number }[]; hasSignals: boolean;
}

export function areas(findings: Finding[], groups: { label: string; controls: number[] }[], result: Result): Area[] {
  return groups.map((g) => {
    const list = findings.filter((f) => g.controls.includes(f.controls[0]));
    const bySeverity: Record<string, number> = {};
    for (const s of SEVERITY_ORDER) bySeverity[s] = list.filter((f) => f.severity === s).length;
    const ruleCounts = new Map<string, number>();
    for (const f of list) ruleCounts.set(f.id, (ruleCounts.get(f.id) ?? 0) + 1);
    const topRules = [...ruleCounts.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || (a.id < b.id ? -1 : 1));
    const hasSignals = result.controls.some((c) => g.controls.includes(c.id) && (c.signals?.source_count ?? 0) > 0);
    return { label: g.label, controls: g.controls, total: list.length, bySeverity, topRules, hasSignals };
  });
}

/** Where the worst findings live, grouped by directory, with each group's role. */
export function whereWorst(shown: Finding[]): { severity: string; total: number; groups: { dir: string; count: number; role: PathRole; label: string }[] } | null {
  const severity = shown.some((f) => f.severity === "Critical") ? "Critical" : shown.some((f) => f.severity === "High") ? "High" : null;
  if (!severity) return null;
  const list = shown.filter((f) => f.severity === severity);
  const secret = list.every((f) => f.id === "SEC012" || f.id === "SEC001" || f.id === "SEC023");
  const map = new Map<string, { dir: string; count: number; role: PathRole }>();
  for (const f of list) {
    const dir = f.file.includes("/") ? f.file.slice(0, f.file.lastIndexOf("/") + 1) : "./";
    const role = pathRole(f);
    const key = role + "\u0000" + dir;
    const g = map.get(key) ?? { dir, count: 0, role };
    g.count++;
    map.set(key, g);
  }
  const roleLabel = (role: PathRole) => ({
    source: secret ? "application source · rotate the keys now" : "application source · fix here first",
    build: secret ? "generated build output · copies of the same keys" : "generated build output · fixed when the source is fixed",
    docs: "docs and agent files · check whether values are real",
    test: "test files · usually intentional samples",
    "local env": "gitignored local env files",
    "third-party": "bundled library · update it, don't edit it",
  })[role];
  const order: PathRole[] = ["source", "local env", "docs", "test", "third-party", "build"];
  const groups = [...map.values()]
    .sort((a, b) => order.indexOf(a.role) - order.indexOf(b.role) || b.count - a.count)
    .map((g) => ({ ...g, label: roleLabel(g.role) }));
  return { severity, total: list.length, groups };
}

export interface Verdict {
  kind: "blocked" | "passed" | "risk" | "review" | "clean";
  title: string; detail: string; gate: string; exit: number;
}

export function verdict(sourceCounts: Record<string, number>, failOn: string, gateTripped: boolean): Verdict {
  const crit = sourceCounts.Critical ?? 0;
  const high = sourceCounts.High ?? 0;
  const med = sourceCounts.Medium ?? 0;
  const gate = failOn === "none" ? "no gate · add --fail-on high" : `gate --fail-on ${failOn} · exit ${gateTripped ? 1 : 0}`;
  const leads = crit || high
    ? `${crit ? `${num(crit)} critical and ` : ""}${num(high)} high-severity lead${crit + high === 1 ? "" : "s"} in source code.`
    : "";
  if (gateTripped) return { kind: "blocked", title: "✗ RELEASE BLOCKED", detail: `${leads} Verify and fix them before the next release.`, gate, exit: 1 };
  if (crit || high) return { kind: "risk", title: "▲ HIGH-RISK LEADS TO VERIFY", detail: `${leads} Verify and fix them before the next release.`, gate, exit: 0 };
  if (failOn !== "none") return { kind: "passed", title: "✓ GATE PASSED", detail: `No leads at or above ${failOn} in source code.${med ? ` ${num(med)} medium-severity leads to review.` : ""}`, gate, exit: 0 };
  if (med) return { kind: "review", title: "◐ NO HIGH-RISK LEADS", detail: `${num(med)} medium-severity lead${med === 1 ? "" : "s"} to review. No findings is not proof of security.`, gate, exit: 0 };
  return { kind: "clean", title: "✓ NO SIGNIFICANT LEADS", detail: "Heuristics found nothing serious in source code. Controls still need verification with tests.", gate, exit: 0 };
}

const num = (n: number) => n.toLocaleString("en-US");

export interface FixAction {
  severity: string; title: string; detail: string; command?: string; tags: string[]; when: string;
}

function namesOf(list: Finding[], max = 3): string {
  const counts = new Map<string, number>();
  for (const f of list) {
    const base = f.file.split("/").pop() || f.file;
    counts.set(base, (counts.get(base) ?? 0) + 1);
  }
  const names = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n);
  return names.slice(0, max).join(", ") + (names.length > max ? ` +${names.length - max} more` : "");
}

const quoted = (list: Finding[]) => [...new Set(list.map((f) => /'([^']+)'/.exec(f.title)?.[1]).filter(Boolean))].slice(0, 3).join(", ");

const ACTION_TITLE: Record<string, (list: Finding[]) => string> = {
  SEC012: (l) => `Rotate the exposed secrets in ${namesOf(l.filter((f) => pathRole(f) !== "build").length ? l.filter((f) => pathRole(f) !== "build") : l)}`,
  SEC001: (l) => `Confirm the hardcoded credentials in ${namesOf(l)}`,
  SEC023: () => "Move server-only secrets out of public env variables",
  SEC032: (l) => `Ignore ${l[0].file} and check its history`,
  SEC031: (l) => `Verify webhook signatures in ${namesOf(l)}`,
  SEC026: (l) => `Make storage private in ${namesOf(l)}`,
  SEC003: (l) => `Parameterise the SQL queries in ${namesOf(l)}`,
  SEC029: (l) => `Validate query filters in ${namesOf(l)}`,
  SEC002: (l) => `Remove dynamic code evaluation in ${namesOf(l)}`,
  SEC013: (l) => `Remove shell command execution in ${namesOf(l)}`,
  SEC014: (l) => `Replace unsafe deserialization in ${namesOf(l)}`,
  SEC016: (l) => `Re-enable TLS certificate verification in ${namesOf(l)}`,
  SEC017: (l) => `Verify JWTs properly in ${namesOf(l)}`,
  SEC020: (l) => `Allowlist outbound request destinations in ${namesOf(l)}`,
  SEC022: (l) => `Tighten permissive data access rules in ${namesOf(l)}`,
  SEC030: (l) => `Enable row-level security on ${quoted(l) || namesOf(l)}`,
  SEC005: (l) => `Restrict CORS to an origin allowlist in ${namesOf(l)}`,
  SEC024: (l) => `Use a password hashing function in ${namesOf(l)}`,
  SEC028: (l) => `Contain file paths built from request input in ${namesOf(l)}`,
  SEC036: (l) => `Stop passing LLM output to execution sinks in ${namesOf(l)}`,
  SEC044: (l) => `Check sign-in in ${namesOf(l)}`,
  SEC045: (l) => `Scope record lookups to their owner in ${namesOf(l)}`,
  SEC046: (l) => `Pick allowed fields before writing in ${namesOf(l)}`,
  SEC047: (l) => `Set owner, role and price on the server in ${namesOf(l)}`,
  SEC048: (l) => `Keep request input out of SQL, shells and eval in ${namesOf(l)}`,
  SEC049: (l) => `Allowlist fetch and redirect targets in ${namesOf(l)}`,
  SEC053: (l) => `Move secrets out of ${namesOf(l)} and rotate them`,
  SEC055: (l) => `Close internet-wide access in ${namesOf(l)}`,
  SEC056: (l) => `Lock down the database in ${namesOf(l)}`,
  SEC057: (l) => `Stop CI from running untrusted code with secrets in ${namesOf(l)}`,
  SEC058: (l) => `Remove privileged and host access in ${namesOf(l)}`,
  SEC050: (l) => `Upgrade ${l.length} vulnerable package${l.length === 1 ? "" : "s"} (${[...new Set(l.map((f) => /^(@?[^@\s]+)@/.exec(f.title)?.[1] ?? f.title))].slice(0, 3).join(", ")})`,
};

/** Every critical, then the high-severity rules, ordered by severity × number of hits. */
export function fixPlan(shown: Finding[]): FixAction[] {
  const byRule = new Map<string, Finding[]>();
  for (const f of shown) byRule.set(f.id, [...(byRule.get(f.id) ?? []), f]);
  const worst = (l: Finding[]) => Math.max(...l.map((f) => SEVERITY_RANK[f.severity]));
  const rules = [...byRule.entries()].filter(([, l]) => worst(l) >= SEVERITY_RANK.High)
    .sort((a, b) => worst(b[1]) - worst(a[1]) || b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
  const idempotency = byRule.get("SEC034") ?? [];
  return rules.map(([id, list]) => {
    const severity = worst(list) === SEVERITY_RANK.Critical ? "Critical" : "High";
    const crit = list.filter((f) => f.severity === "Critical").length;
    const tags = [list.length > 1 ? `${id} ×${list.length}` : id];
    if (crit) tags.push(`${crit} crit`);
    let title = (ACTION_TITLE[id] ?? ((l: Finding[]) => `${RULE_TITLES[id] ?? id}: fix in ${namesOf(l)}`))(list);
    let detail = list[0].guidance;
    let command: string | undefined;
    if (id === "SEC031" && idempotency.length) {
      title = "Verify webhook signatures and make handlers idempotent";
      detail = "Check the signature over the raw body with a constant-time compare, then persist processed event IDs under a unique constraint.";
      tags.push(idempotency.length > 1 ? `SEC034 ×${idempotency.length}` : "SEC034");
    }
    if (id === "SEC012") {
      const build = list.filter((f) => pathRole(f) === "build");
      if (build.length && build.length < list.length) {
        const dir = build[0].file.split("/").slice(0, 2).join("/");
        detail += ` Rebuild so the ${build.length} cop${build.length === 1 ? "y" : "ies"} in ${dir}/ disappear.`;
      }
    }
    if (id === "SEC032") {
      command = `git log --all -- ${list[0].file}`;
      detail = "";
    }
    return { severity, title, detail, command, tags, when: severity === "Critical" ? "do today" : "before release" };
  });
}

// ---------- report sections shared by the Markdown, HTML and PDF reports ----------

export interface StandardSection {
  title: string; kind: string;
  rows: { id: string; name: string; refs: string[]; locations: number }[];
  /** Entries this scanner checks that had no findings. */
  quiet: number;
}

/** Standards tables trimmed to what was found, each row pointing at the report's finding numbers. */
export function standardSections(result: Result, issues: Issue[]): StandardSection[] {
  const s = result.standards;
  const refOf = new Map(issues.map((i) => [i.id, i.ref]));
  const refs = (rules: string[]) => [...new Set(rules.map((r) => refOf.get(r)).filter((r): r is string => Boolean(r)))].sort();
  const section = (title: string, kind: string, rows: { id: string; name: string; leads: number; rules: string[]; checked?: boolean }[]): StandardSection => ({
    title, kind,
    rows: rows.map((r) => ({ id: r.id, name: r.name, refs: refs(r.rules), locations: r.leads })).filter((r) => r.locations && r.refs.length),
    quiet: rows.filter((r) => (r.checked ?? true) && !(r.leads && refs(r.rules).length)).length,
  });
  const cweRules = (id: string) => Object.keys(R.standards).filter((rid) => R.standards[rid].cwe.includes(id));
  return [
    section("OWASP Top 10 (2021)", "Category", s.owasp_top10_2021),
    section("OWASP API Security Top 10 (2023)", "Category", s.owasp_api_2023),
    section("OWASP Top 10 for LLM Applications (2025)", "Category", s.owasp_llm_2025),
    { ...section("CWE", "Weakness", s.cwe.map((c) => ({ id: c.id, name: c.name + (c.top25 ? " (CWE Top 25)" : ""), leads: c.leads, rules: cweRules(c.id) }))), quiet: 0 },
    section(`MITRE ATT&CK (v${s.versions.attack})`, "Technique", s.mitre_attack),
    section(`MITRE ATLAS (${s.versions.atlas})`, "Technique", s.mitre_atlas),
    section(`MITRE D3FEND (${s.versions.d3fend})`, "Countermeasure", s.mitre_d3fend),
  ];
}

export interface CoverageLine { id: number; name: string; result: string; refs: string[]; found: boolean }

/** Each control's outcome in words: issues found (with refs), or no issues and whether related code was seen. */
export function coverageLines(result: Result, issues: Issue[]): CoverageLine[] {
  return result.controls.map((c) => {
    const refs = issues.filter((i) => i.controls[0] === c.id).map((i) => i.ref);
    const sig = c.signals;
    const result = refs.length ? `${plural(refs.length, "issue")} found`
      : c.id === 15 ? "None found · also run a dependency audit"
      : c.id === 17 ? "Needs a manual or agent review"
      : sig && sig.source_count ? "None found · related code seen"
      : "None found · no related code";
    return { id: c.id, name: c.name, result, refs, found: refs.length > 0 };
  });
}

/** The common-mistakes checklist (vibe review), with finding numbers instead of rule ids. */
export function checklistLines(result: Result, issues: Issue[]): { id: string; title: string; refs: string[] }[] {
  return result.vibe_review.map((v) => ({ id: v.id, title: v.title, refs: issues.filter((i) => v.rules.includes(i.id)).map((i) => i.ref) }));
}
