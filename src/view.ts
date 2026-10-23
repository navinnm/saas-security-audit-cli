/** Presentation helpers shared by the terminal summary, HTML report, and PDF report. */
import { basename } from "node:path";
import type { Finding } from "./engine.js";
import type { Result } from "./report.js";
import { RULE_TITLES, SEVERITY_RANK } from "./rules.js";

/**
 * Shown by default: findings in the project's own source code, plus real-format secrets wherever
 * they are (a live key in a test fixture is still a leaked key).
 */
export const shownByDefault = (f: Finding) => f.context === "source" || (f.context === "test" && f.id === "SEC012");

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;

export const CONTROL_SHORT = [
  "Tenant isolation / RLS", "Route authN / authZ", "Server-side enforcement", "Rate limiting",
  "Input validation & encoding", "Parameterized queries", "CORS policy", "HTTPS & cookies",
  "IDOR / BOLA", "Debug & error handling", "Anti-automation", "Audit logging",
  "Private storage", "Admin protection", "Dependencies & secrets", "File uploads",
  "Independent review", "Security headers", "Webhook security", "SSRF & egress",
  "JWT & sessions", "AI / LLM security",
];

export interface View {
  project: string;
  generatedAt: Date;
  shown: Finding[];
  hidden: Finding[];
  sourceCounts: Record<string, number>;
  stack: string[];
  posture: { level: "critical" | "high" | "medium" | "low"; headline: string; detail: string };
  controlsWithLeads: number;
  guidance: { id: string; title: string; guidance: string; count: number }[];
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
  const hidden = includeTests ? [] : result.findings.filter((f) => !shownByDefault(f)).sort(bySeverity);
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
    else guidanceMap.set(f.id, { id: f.id, title: RULE_TITLES[f.id] ?? f.title, guidance: f.guidance, count: 1 });
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

  return {
    project: basename(result.root) || result.root, generatedAt: now, shown, hidden, sourceCounts, stack, posture,
    controlsWithLeads: coverage.leads.length, guidance, coverage,
  };
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

export const controlLabel = (id: number) => `C${id} ${CONTROL_SHORT[id - 1]}`;

export function formatDate(d: Date): string {
  return d.toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
