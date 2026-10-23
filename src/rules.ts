import { readFileSync } from "node:fs";

type Rx = { source: string; flags: string };

interface RawRules {
  version: string;
  schema_version: number;
  controls: string[];
  severity_rank: Record<string, number>;
  skip_dirs: string[];
  code_exts: string[];
  config_exts: string[];
  sql_exts: string[];
  doc_exts: string[];
  config_names: string[];
  lockfiles: string[];
  manifests: Record<string, string>;
  lock_for: Record<string, string[]>;
  dep_tools: Record<string, { command: string; binary: string; network: boolean }[]>;
  general_tools: { command: string; binary: string; network: boolean }[];
  max_bytes: number;
  max_line: number;
  max_signal_locations: number;
  comment_prefixes: string[];
  report_markdown_header: string;
  report_json_marker: string;
  rules: {
    id: string; title: string; severity: string; confidence: string; controls: number[];
    scope: string[]; skip_comments: boolean; guidance: string;
    patterns: (Rx & { exts: string[] | null })[];
  }[];
  secret_formats: (Rx & { title: string; severity: string; groups: string[] })[];
  regex: Record<string, Rx>;
  control_signals: Record<string, Rx>;
  security_packages: Record<string, { control: number; role: string }>;
  rule_titles: Record<string, string>;
  secret_guidance: Record<string, string>;
}

const raw: RawRules = JSON.parse(readFileSync(new URL("../rules.json", import.meta.url), "utf8"));

/** Compile for single-match use (search/test). */
export const rx = (r: Rx) => new RegExp(r.source, r.flags);
/** Compile for iteration/replacement with group indices (Python finditer/sub). */
export const rxAll = (r: Rx) => new RegExp(r.source, r.flags + "gd");

export const R = raw;
export const VERSION = raw.version;
export const SCHEMA_VERSION = raw.schema_version;
export const CONTROLS = raw.controls;
export const SEVERITY_RANK = raw.severity_rank;
export const SEVERITIES = Object.keys(raw.severity_rank);
export const SKIP_DIRS = new Set(raw.skip_dirs);
export const CODE_EXTS = new Set(raw.code_exts);
export const CONFIG_EXTS = new Set(raw.config_exts);
export const SQL_EXTS = new Set(raw.sql_exts);
export const DOC_EXTS = new Set(raw.doc_exts);
export const CONFIG_NAMES = new Set(raw.config_names);
export const LOCKFILES = new Set(raw.lockfiles);

export interface Rule {
  id: string; title: string; severity: string; confidence: string; controls: number[];
  scope: Set<string>; skipComments: boolean; guidance: string;
  patterns: { re: RegExp; exts: Set<string> | null }[];
}

export const RULES: Rule[] = raw.rules.map((r) => ({
  id: r.id, title: r.title, severity: r.severity, confidence: r.confidence, controls: r.controls,
  scope: new Set(r.scope), skipComments: r.skip_comments, guidance: r.guidance,
  patterns: r.patterns.map((p) => ({ re: rx(p), exts: p.exts ? new Set(p.exts) : null })),
}));

export const SECRET_FORMATS = raw.secret_formats.map((s) => ({
  title: s.title, severity: s.severity, groups: new Set(s.groups), re: rxAll(s),
}));

const g = raw.regex;
export const RE = {
  quotedCred: rx(g.quoted_cred_re), quotedCredAll: rxAll(g.quoted_cred_re),
  envCred: rx(g.env_cred_re), envCredAll: rxAll(g.env_cred_re),
  bearerAll: rxAll(g.bearer_re),
  placeholder: rx(g.placeholder_re),
  localHost: rx(g.local_host_re),
  suppress: rx(g.suppress_re),
  testPath: rx(g.test_path_re),
  exampleEnv: rx(g.example_env_re),
  webhookRoute: rx(g.webhook_route_re),
  webhookVerify: rx(g.webhook_verify_re),
  webhookIdempotency: rx(g.webhook_idempotency_re),
  createTableAll: rxAll(g.create_table_re),
  enableRlsAll: rxAll(g.enable_rls_re),
  dropTableAll: rxAll(g.drop_table_re),
  policyAll: rxAll(g.policy_re),
  drizzleTableAll: rxAll(g.drizzle_table_re),
  drizzleRls: rx(g.drizzle_rls_re),
  prismaModel: rx(g.prisma_model_re),
  tenantField: rx(g.tenant_field_re),
  prismaGlobal: rx(g.prisma_global_models),
};

export const CONTROL_SIGNALS: [number, RegExp][] = Object.entries(raw.control_signals).map(([k, v]) => [Number(k), rx(v)]);
export const RULE_TITLES = raw.rule_titles;
export const SECRET_GUIDANCE = raw.secret_guidance;
