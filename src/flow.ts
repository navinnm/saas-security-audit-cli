/**
 * Code-flow analysis for the bugs vibe-coded apps ship most and line scanners can't see:
 * API routes and server actions nobody has to sign in for, records loaded by an id from the
 * request without an owner check (IDOR), request bodies written straight into the database,
 * owner ids or prices taken from the browser, and request input reaching SQL, a shell, eval,
 * an outgoing request or a redirect.
 *
 * JS/TS only, parsed with @babel/parser. Never runs the code. Taint is followed inside each handler
 * (variables, destructuring, awaits, templates, string helpers); auth checks are also followed into
 * functions the handler calls, in the same file or imported, a few levels deep.
 */
import { parse } from "@babel/parser";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";

type Node = { type: string; loc?: { start: { line: number } }; [k: string]: any };

export interface FlowHit {
  id: string; title: string; severity: string; confidence: string; controls: number[];
  rel: string; line: number; guidance: string;
}

export interface FlowFile { rel: string; ext: string; text: string }

export const FLOW_EXTS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);

const GUIDE = {
  SEC044: "Anyone can call this without signing in, and it reads or changes data. Check the session first and answer 401 " +
    "without one (const user = await getCurrentUser(); if (!user) return 401). If it is meant to be public, rate-limit it " +
    "and make sure it only touches public data.",
  SEC045: "The record is looked up only by an id that comes from the request, so any signed-in user can read or change " +
    "someone else's by changing the id. Add the owner or tenant to the query (where: { id, userId: user.id }) or compare " +
    "the record's owner with the signed-in user before using it.",
  SEC046: "The request body goes into the database as a whole, so a user can set any column (role, plan, ownerId, " +
    "price). Pick the allowed fields one by one, or parse with a schema that strips unknown keys (zod .parse).",
  SEC047: "The owner, role or price is taken from what the browser sent. Set owner and tenant from the signed-in session " +
    "and look prices up on the server; never trust these from the request.",
  SEC048: "Request input reaches this sink directly. Use bound parameters (tagged sql`` / $queryRaw``), pass argument " +
    "arrays to a fixed program without a shell, and never evaluate request data.",
  SEC049: "Request input decides where the server sends a request or redirects the user. Allowlist hosts for outgoing " +
    "requests (and block private addresses); only redirect to relative paths or known hosts.",
};

// ---------- names that matter ----------

/** Calls that establish who the caller is (or check a signature / shared secret). */
const AUTH_EXACT = new Set([
  "auth", "getServerSession", "getSession", "currentUser", "getCurrentUser", "requireUser", "requireAuth", "requireAdmin",
  "getUser", "getAuth", "getToken", "verifySession", "verifyToken", "validateRequest", "validateSession", "withAuth",
  "protect", "isAuthenticated", "ensureAuth", "checkAuth", "authenticate", "getKindeServerSession", "getIronSession",
  "getClaims", "jwtVerify", "verify", "timingSafeEqual", "constructEvent", "verifyHeader", "unwrap", "verifySignature",
  "getServerAuthSession", "getUserOrThrow", "useSession", "createRouteHandlerClient",
]);
const AUTH_WORD = /(?:^|[a-z0-9_])(?:Auth|Session|User|Viewer|Actor|Staff|Admin|Member|Workspace|Tenant|Account|Permission|Role|Signature|Signed|Sig|Ticket)(?:[A-Z_]|$)|^(?:auth|session|admin|staff|require|ensure|assert|verify|validate|guard|protect|authorize|authenticate|must|token|signed)(?:[A-Z_]|$)/;
/** Deliberately public endpoints rate-limit or use a CAPTCHA. */
const PUBLIC_GUARD = /limit|throttl|captcha|turnstile|blocked|quota|honeypot/i;
const PUBLIC_PATH = /(?:^|\/)(?:webhooks?|auth|login|logout|sign-?in|sign-?out|sign-?up|register|callback|oauth|health(?:z)?|status|ping|ready|live|public|og|opengraph-image|sitemap|robots|rss|feed|manifest|\.well-known|share|unsubscribe|verify|reset|forgot|invite|contact|newsletter|subscribe|csp-report)(?:\/|$|\.|\[)/i;
const DB_ROOT = /^(?:prisma|db|database|drizzle|knex|supabase|sb|sql|pool|conn|connection|mongo|mongoose|firestore|tx|trx|models?|repo|repository)$/i;
const DB_WRITE = new Set(["create", "createMany", "update", "updateMany", "upsert", "delete", "deleteMany", "insert", "insertOne",
  "insertMany", "updateOne", "deleteOne", "findByIdAndUpdate", "findByIdAndDelete", "findOneAndUpdate", "findOneAndDelete",
  "values", "set", "$executeRaw", "$executeRawUnsafe", "save"]);
/** Mongoose / Sequelize style: Post.findById(x), User.create(x). */
const MODEL_METHODS = /^(?:find|findOne|findById|findAll|findByPk|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|create|insertMany|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|destroy)$/;
const MODEL_CALL = (p: string[], name: string) => p.length === 2 && /^[A-Z][a-z][A-Za-z0-9]*$/.test(p[0]) && !/^(?:Object|Array|JSON|Math|Promise|Response|NextResponse|Date|Number|String|Buffer|URL|Reflect|Intl)$/.test(p[0]) && MODEL_METHODS.test(name);
const BY_ID_LOOKUP = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "update", "delete", "upsert"]);
const OWNER_KEY = /(?:user|owner|author|creator|member|workspace|org|organi[sz]ation|tenant|team|account|company|project|createdBy)/i;
const ID_KEY = /^(?:id|_id|uuid|slug|key|[a-z]\w*Id|[a-z]\w*_id)$/;
const TRUSTED_FIELD = /^(?:userId|user_id|ownerId|owner_id|authorId|author_id|creatorId|createdBy|created_by|createdById|workspaceId|workspace_id|orgId|org_id|organizationId|organization_id|tenantId|tenant_id|teamId|team_id|accountId|account_id|role|roles|isAdmin|is_admin|admin|isStaff|permissions|plan|price|unitPrice|amount|total|credits|balance|subscriptionTier|tier)$/;
/** canEdit(user, doc), assertOwner(doc), hasAccess(…): checks of a record against the caller (not sign-in itself). */
const OWNERSHIP_CHECK = /^(?:can|assert|ensure|check|verify|authorize|guard)[A-Z]|(?:Access|Owner|Ownership|Permission|Allowed|Member)(?:[A-Z]|$)|^(?:owns|isOwner|hasAccess)/;
/** where: { shareToken: t } / { widgetKey: k }: holding the secret is the permission. */
const CAPABILITY_KEY = /^(?:token|secret|sig|signature|code)$|(?:[a-z]Token|[a-z]Key|_key|_token|[a-z]Secret|[a-z]Hash|[a-z]Code|_code|[a-z]Sig)$/;
const SIGN_IN_ONLY = /Session|User|Token|Auth|Signature|Ticket/;

// ---------- AST helpers ----------

const SKIP_KEYS = new Set(["loc", "start", "end", "extra", "leadingComments", "trailingComments", "innerComments", "range", "comments", "tokens", "typeAnnotation", "returnType", "typeParameters"]);

function visit(node: Node | null | undefined, fn: (n: Node, parent: Node | null) => void | false, parent: Node | null = null): void {
  if (!node || typeof node.type !== "string") return;
  if (fn(node, parent) === false) return;
  for (const key in node) {
    if (SKIP_KEYS.has(key)) continue;
    const v = node[key];
    if (Array.isArray(v)) { for (const c of v) if (c && typeof c.type === "string") visit(c, fn, node); }
    else if (v && typeof v.type === "string") visit(v, fn, node);
  }
}

const unwrapExpr = (n: Node | null | undefined): Node | null | undefined => {
  while (n && ["AwaitExpression", "TSAsExpression", "TSNonNullExpression", "TSSatisfiesExpression", "ParenthesizedExpression", "TypeCastExpression", "TSTypeAssertion"].includes(n.type)) {
    n = n.type === "AwaitExpression" ? n.argument : n.expression;
  }
  return n;
};

/** ["prisma","user","findUnique"] for prisma.user.findUnique, ["cookies()","get"] for cookies().get. */
function memberPath(n: Node | null | undefined): string[] {
  n = unwrapExpr(n);
  if (!n) return [];
  if (n.type === "Identifier") return [n.name];
  if (n.type === "ThisExpression") return ["this"];
  if (n.type === "MemberExpression" || n.type === "OptionalMemberExpression") {
    const prop = !n.computed && n.property.type === "Identifier" ? n.property.name
      : n.property.type === "StringLiteral" ? n.property.value : "[]";
    return [...memberPath(n.object), prop];
  }
  if (n.type === "CallExpression" || n.type === "OptionalCallExpression") {
    const p = memberPath(n.callee);
    return p.length ? [...p.slice(0, -1), p[p.length - 1] + "()"] : [];
  }
  return [];
}

const calleeName = (call: Node): string => {
  const p = memberPath(call.callee);
  return p.length ? p[p.length - 1].replace(/\(\)$/, "") : "";
};
const isCall = (n: Node | null | undefined): boolean => !!n && (n.type === "CallExpression" || n.type === "OptionalCallExpression");
const isFn = (n: Node | null | undefined): boolean => !!n && ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod"].includes(n.type);
const line = (n: Node) => n.loc?.start.line ?? 1;
const propKey = (p: Node): string | null =>
  p.key?.type === "Identifier" ? p.key.name : p.key?.type === "StringLiteral" ? p.key.value : null;

// ---------- taint inside one handler ----------

/** object = the whole request body / params (could set any field); value = data from the request; checked = parsed by a schema. */
type Taint = "object" | "value" | "checked";

const REQ_PARTS = /^(?:body|query|params|headers|cookies|searchParams|nextUrl|url|formData\(\)|json\(\)|text\(\)|param\(\)|req|valid\(\))$/;
const PASS_THROUGH = new Set(["String", "Number", "parseInt", "parseFloat", "decodeURIComponent", "decodeURI", "trim", "toLowerCase",
  "toUpperCase", "toString", "get", "getAll", "slice", "substring", "replace", "split", "join", "at", "concat", "padStart", "Object.fromEntries", "fromEntries", "entries"]);
const SCHEMA_PARSE = /^(?:parse|parseAsync|safeParse|safeParseAsync|validate|validateSync|cast|assert)$/;

class Taints {
  map = new Map<string, Taint>();
  constructor(private reqNames: Set<string>) {}

  of(expr: Node | null | undefined): Taint | null {
    const n = unwrapExpr(expr);
    if (!n) return null;
    switch (n.type) {
      case "Identifier":
        return this.map.get(n.name) ?? null;
      case "MemberExpression": case "OptionalMemberExpression": {
        const p = memberPath(n);
        if (p.length >= 2 && this.reqNames.has(p[0])) {
          if (p.length === 2 && /^(?:body|params|query)$/.test(p[1])) return "object";
          if (p.slice(1).some((x) => REQ_PARTS.test(x))) return "value";
        }
        const base = this.of(n.object);
        return base ? "value" : null;
      }
      case "CallExpression": case "OptionalCallExpression": {
        const p = memberPath(n.callee);
        const name = calleeName(n);
        if (p.length >= 2 && this.reqNames.has(p[0])) {
          if (/^(?:json|formData)$/.test(name) && p.length <= 3) return "object";
          if (p.slice(1).some((x) => REQ_PARTS.test(x.replace(/\(\)$/, "")) || REQ_PARTS.test(x))) return "value";
        }
        if (SCHEMA_PARSE.test(name) && n.arguments.some((a: Node) => this.of(a))) return "checked";
        const objTaint = n.callee.type?.includes("Member") ? this.of(n.callee.object) : null;
        if (objTaint && PASS_THROUGH.has(name)) return name === "fromEntries" || name === "entries" ? objTaint : "value";
        if (objTaint && /^(?:json|formData|text)$/.test(name)) return "object";
        if ((PASS_THROUGH.has(name) || name === "fromEntries") && n.arguments.some((a: Node) => this.of(a))) {
          return name === "fromEntries" ? "object" : "value";
        }
        return null;
      }
      case "NewExpression":
        return n.callee.type === "Identifier" && /^(?:URL|URLSearchParams|String)$/.test(n.callee.name) && n.arguments.some((a: Node) => this.of(a)) ? "value" : null;
      case "TemplateLiteral":
        return n.expressions.some((e: Node) => this.of(e)) ? "value" : null;
      case "BinaryExpression":
        return n.operator === "+" && (this.of(n.left) || this.of(n.right)) ? "value" : null;
      case "LogicalExpression":
        return this.of(n.left) ?? this.of(n.right);
      case "ConditionalExpression":
        return this.of(n.consequent) ?? this.of(n.alternate);
      case "ObjectExpression":
        return n.properties.some((p: Node) => p.type === "SpreadElement" && this.of(p.argument) === "object") ? "object" : null;
      default:
        return null;
    }
  }

  bind(pattern: Node | null | undefined, t: Taint | null): boolean {
    if (!pattern || !t) return false;
    let changed = false;
    const set = (name: string, v: Taint) => {
      if (this.map.get(name) !== v && !(this.map.get(name) === "object" && v === "value")) { this.map.set(name, v); changed = true; }
    };
    if (pattern.type === "Identifier") set(pattern.name, t);
    else if (pattern.type === "ObjectPattern") {
      for (const p of pattern.properties) {
        if (p.type === "RestElement") changed = this.bind(p.argument, t === "checked" ? "checked" : "object") || changed;
        else {
          const key = propKey(p);
          // `{ params }` / `{ body }` keep the whole object; any other field is one value.
          const inner: Taint = t === "checked" ? "checked" : key && /^(?:params|body|query|searchParams)$/.test(key) ? "object" : "value";
          changed = this.bind(p.value?.type === "AssignmentPattern" ? p.value.left : p.value, inner) || changed;
        }
      }
    } else if (pattern.type === "ArrayPattern") {
      for (const el of pattern.elements) changed = this.bind(el?.type === "AssignmentPattern" ? el.left : el, t === "checked" ? "checked" : "value") || changed;
    } else if (pattern.type === "AssignmentPattern") changed = this.bind(pattern.left, t);
    return changed;
  }

  /** Follow assignments in the body until nothing new is tainted. */
  spread(body: Node): void {
    for (let round = 0; round < 4; round++) {
      let changed = false;
      visit(body, (n) => {
        if (n.type === "VariableDeclarator") changed = this.bind(n.id, this.of(n.init)) || changed;
        else if (n.type === "AssignmentExpression" && n.operator === "=") changed = this.bind(n.left, this.of(n.right)) || changed;
        else if (n.type === "ForOfStatement") {
          const t = this.of(n.right);
          const decl = n.left.type === "VariableDeclaration" ? n.left.declarations[0]?.id : n.left;
          changed = this.bind(decl, t ? "value" : null) || changed;
        }
      });
      if (!changed) break;
    }
  }
}

// ---------- project index (functions and imports, for following calls) ----------

interface FileInfo {
  rel: string;
  ast: Node;
  fns: Map<string, Node>;
  imports: Map<string, { from: string; name: string }>;
  exportsMap: Map<string, string>;
  lines: string[];
  directive: boolean;
}

function parseFile(f: FlowFile): Node | null {
  const plugins: any[] = f.ext === ".ts" ? ["typescript"] : f.ext === ".tsx" ? ["typescript", "jsx"] : ["jsx"];
  try {
    return parse(f.text, {
      sourceType: "unambiguous", errorRecovery: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true, plugins: [...plugins, "decorators-legacy", "importAttributes", "explicitResourceManagement"],
    }) as unknown as Node;
  } catch {
    return null;
  }
}

function indexFile(f: FlowFile, ast: Node): FileInfo {
  const fns = new Map<string, Node>();
  const imports = new Map<string, { from: string; name: string }>();
  const exportsMap = new Map<string, string>();
  const body: Node[] = ast.program?.body ?? [];
  const directive = (ast.program?.directives ?? []).some((d: Node) => d.value?.value === "use server");
  const addDecl = (d: Node) => {
    if (d.type === "FunctionDeclaration" && d.id) fns.set(d.id.name, d);
    if (d.type === "VariableDeclaration") {
      for (const v of d.declarations) {
        if (v.id.type !== "Identifier") continue;
        const init = unwrapExpr(v.init);
        if (init) fns.set(v.id.name, init);
      }
    }
  };
  for (const s of body) {
    if (s.type === "ImportDeclaration") {
      for (const sp of s.specifiers) {
        const name = sp.type === "ImportDefaultSpecifier" ? "default" : sp.type === "ImportNamespaceSpecifier" ? "*" : sp.imported?.name ?? sp.imported?.value;
        imports.set(sp.local.name, { from: s.source.value, name });
      }
    } else if (s.type === "ExportNamedDeclaration") {
      if (s.declaration) {
        addDecl(s.declaration);
        if (s.declaration.id) exportsMap.set(s.declaration.id.name, s.declaration.id.name);
        for (const v of s.declaration.declarations ?? []) if (v.id.type === "Identifier") exportsMap.set(v.id.name, v.id.name);
      }
      for (const sp of s.specifiers ?? []) {
        const exported = sp.exported?.name ?? sp.exported?.value;
        if (s.source) imports.set(`__reexport_${exported}`, { from: s.source.value, name: sp.local?.name ?? exported });
        else exportsMap.set(exported, sp.local.name);
      }
    } else if (s.type === "ExportDefaultDeclaration") {
      const d = s.declaration;
      if (d.type === "Identifier") exportsMap.set("default", d.name);
      else { fns.set("__default", unwrapExpr(d)!); exportsMap.set("default", "__default"); }
    } else addDecl(s);
  }
  return { rel: f.rel, ast, fns, imports, exportsMap, lines: f.text.split(/\r?\n/), directive };
}

class Project {
  files = new Map<string, FileInfo>();
  private authMemo = new Map<Node, boolean>();
  private dbMemo = new Map<Node, boolean>();
  constructor(private root: string) {}

  add(info: FileInfo) { this.files.set(info.rel, info); }

  private resolveModule(fromRel: string, spec: string): FileInfo | null {
    const candidates: string[] = [];
    if (spec.startsWith(".")) candidates.push(normalize(join(dirname(fromRel), spec)));
    else if (/^[@~]\//.test(spec) || spec.startsWith("#/")) {
      // `@/lib/x`: from the package root (nearest package.json) or its src/ folder.
      let dir = dirname(fromRel);
      for (;;) {
        if (existsSync(join(this.root, dir, "package.json")) || dir === "." || dir === "") break;
        dir = dirname(dir);
      }
      const base = dir === "." ? "" : dir;
      candidates.push(normalize(join(base, spec.slice(2))), normalize(join(base, "src", spec.slice(2))));
    } else return null;
    for (const c of candidates) {
      const clean = c.replace(/\\/g, "/").replace(/^\.\//, "");
      for (const ext of ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js"]) {
        const hit = this.files.get(clean + ext);
        if (hit) return hit;
      }
    }
    return null;
  }

  /** The function node a name refers to in this file (local, imported, re-exported). */
  resolve(file: FileInfo, name: string, depth = 0): { fn: Node; file: FileInfo } | null {
    if (depth > 4) return null;
    const local = file.fns.get(name);
    if (local) {
      if (local.type === "Identifier") return this.resolve(file, local.name, depth + 1);
      return isFn(local) || isCall(local) ? { fn: local, file } : null;
    }
    const imp = file.imports.get(name);
    if (!imp) return null;
    const target = this.resolveModule(file.rel, imp.from);
    if (!target) return null;
    return this.resolveExport(target, imp.name, depth + 1);
  }

  resolveExport(file: FileInfo, exported: string, depth = 0): { fn: Node; file: FileInfo } | null {
    if (depth > 5) return null;
    const local = file.exportsMap.get(exported);
    if (local) return this.resolve(file, local, depth + 1);
    const re = file.imports.get(`__reexport_${exported}`);
    if (re) {
      const target = this.resolveModule(file.rel, re.from);
      return target ? this.resolveExport(target, re.name, depth + 1) : null;
    }
    return null;
  }

  /** Does this function (or one it calls, a few levels down) check who the caller is? */
  hasAuth(fn: Node, file: FileInfo, depth = 0): boolean {
    const memo = this.authMemo.get(fn);
    if (memo !== undefined) return memo;
    this.authMemo.set(fn, false);
    let found = false;
    visit(fn, (n) => {
      if (found) return false;
      if (isCall(n)) {
        const name = calleeName(n);
        const p = memberPath(n.callee);
        if (AUTH_EXACT.has(name) || (AUTH_WORD.test(name) && !DB_ROOT.test(p[0] ?? ""))) { found = true; return false; }
        if (name === "get" && n.arguments[0]?.type === "StringLiteral" && /authorization|api-?key|token|secret|signature/i.test(n.arguments[0].value)) { found = true; return false; }
        if (depth < 4 && n.callee.type === "Identifier") {
          const target = this.resolve(file, n.callee.name);
          if (target && isFn(target.fn) && this.hasAuth(target.fn, target.file, depth + 1)) { found = true; return false; }
        }
      }
      // A shared secret compared with what the request sent (cron jobs, internal calls).
      if (n.type === "BinaryExpression" && /^[!=]==?$/.test(n.operator)) {
        const sides = [memberPath(n.left).join("."), memberPath(n.right).join(".")];
        if (sides.some((s) => /^process\.env\.\w*(?:SECRET|TOKEN|KEY)\w*$/i.test(s))) { found = true; return false; }
      }
    });
    this.authMemo.set(fn, found);
    return found;
  }

  touchesDb(fn: Node, file: FileInfo, depth = 0): boolean {
    const memo = this.dbMemo.get(fn);
    if (memo !== undefined) return memo;
    this.dbMemo.set(fn, false);
    let found = false;
    visit(fn, (n) => {
      if (found) return false;
      if (n.type === "TaggedTemplateExpression" && DB_ROOT.test(memberPath(n.tag)[0] ?? "")) { found = true; return false; }
      if (isCall(n)) {
        const p = memberPath(n.callee);
        const name = calleeName(n);
        if ((DB_ROOT.test(p[0] ?? "") && p.length >= 2) || /^\$(?:queryRaw|executeRaw)/.test(name) || MODEL_CALL(p, name)) { found = true; return false; }
        if (depth < 2 && n.callee.type === "Identifier") {
          const target = this.resolve(file, n.callee.name);
          if (target && isFn(target.fn) && this.touchesDb(target.fn, target.file, depth + 1)) { found = true; return false; }
        }
      }
    });
    this.dbMemo.set(fn, found);
    return found;
  }
}

// ---------- handlers ----------

interface Handler {
  file: FileInfo;
  fn: Node;
  /** Wrappers / middleware applied around it (`withAuth(handler)`, `app.get(path, requireUser, handler)`). */
  guards: Node[];
  kind: "route" | "action";
  path: string;
  label: string;
  reqNames: Set<string>;
  /** Every parameter is client-controlled (server actions). */
  allParams: boolean;
}

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const APP_ROUTE = /(?:^|\/)app\/(?:.*\/)?route\.(?:t|j)sx?$/;
const PAGES_API = /(?:^|\/)pages\/api\//;
const ROUTER_OBJ = /^(?:app|router|api|server|routes?|r|hono|fastify)$/;

function paramNames(fn: Node): Node[] {
  return (fn.params ?? []).map((p: Node) => (p.type === "AssignmentPattern" ? p.left : p));
}

function findHandlers(project: Project, file: FileInfo): Handler[] {
  const out: Handler[] = [];
  const routePath = file.rel.replace(/\/route\.\w+$/, "");
  const fromExport = (name: string, label: string, kind: Handler["kind"]) => {
    let target = project.resolveExport(file, name);
    const guards: Node[] = [];
    // export const POST = withAuth(async (req) => …)
    for (let i = 0; target && isCall(target.fn) && i < 3; i++) {
      guards.push(target.fn);
      const inner = target.fn.arguments.map(unwrapExpr).find((a: Node) => isFn(a) || a?.type === "Identifier");
      if (!inner) { target = null; break; }
      target = isFn(inner) ? { fn: inner, file: target.file } : project.resolve(target.file, inner.name);
    }
    if (!target || !isFn(target.fn)) return;
    const params = paramNames(target.fn);
    const reqNames = new Set<string>();
    if (kind === "route" && params[0]?.type === "Identifier") reqNames.add(params[0].name);
    out.push({ file, fn: target.fn, guards, kind, path: routePath, label, reqNames, allParams: kind === "action" });
    const h = out[out.length - 1];
    // Next.js: (req, ctx) → ctx.params is request data; (req, { params }) is bound in analyzeHandler.
    if (kind === "route" && params[1]?.type === "Identifier") h.reqNames.add(params[1].name);
  };

  if (APP_ROUTE.test(file.rel)) {
    for (const m of HTTP_METHODS) if (file.exportsMap.has(m) || file.imports.has(`__reexport_${m}`)) fromExport(m, `${m} ${routePath}`, "route");
  } else if (PAGES_API.test(file.rel) && file.exportsMap.has("default")) {
    fromExport("default", `API ${file.rel}`, "route");
  }
  if (file.directive) {
    for (const name of file.exportsMap.keys()) if (name !== "default" || file.exportsMap.size === 1) fromExport(name, `server action ${name}()`, "action");
  } else {
    // Inline server actions: async functions whose body starts with "use server".
    visit(file.ast, (n) => {
      if (isFn(n) && n.body?.directives?.some((d: Node) => d.value?.value === "use server")) {
        out.push({ file, fn: n, guards: [], kind: "action", path: file.rel, label: `server action ${n.id?.name ?? "(inline)"}`, reqNames: new Set(), allParams: true });
      }
    });
  }
  // Express / Hono / Fastify: app.post('/path', mw…, handler)
  const fileGuards: Node[] = [];
  visit(file.ast, (n) => {
    if (!isCall(n) || n.callee.type !== "MemberExpression") return;
    const p = memberPath(n.callee);
    const obj = p[0] ?? "";
    const method = p[p.length - 1];
    if (!ROUTER_OBJ.test(obj)) return;
    if (method === "use") { fileGuards.push(...n.arguments); return; }
    if (!/^(?:get|post|put|patch|delete|all)$/.test(method)) return;
    const [first, ...rest] = n.arguments;
    if (first?.type !== "StringLiteral" || !first.value.startsWith("/")) return;
    const last = unwrapExpr(rest[rest.length - 1]);
    let handler: Node | null = isFn(last) ? last! : last?.type === "Identifier" ? project.resolve(file, last.name)?.fn ?? null : null;
    if (!handler || !isFn(handler)) return;
    const reqNames = new Set<string>();
    const ps = paramNames(handler);
    if (ps[0]?.type === "Identifier") reqNames.add(ps[0].name);
    out.push({ file, fn: handler, guards: [...rest.slice(0, -1), ...fileGuards], kind: "route", path: first.value,
      label: `${method.toUpperCase()} ${first.value}`, reqNames, allParams: false });
  });
  return out;
}

// ---------- checks ----------

function guardIsAuth(project: Project, file: FileInfo, g: Node): boolean {
  const n = unwrapExpr(g);
  if (!n) return false;
  const name = n.type === "Identifier" ? n.name : isCall(n) ? calleeName(n) : memberPath(n).pop() ?? "";
  if (AUTH_EXACT.has(name) || AUTH_WORD.test(name)) return true;
  const target = n.type === "Identifier" ? project.resolve(file, n.name) : isCall(n) && n.callee.type === "Identifier" ? project.resolve(file, n.callee.name) : null;
  return !!target && isFn(target.fn) && project.hasAuth(target.fn, target.file);
}

function analyzeHandler(project: Project, h: Handler, middlewareAuth: boolean, hits: FlowHit[]): void {
  const { fn, file } = h;
  const authed = h.guards.some((g) => guardIsAuth(project, file, g)) || project.hasAuth(fn, file);
  const hit = (id: keyof typeof GUIDE, title: string, severity: string, confidence: string, controls: number[], at: Node) =>
    hits.push({ id, title, severity, confidence, controls, rel: file.rel, line: line(at), guidance: GUIDE[id] });

  // Taint: the request (routes) or every parameter (server actions).
  const taints = new Taints(h.reqNames);
  const ps = paramNames(fn);
  if (h.allParams) for (const p of ps) taints.bind(p, p.type === "Identifier" ? "object" : "value");
  else if (ps[1]?.type === "ObjectPattern") taints.bind(ps[1], "object"); // ({ params }) → params is request data
  if (fn.body) taints.spread(fn.body);

  const rootId = (e: Node | null | undefined): string | null => {
    const n = unwrapExpr(e);
    if (!n) return null;
    if (n.type === "Identifier") return n.name;
    if (n.type === "MemberExpression") return rootId(n.object);
    if (n.type === "NewExpression" || isCall(n)) return rootId(n.arguments?.[0]);
    if (n.type === "TemplateLiteral") return rootId(n.expressions[0]);
    return null;
  };

  // SEC044: nobody has to sign in, and the handler reaches the database.
  if (!authed && !PUBLIC_PATH.test(h.path)) {
    let deliberate = false;
    visit(fn, (n) => {
      if (deliberate) return false;
      if (isCall(n) && PUBLIC_GUARD.test(calleeName(n))) deliberate = true;
      // A lookup by a secret from the request (share token, API key, invite code) is the access check.
      if (n.type === "ObjectProperty" && CAPABILITY_KEY.test(propKey(n) ?? "") && taints.of(n.shorthand ? n.key : n.value)) deliberate = true;
    });
    if (!deliberate && project.touchesDb(fn, file)) {
      const what = h.kind === "action" ? "Server action" : "API route";
      hit("SEC044", `${what} with no login check: ${h.label}`, middlewareAuth ? "Medium" : "High", middlewareAuth ? "low" : "medium", [2, 3], fn);
    }
  }

  // Who the caller is: variables holding the result of a sign-in call (user, session, ws = currentWorkspace(user)).
  const authVars = new Set<string>();
  let adminOnly = false;
  for (let round = 0; round < 3; round++) {
    visit(fn, (n) => {
      if (n.type !== "VariableDeclarator") return;
      const init = unwrapExpr(n.init);
      if (!isCall(init)) return;
      const name = calleeName(init!);
      const fromAuth = AUTH_EXACT.has(name) || AUTH_WORD.test(name) ||
        init!.arguments.some((a: Node) => { const r = rootId(a); return !!r && authVars.has(r); });
      if (!fromAuth || DB_ROOT.test(memberPath(init!.callee)[0] ?? "")) return;
      const names: string[] = [];
      visit(n.id, (x) => { if (x.type === "Identifier") names.push(x.name); });
      names.forEach((x) => authVars.add(x));
    });
  }
  visit(fn, (n) => {
    if (isCall(n) && /admin|staff|superuser/i.test(calleeName(n)) && (AUTH_EXACT.has(calleeName(n)) || AUTH_WORD.test(calleeName(n)))) adminOnly = true;
  });

  // The variable each lookup's result lands in: `const result = await prisma.x.findUnique(…)`.
  const declOf = new Map<Node, string>();
  visit(fn, (n) => {
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init) {
      visit(n.init, (c) => { if (isCall(c)) declOf.set(c, n.id.name); });
    }
  });

  // A check only counts when its answer decides something: used in an if / ?: / && test, or a guard that throws.
  const inTest = new Set<Node>();
  const testIdents = new Set<string>();
  visit(fn, (n) => {
    const test = n.type === "IfStatement" || n.type === "ConditionalExpression" ? n.test : n.type === "LogicalExpression" ? n.left : null;
    if (!test) return;
    visit(test, (x) => { if (isCall(x)) inTest.add(x); if (x.type === "Identifier") testIdents.add(x.name); });
  });
  const statementCalls = new Set<Node>();
  visit(fn, (n) => {
    if (n.type === "ExpressionStatement") { const e = unwrapExpr(n.expression); if (isCall(e)) statementCalls.add(e!); }
  });
  const decides = (call: Node) => inTest.has(call) || testIdents.has(declOf.get(call) ?? "\u0000") ||
    (statementCalls.has(call) && /^(?:assert|require|ensure|check|verify|authorize|guard|protect)/i.test(calleeName(call)));

  // Ids the handler already checked: passed to a helper together with the caller (runToManage(id, user)), to a helper
  // that checks the caller itself, or used in a query that is scoped to an owner or tenant.
  const authorized = new Set<string>();
  visit(fn, (n) => {
    if (!isCall(n)) return;
    const p = memberPath(n.callee);
    if (DB_ROOT.test(p[0] ?? "")) {
      const a0 = unwrapExpr(n.arguments[0]);
      const where = a0?.type === "ObjectExpression" ? unwrapExpr(a0.properties.find((pr: Node) => propKey(pr) === "where")?.value) : null;
      if (where?.type === "ObjectExpression") {
        let scoped = false;
        visit(where, (x) => { if (x.type === "ObjectProperty" && OWNER_KEY.test(propKey(x) ?? "") && propKey(x) !== "id") scoped = true; });
        if (scoped) visit(where, (x) => { if (x.type === "ObjectProperty") { const r = rootId(x.shorthand ? x.key : x.value); if (r) authorized.add(r); } });
      }
      return;
    }
    const roots = n.arguments.map((a: Node) => rootId(a));
    const withCaller = roots.some((r: string | null) => r && authVars.has(r));
    const cname = calleeName(n);
    let checksCaller = withCaller || AUTH_EXACT.has(cname) || AUTH_WORD.test(cname); // feedbackShotSigOk(id, sig)
    if (!checksCaller && n.callee.type === "Identifier") {
      const target = project.resolve(file, n.callee.name);
      checksCaller = !!target && isFn(target.fn) && project.hasAuth(target.fn, target.file);
    }
    if (checksCaller && decides(n)) roots.forEach((r: string | null) => { if (r && !authVars.has(r)) authorized.add(r); });
  });

  // Values checked against an allowlist or a prefix count as validated for redirects / fetches.
  const validated = new Set<string>();
  visit(fn, (n) => {
    if (!isCall(n)) return;
    const name = calleeName(n);
    if (/^(?:startsWith|endsWith|includes|has|test|match)$/.test(name)) {
      for (const a of [n.callee.object, ...n.arguments]) { const id = unwrapExpr(a); if (id?.type === "Identifier") validated.add(id.name); }
    }
    if (/^(?:isAllowed|isSafe|isPublic|safe|allowed|isInternal|sameOrigin|isRelative)\w*/i.test(name)) {
      for (const a of n.arguments) { const id = unwrapExpr(a); if (id?.type === "Identifier") validated.add(id.name); }
    }
  });

  // Ownership checked somewhere in the handler: record.userId !== user.id, canEdit(user, doc) …
  let ownershipChecked = false;
  visit(fn, (n) => {
    if (ownershipChecked) return false;
    if (n.type === "BinaryExpression" && /^[!=]==?$/.test(n.operator)) {
      const keys = [memberPath(n.left).pop() ?? "", memberPath(n.right).pop() ?? ""];
      if (keys.some((k) => OWNER_KEY.test(k))) ownershipChecked = true;
    }
    if (isCall(n)) {
      const name = calleeName(n);
      if (OWNERSHIP_CHECK.test(name) && !SIGN_IN_ONLY.test(name) && !DB_ROOT.test(memberPath(n.callee)[0] ?? "")) ownershipChecked = true;
    }
  });

  visit(fn, (n) => {
    if (!isCall(n)) return;
    const p = memberPath(n.callee);
    const name = calleeName(n);
    const onDb = DB_ROOT.test(p[0] ?? "") && p.length >= 2;
    const arg0 = unwrapExpr(n.arguments[0]);

    // SEC045: a record found or changed by an id from the request, no owner in the query, no check after.
    if (authed && !adminOnly && !ownershipChecked && onDb && BY_ID_LOOKUP.has(name) && arg0?.type === "ObjectExpression") {
      const where = arg0.properties.find((pr: Node) => propKey(pr) === "where");
      const w = unwrapExpr(where?.value);
      if (w?.type === "ObjectExpression") {
        const keys: string[] = [];
        let byRequestId = false;
        visit(w, (x) => {
          if (x.type !== "ObjectProperty") return;
          const k = propKey(x) ?? "";
          keys.push(k);
          const v = x.shorthand ? x.key : x.value;
          const r = rootId(v);
          if (ID_KEY.test(k) && !OWNER_KEY.test(k) && taints.of(v) && !(r && authorized.has(r))) byRequestId = true;
          // Also filtered by a parent the handler already checked: where: { id: resultId, runId: id }
          else if (k !== "id" && /(?:Id|_id)$/.test(k) && r && (authorized.has(r) || authVars.has(r))) keys.push("__scoped");
        });
        // …or the record itself is checked right after: runToManage(result.runId, user)
        const checkedAfter = authorized.has(declOf.get(n) ?? "");
        if (byRequestId && !checkedAfter && !keys.some((k) => k === "__scoped" || (OWNER_KEY.test(k) && !/^(?:id)$/.test(k)))) {
          hit("SEC045", `Record ${name === "update" || name === "delete" || name === "upsert" ? "changed" : "read"} by an id from the request with no owner check (${p.slice(0, -1).join(".")})`,
            "High", "medium", [9, 1], n);
        }
      }
    }
    if (authed && !adminOnly && !ownershipChecked && /^(?:findById|findByIdAndUpdate|findByIdAndDelete)$/.test(name) && taints.of(n.arguments[0]) && !authorized.has(rootId(n.arguments[0]) ?? "")) {
      hit("SEC045", `Record looked up by an id from the request with no owner check (${p.join(".")})`, "High", "medium", [9, 1], n);
    }

    // SEC046 / SEC047: writes.
    // Mongoose-style models (Post.create(x)) count; other SDKs' create() (Stripe, OpenAI) don't.
    const model = !onDb && /^[A-Z]\w*$/.test(p[0] ?? "") && p.length === 2 && /^(?:create|insertMany|updateOne|findByIdAndUpdate|findOneAndUpdate)$/.test(name);
    if ((onDb || model) && DB_WRITE.has(name)) {
      const dataArgs: Node[] = [];
      if (arg0?.type === "ObjectExpression" && onDb && !/^(?:values|set|insert)$/.test(name)) {
        for (const pr of arg0.properties) {
          if (pr.type === "ObjectProperty" && /^(?:data|create|update)$/.test(propKey(pr) ?? "")) dataArgs.push(unwrapExpr(pr.value)!);
        }
        if (!dataArgs.length && /^(?:create|insertOne|insertMany|save)$/.test(name)) dataArgs.push(arg0);
      } else if (/^(?:values|set|insert|insertOne|insertMany|update|upsert|create)$/.test(name) && arg0) dataArgs.push(arg0);
      if (/^(?:findByIdAndUpdate|findOneAndUpdate|updateOne)$/.test(name) && n.arguments[1]) dataArgs.push(unwrapExpr(n.arguments[1])!);
      for (const d of dataArgs) {
        if (!d) continue;
        if (taints.of(d) === "object") {
          hit("SEC046", `Request body written straight to the database (${p.join(".")})`, "High", "medium", [3, 5], n);
          continue;
        }
        if (d.type === "ObjectExpression") {
          for (const pr of d.properties) {
            if (pr.type !== "ObjectProperty") continue;
            const k = propKey(pr) ?? "";
            const v = pr.shorthand ? pr.key : pr.value;
            // A tenant id from the URL is fine once the handler checked membership; role and price never are.
            const ownerField = OWNER_KEY.test(k) && !/role|admin|staff|permission|plan|price|amount|total|credit|balance|tier/i.test(k);
            if (TRUSTED_FIELD.test(k) && taints.of(v) && taints.of(v) !== "checked" && !(ownerField && ownershipChecked)) {
              hit("SEC047", `'${k}' is taken from the request in a database write (${p.join(".")})`, "High", "medium", [3, 9], pr);
            }
          }
        }
      }
    }

    // SEC048: request input into raw SQL, a shell, or eval.
    const tainted = (e: Node | undefined) => {
      const t = taints.of(e);
      return t && t !== "checked" ? t : null;
    };
    if (/^\$(?:queryRawUnsafe|executeRawUnsafe)$/.test(name) || (name === "raw" && /^(?:sql|knex|Prisma)$/.test(p[0] ?? "")) || /^(?:whereRaw|selectRaw|orderByRaw|havingRaw)$/.test(name)) {
      if (tainted(n.arguments[0])) {
        hit("SEC048", `Request input reaches raw SQL (${p.join(".")})`, "Critical", "high", [6, 5], n);
      }
    } else if (onDb && /^(?:query|execute|run|all|get|exec)$/.test(name) && (arg0?.type === "TemplateLiteral" || arg0?.type === "BinaryExpression") && tainted(arg0)) {
      hit("SEC048", `Request input built into a SQL string (${p.join(".")})`, "Critical", "high", [6, 5], n);
    } else if (/^(?:exec|execSync)$/.test(name) && (n.callee.type === "Identifier" || /^(?:child_process|childProcess|cp|proc|shell)$/.test(p[0] ?? "")) && tainted(n.arguments[0])) {
      hit("SEC048", `Request input reaches a shell command (${name})`, "Critical", "high", [5], n);
    } else if (/^(?:spawn|spawnSync|execFile|execFileSync)$/.test(name) && n.arguments.some((a: Node) => {
      const x = unwrapExpr(a);
      return x?.type === "ObjectExpression" && x.properties.some((pr: Node) => propKey(pr) === "shell" && unwrapExpr(pr.value)?.value === true);
    }) && n.arguments.some((a: Node) => tainted(a) || (unwrapExpr(a)?.type === "ArrayExpression" && unwrapExpr(a)!.elements.some((e: Node) => tainted(e))))) {
      hit("SEC048", `Request input reaches a shell command (${name} with shell: true)`, "Critical", "high", [5], n);
    } else if ((n.callee.type === "Identifier" && n.callee.name === "eval") && tainted(n.arguments[0])) {
      hit("SEC048", "Request input is evaluated as code (eval)", "Critical", "high", [5], n);
    }

    // SEC049: request input picks the destination of a server request or a redirect.
    const dest = n.arguments[0];
    const destRoot = rootId(dest);
    const unchecked = tainted(dest) && !(destRoot && validated.has(destRoot));
    if (unchecked && (n.callee.type === "Identifier" && /^(?:fetch|got|request|axios|ky|undici)$/.test(n.callee.name) || /^(?:axios|got|ky|http|https|undici|superagent)$/.test(p[0] ?? "") && /^(?:get|post|put|patch|delete|request|head|fetch)$/.test(name))) {
      const d = unwrapExpr(dest);
      // `${API}/users/${id}`: the host is fixed, only the path varies.
      const fixedHost = d?.type === "TemplateLiteral" && (d.quasis[0]?.value?.raw ?? "").match(/^https?:\/\/[^/]+\//);
      const fixedBase = d?.type === "TemplateLiteral" && d.quasis[0]?.value?.raw === "" && d.expressions[0] && !taints.of(d.expressions[0]);
      if (!fixedHost && !fixedBase) hit("SEC049", `Request input decides where the server sends a request (${p.join(".")})`, "High", "high", [20], n);
    }
    if (unchecked && /^(?:redirect|permanentRedirect)$/.test(name) && (n.callee.type === "Identifier" || /^(?:res|reply|NextResponse|Response|c|ctx)$/.test(p[0] ?? ""))) {
      const d = unwrapExpr(dest);
      const inner = d?.type === "NewExpression" ? unwrapExpr(d.arguments[0]) : d;
      const first = inner?.type === "TemplateLiteral" ? inner.quasis[0]?.value?.raw ?? "" : null;
      const relative = first !== null && /^\/(?!\/)/.test(first);
      const fixedHost = first !== null && /^https?:\/\/[^/]+\//.test(first);
      const fixedBase = first === "" && inner!.expressions[0] && !taints.of(inner!.expressions[0]);
      if (!relative && !fixedHost && !fixedBase) hit("SEC049", `Request input decides where the user is redirected (${p.join(".")})`, "Medium", "high", [20], n);
    }
  });
}

/** Project-wide: is there a Next.js middleware / proxy that checks sign-in? */
function middlewareChecksAuth(project: Project): boolean {
  for (const f of project.files.values()) {
    if (!/(?:^|\/)(?:src\/)?(?:middleware|proxy)\.(?:t|j)s$/.test(f.rel)) continue;
    for (const fn of f.fns.values()) if (isFn(fn) && project.hasAuth(fn, f)) return true;
    const def = project.resolveExport(f, "default") ?? project.resolveExport(f, "middleware") ?? project.resolveExport(f, "proxy");
    if (def && (isCall(def.fn) ? guardIsAuth(project, f, def.fn) : project.hasAuth(def.fn, f))) return true;
  }
  return false;
}

export function analyzeFlows(root: string, files: FlowFile[]): FlowHit[] {
  const project = new Project(root);
  for (const f of files) {
    if (/\.d\.ts$|\.min\.js$/.test(f.rel)) continue;
    const ast = parseFile(f);
    if (ast) project.add(indexFile(f, ast));
  }
  const middlewareAuth = middlewareChecksAuth(project);
  const hits: FlowHit[] = [];
  for (const file of project.files.values()) {
    for (const h of findHandlers(project, file)) {
      try {
        analyzeHandler(project, h, middlewareAuth, hits);
      } catch { /* one odd file never stops the scan */ }
    }
  }
  const seen = new Set<string>();
  return hits.filter((x) => {
    const k = `${x.id}|${x.rel}|${x.line}|${x.title}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : a.line - b.line));
}
