/**
 * Architecture and deployment checks, any stack: Dockerfiles, docker-compose, Kubernetes manifests,
 * GitHub Actions workflows, Terraform, and database server configs (pg_hba.conf, mongod.conf, redis.conf).
 * YAML is parsed (multi-document); line numbers point at the setting itself.
 *
 *   SEC052 container runs as root (no USER)            SEC056 database reachable from anywhere / weak auth
 *   SEC053 secret baked into an image or manifest       SEC057 CI workflow runs untrusted code with secrets
 *   SEC054 base image or action not pinned              SEC058 privileged container / host access
 *   SEC055 cloud resource open to the internet
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { LineCounter, parseAllDocuments, isMap, isSeq, isScalar, isPair, type Node as YNode } from "yaml";

export interface InfraHit {
  id: string; title: string; severity: string; confidence: string; controls: number[];
  rel: string; line: number; guidance: string;
}

const G = {
  SEC052: "Add a non-root USER to the final stage (create one with a fixed UID) so a compromise of the app is not root in the container.",
  SEC053: "Secrets in an image or a committed manifest are readable by anyone who can pull or clone it. Pass them at runtime (secret store, orchestrator secrets, CI secrets) and rotate this one.",
  SEC054: "Pin to an exact version (and for GitHub Actions from outside actions/* to a full commit SHA) so a moved tag can't change what you run.",
  SEC055: "Restrict the source range to known addresses (VPN, office, load balancer) or put the resource in a private subnet; never 0.0.0.0/0 on admin or database ports.",
  SEC056: "Bind the database to localhost or a private network, require a strong password (or certificate auth), and never use trust / no-auth modes outside a throwaway local setup.",
  SEC057: "Workflows triggered by outside contributors must not check out and run their code with secrets or a write token. Use pull_request (not pull_request_target) for builds, and pass untrusted text through env: variables instead of ${{ }} inside run:.",
  SEC058: "Drop privileged mode, host namespaces and hostPath mounts; set runAsNonRoot: true and allowPrivilegeEscalation: false.",
};

const SECRET_NAME = /(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)/i;
const PLACEHOLDER = /^(?:\$\{?[\w:-]+\}?|<[^>]*>|changeme|change_me|example|xxx+|\*+|)$/i;
const DB_IMAGE = /(?:^|\/)(postgres|postgis|mysql|mariadb|mongo|redis|valkey|elasticsearch|opensearch|cassandra|couchdb|memcached|rabbitmq|clickhouse)(?::|@|$)/i;
const DB_PORTS = new Set([5432, 3306, 27017, 27018, 6379, 9200, 9300, 9042, 5984, 11211, 5672, 15672, 8123, 9000, 1433, 1521]);
const ADMIN_PORTS = new Set([22, 3389, 2375, 2376, 6443, 10250]);

// ---------- YAML helpers ----------

type Doc = { node: YNode | null | undefined; lc: LineCounter };
const lineAt = (d: Doc, n: any): number => {
  const at = isPair(n) ? (n.key ?? n.value) : n;
  return at?.range ? d.lc.linePos(at.range[0]).line : 1;
};
function get(n: any, ...path: (string | number)[]): any {
  let cur = n;
  for (const k of path) {
    if (!cur) return undefined;
    if (isMap(cur)) cur = (cur.items.find((p: any) => isScalar(p.key) && String(p.key.value) === String(k)) as any)?.value;
    else if (isSeq(cur) && typeof k === "number") cur = cur.items[k];
    else return undefined;
  }
  return cur;
}
const val = (n: any): unknown => (isScalar(n) ? n.value : undefined);
const str = (n: any): string => { const v = val(n); return v === undefined || v === null ? "" : String(v); };
const pairs = (n: any): any[] => (isMap(n) ? n.items.filter(isPair) : []);
const items = (n: any): any[] => (isSeq(n) ? n.items : []);

function yamlDocs(text: string): Doc[] {
  const lc = new LineCounter();
  try {
    return parseAllDocuments(text, { lineCounter: lc, strict: false, uniqueKeys: false } as any)
      .filter((d: any) => !Array.isArray(d) && d.contents).map((d: any) => ({ node: d.contents, lc }));
  } catch {
    return [];
  }
}

// ---------- Dockerfile ----------

function dockerfile(rel: string, text: string, out: InfraHit[]) {
  const lines = text.split(/\r?\n/);
  // Join continuation lines but keep the first line number.
  const ins: { line: number; cmd: string; args: string }[] = [];
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let l = lines[i];
    while (/\\\s*$/.test(l) && i + 1 < lines.length) l = l.replace(/\\\s*$/, " ") + lines[++i];
    const m = /^\s*([A-Za-z]+)\s+(.*)$/.exec(l);
    if (m && !l.trim().startsWith("#")) ins.push({ line: start + 1, cmd: m[1].toUpperCase(), args: m[2].trim() });
  }
  const stages: number[] = ins.map((x, i) => (x.cmd === "FROM" ? i : -1)).filter((i) => i >= 0);
  if (!stages.length) return;
  const last = stages[stages.length - 1];
  const finalStage = ins.slice(last);
  const user = finalStage.filter((x) => x.cmd === "USER").pop();
  const from = ins[last];
  const image = from.args.replace(/--\S+\s+/g, "").split(/\s+/)[0];
  const scratchLike = /^(?:scratch|gcr\.io\/distroless\/.*nonroot.*|.*:nonroot|cgr\.dev\/.*)$/i.test(image);
  if (!scratchLike && (!user || /^(?:root|0)(?::|$)/.test(user.args))) {
    out.push({ id: "SEC052", title: `Container runs as root (${image})`, severity: "Medium", confidence: "medium", controls: [14],
      rel, line: user?.line ?? from.line, guidance: G.SEC052 });
  }
  const aliases = new Set(ins.filter((x) => x.cmd === "FROM").map((x) => /\bAS\s+(\S+)/i.exec(x.args)?.[1]?.toLowerCase()).filter(Boolean));
  for (const x of ins) {
    if (x.cmd === "FROM") {
      const img = x.args.replace(/--\S+\s+/g, "").split(/\s+/)[0];
      if (!aliases.has(img.toLowerCase()) && img !== "scratch" && !img.includes("$") && !img.includes("@sha256:") && (!img.includes(":") || /:latest$/.test(img))) {
        out.push({ id: "SEC054", title: `Base image not pinned to a version (${img})`, severity: "Low", confidence: "high", controls: [15], rel, line: x.line, guidance: G.SEC054 });
      }
    }
    if (x.cmd === "ENV" || x.cmd === "ARG") {
      for (const m of x.args.matchAll(/([A-Za-z_][\w]*)(?:\s*=\s*|\s+)("[^"]*"|'[^']*'|\S+)/g)) {
        const value = m[2].replace(/^["']|["']$/g, "");
        if (SECRET_NAME.test(m[1]) && !PLACEHOLDER.test(value) && value.length >= 6 && !/^\$/.test(value)) {
          out.push({ id: "SEC053", title: `Secret baked into the image (${x.cmd} ${m[1]})`, severity: "High", confidence: "medium", controls: [15], rel, line: x.line, guidance: G.SEC053 });
        }
      }
    }
    if ((x.cmd === "COPY" || x.cmd === "ADD") && /(?:^|\s|\/)(?:\.env(?:\.[\w.]+)?|id_rsa|\.npmrc|\.pypirc|credentials\.json|[\w-]+\.pem)(?:\s|$)/.test(x.args) && !/\.env\.example/.test(x.args)) {
      out.push({ id: "SEC053", title: "Secret file copied into the image", severity: "High", confidence: "medium", controls: [15], rel, line: x.line, guidance: G.SEC053 });
    }
  }
}

// ---------- docker-compose ----------

function compose(rel: string, docs: Doc[], out: InfraHit[]) {
  for (const d of docs) {
    for (const svc of pairs(get(d.node, "services"))) {
      const name = str(svc.key);
      const s = svc.value;
      const image = str(get(s, "image"));
      const db = DB_IMAGE.exec(image)?.[1]?.toLowerCase();
      for (const p of items(get(s, "ports"))) {
        const spec = isScalar(p) ? String(p.value) : str(get(p, "published")) && `${str(get(p, "host_ip"))}:${str(get(p, "published"))}:${str(get(p, "target"))}`;
        const m = /^(?:(\[?[\d.:a-f]+\]?):)?(\d+)(?:-\d+)?:(\d+)/i.exec(spec);
        if (!m) continue;
        const hostIp = m[1] ?? "";
        const local = /^(?:127\.|localhost|\[?::1\]?)/.test(hostIp);
        if (!local && (db || DB_PORTS.has(+m[3]))) {
          out.push({ id: "SEC056", title: `Database port published on every interface (${name}: ${spec})`, severity: "Medium", confidence: "medium", controls: [8],
            rel, line: lineAt(d, p), guidance: G.SEC056 + ` Use "127.0.0.1:${m[2]}:${m[3]}" for local access.` });
        }
      }
      const env = get(s, "environment");
      const envPairs: [string, string, any][] = isMap(env) ? pairs(env).map((p: any) => [str(p.key), str(p.value), p]) :
        items(env).map((e: any) => { const [k, ...v] = str(e).split("="); return [k, v.join("="), e]; });
      for (const [k, v, n] of envPairs) {
        if ((/^POSTGRES_HOST_AUTH_METHOD$/.test(k) && /^trust$/i.test(v)) || (/^(?:MYSQL|MARIADB)_ALLOW_EMPTY(?:_ROOT)?_PASSWORD$/.test(k) && /^(?:yes|true|1)$/i.test(v)) || (/^ALLOW_EMPTY_PASSWORD$/.test(k) && /^(?:yes|true)$/i.test(v))) {
          out.push({ id: "SEC056", title: `Database accepts connections without a password (${name}: ${k})`, severity: "High", confidence: "high", controls: [8], rel, line: lineAt(d, n), guidance: G.SEC056 });
        } else if (/(?:PASSWORD|_PASS)$/.test(k) && /^(?:postgres|password|root|admin|secret|mysql|123456|changeme|example|mongo|redis)$/i.test(v)) {
          out.push({ id: "SEC056", title: `Database uses a default password (${name}: ${k}=${v})`, severity: "Medium", confidence: "high", controls: [8], rel, line: lineAt(d, n), guidance: G.SEC056 });
        } else if (SECRET_NAME.test(k) && v.length >= 12 && !PLACEHOLDER.test(v) && !/^\$\{/.test(v) && !/default|password|example|changeme/i.test(v)) {
          out.push({ id: "SEC053", title: `Secret written into the compose file (${name}: ${k})`, severity: "High", confidence: "medium", controls: [15], rel, line: lineAt(d, n), guidance: G.SEC053 });
        }
      }
      if (/^(?:redis|valkey)$/.test(db ?? "") && items(get(s, "ports")).length && !/requirepass/.test(str(get(s, "command")) + JSON.stringify(get(s, "command")?.toJSON?.() ?? ""))) {
        out.push({ id: "SEC056", title: `Redis published without a password (${name})`, severity: "Medium", confidence: "medium", controls: [8], rel, line: lineAt(d, get(s, "ports")), guidance: G.SEC056 });
      }
      if (val(get(s, "privileged")) === true) out.push({ id: "SEC058", title: `Privileged container (${name})`, severity: "High", confidence: "high", controls: [14], rel, line: lineAt(d, get(s, "privileged")), guidance: G.SEC058 });
      if (/^host$/.test(str(get(s, "network_mode"))) || /^host$/.test(str(get(s, "pid")))) out.push({ id: "SEC058", title: `Container shares the host's network or processes (${name})`, severity: "Medium", confidence: "high", controls: [14], rel, line: lineAt(d, get(s, "network_mode") ?? get(s, "pid")), guidance: G.SEC058 });
      for (const v of items(get(s, "volumes"))) {
        if (/^\/var\/run\/docker\.sock|:\/var\/run\/docker\.sock/.test(str(v)) || /docker\.sock/.test(str(get(v, "source")))) {
          out.push({ id: "SEC058", title: `Docker socket mounted into a container (${name}): root on the host`, severity: "High", confidence: "high", controls: [14], rel, line: lineAt(d, v), guidance: G.SEC058 });
        }
      }
    }
  }
}

// ---------- Kubernetes ----------

function kubernetes(rel: string, docs: Doc[], out: InfraHit[]) {
  for (const d of docs) {
    const kind = str(get(d.node, "kind"));
    const name = str(get(d.node, "metadata", "name")) || kind;
    if (kind === "Secret") {
      const data = get(d.node, "data") ?? get(d.node, "stringData");
      const real = pairs(data).filter((p: any) => str(p.value).length >= 8 && !PLACEHOLDER.test(str(p.value)) && !/\{\{|\$\{/.test(str(p.value)));
      if (real.length) out.push({ id: "SEC053", title: `Kubernetes Secret with real values committed (${name})`, severity: "High", confidence: "medium", controls: [15], rel, line: lineAt(d, real[0]), guidance: G.SEC053 });
      continue;
    }
    const spec = kind === "Pod" ? get(d.node, "spec") : kind === "CronJob" ? get(d.node, "spec", "jobTemplate", "spec", "template", "spec") : get(d.node, "spec", "template", "spec");
    if (!spec) continue;
    for (const k of ["hostNetwork", "hostPID", "hostIPC"]) {
      if (val(get(spec, k)) === true) out.push({ id: "SEC058", title: `${kind} ${name} uses ${k}`, severity: "High", confidence: "high", controls: [14], rel, line: lineAt(d, get(spec, k)), guidance: G.SEC058 });
    }
    for (const v of items(get(spec, "volumes"))) {
      const hp = get(v, "hostPath", "path");
      if (hp) out.push({ id: "SEC058", title: `${kind} ${name} mounts a host path (${str(hp)})`, severity: /^\/(?:$|var\/run\/docker|etc|root|proc|sys)/.test(str(hp)) ? "High" : "Medium", confidence: "high", controls: [14], rel, line: lineAt(d, hp), guidance: G.SEC058 });
    }
    const podRunAsNonRoot = val(get(spec, "securityContext", "runAsNonRoot")) === true;
    for (const c of [...items(get(spec, "containers")), ...items(get(spec, "initContainers"))]) {
      const cname = str(get(c, "name"));
      const sc = get(c, "securityContext");
      if (val(get(sc, "privileged")) === true) out.push({ id: "SEC058", title: `Privileged container ${cname} in ${kind} ${name}`, severity: "High", confidence: "high", controls: [14], rel, line: lineAt(d, get(sc, "privileged")), guidance: G.SEC058 });
      if (val(get(sc, "allowPrivilegeEscalation")) === true) out.push({ id: "SEC058", title: `Container ${cname} allows privilege escalation`, severity: "Medium", confidence: "high", controls: [14], rel, line: lineAt(d, get(sc, "allowPrivilegeEscalation")), guidance: G.SEC058 });
      const runAsUser = val(get(sc, "runAsUser")) ?? val(get(spec, "securityContext", "runAsUser"));
      if (runAsUser === 0) out.push({ id: "SEC052", title: `Container ${cname} runs as root (runAsUser: 0)`, severity: "Medium", confidence: "high", controls: [14], rel, line: lineAt(d, get(sc, "runAsUser") ?? get(spec, "securityContext", "runAsUser")), guidance: G.SEC052 });
      else if (runAsUser === undefined && !podRunAsNonRoot && val(get(sc, "runAsNonRoot")) !== true) {
        out.push({ id: "SEC052", title: `Container ${cname} may run as root (no runAsNonRoot / runAsUser)`, severity: "Low", confidence: "low", controls: [14], rel, line: lineAt(d, c), guidance: G.SEC052 });
      }
      const image = str(get(c, "image"));
      if (image && !image.includes("@sha256:") && (!/:[^/]+$/.test(image) || /:latest$/.test(image)) && !/\{\{/.test(image)) {
        out.push({ id: "SEC054", title: `Image not pinned to a version (${image})`, severity: "Low", confidence: "high", controls: [15], rel, line: lineAt(d, get(c, "image")), guidance: G.SEC054 });
      }
      for (const e of items(get(c, "env"))) {
        const k = str(get(e, "name")), v = str(get(e, "value"));
        if (SECRET_NAME.test(k) && v.length >= 8 && !PLACEHOLDER.test(v) && !/\{\{|\$\(/.test(v)) {
          out.push({ id: "SEC053", title: `Secret written into the manifest (${cname}: ${k})`, severity: "High", confidence: "medium", controls: [15], rel, line: lineAt(d, get(e, "value")), guidance: G.SEC053 });
        }
      }
    }
  }
}

// ---------- GitHub Actions ----------

const UNTRUSTED = /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)[\w.\[\]*]*\.(?:title|body|message|name|label|ref|email|page_name)|head_ref)\b[^}]*\}\}/;

function workflow(rel: string, docs: Doc[], out: InfraHit[]) {
  for (const d of docs) {
    const on = get(d.node, "on") ?? get(d.node, true as any);
    const triggers = isMap(on) ? pairs(on).map((p: any) => str(p.key)) : isSeq(on) ? items(on).map(str) : [str(on)];
    const prTarget = triggers.includes("pull_request_target") || triggers.includes("workflow_run");
    if (/^write-all$/.test(str(get(d.node, "permissions")))) {
      out.push({ id: "SEC057", title: "Workflow token has write access to everything (permissions: write-all)", severity: "Medium", confidence: "high", controls: [15], rel, line: lineAt(d, get(d.node, "permissions")), guidance: G.SEC057 });
    }
    for (const job of pairs(get(d.node, "jobs"))) {
      for (const step of items(get(job.value, "steps"))) {
        const uses = str(get(step, "uses"));
        const run = get(step, "run");
        if (prTarget && /^actions\/checkout@/.test(uses)) {
          const ref = str(get(step, "with", "ref"));
          if (/github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs\/pull\//.test(ref)) {
            out.push({ id: "SEC057", title: `${triggers.includes("workflow_run") ? "workflow_run" : "pull_request_target"} checks out the pull request's code (runs it with secrets)`, severity: "Critical", confidence: "high", controls: [15],
              rel, line: lineAt(d, get(step, "with", "ref")), guidance: G.SEC057 });
          }
        }
        if (run && UNTRUSTED.test(str(run))) {
          out.push({ id: "SEC057", title: "Untrusted event text inserted into a shell command (${{ github.event… }} in run:)", severity: "High", confidence: "high", controls: [15, 5], rel, line: lineAt(d, run), guidance: G.SEC057 });
        }
        if (uses && !/^(?:actions|github)\//.test(uses) && !/^\.\/|^docker:\/\//.test(uses) && !/@[0-9a-f]{40}$/.test(uses)) {
          out.push({ id: "SEC054", title: `Third-party action not pinned to a commit (${uses})`, severity: "Low", confidence: "high", controls: [15], rel, line: lineAt(d, get(step, "uses")), guidance: G.SEC054 });
        }
      }
    }
  }
}

// ---------- Terraform ----------

function terraform(rel: string, text: string, out: InfraHit[]) {
  const lineOfIndex = (i: number) => text.slice(0, i).split("\n").length;
  for (const m of text.matchAll(/resource\s+"(aws_security_group(?:_rule)?|aws_vpc_security_group_ingress_rule|google_compute_firewall|azurerm_network_security_rule)"\s+"([^"]+)"\s*\{/g)) {
    const start = m.index! + m[0].length;
    let depth = 1, i = start;
    while (i < text.length && depth) { if (text[i] === "{") depth++; else if (text[i] === "}") depth--; i++; }
    const body = text.slice(start, i);
    const blocks = m[1] === "aws_security_group" ? [...body.matchAll(/ingress\s*\{([^}]*)\}/g)].map((b) => ({ s: b[1], at: start + b.index! })) : [{ s: body, at: start }];
    for (const b of blocks) {
      if (!/0\.0\.0\.0\/0|::\/0|"\*"/.test(b.s) || /egress|direction\s*=\s*"EGRESS"|"Outbound"/i.test(b.s)) continue;
      const from = +(/from_port\s*=\s*(\d+)/.exec(b.s)?.[1] ?? NaN), to = +(/to_port\s*=\s*(\d+)/.exec(b.s)?.[1] ?? NaN);
      const listed = [...b.s.matchAll(/(?:ports|destination_port_ranges?|port_range)\s*=\s*\[?([^\]\n]*)/g)].flatMap((x) => x[1].match(/\d+/g) ?? []).map(Number);
      const ports = [...(Number.isNaN(from) ? [] : Array.from({ length: Math.min(Math.max(to - from, 0), 70000) + 1 }, (_, k) => from + k)), ...listed];
      const all = from === 0 && (to === 65535 || to === 0) || /protocol\s*=\s*"(?:-1|all)"/.test(b.s);
      const bad = ports.filter((p) => DB_PORTS.has(p) || ADMIN_PORTS.has(p));
      if (all || bad.length) {
        out.push({ id: "SEC055", title: `${m[1]}.${m[2]} opens ${all ? "every port" : `port ${[...new Set(bad)].slice(0, 4).join(", ")}`} to the whole internet`, severity: "High", confidence: "high", controls: [8],
          rel, line: lineOfIndex(b.at + (b.s.search(/0\.0\.0\.0\/0|::\/0|"\*"/) >= 0 ? b.s.search(/0\.0\.0\.0\/0|::\/0|"\*"/) : 0)), guidance: G.SEC055 });
      }
    }
  }
  for (const m of text.matchAll(/resource\s+"(aws_db_instance|aws_rds_cluster|google_sql_database_instance|azurerm_postgresql_server|azurerm_mysql_server)"\s+"([^"]+)"\s*\{([\s\S]*?)\n\}/g)) {
    const body = m[3];
    const at = m.index! + m[0].indexOf(body);
    const pub = /publicly_accessible\s*=\s*true|public_network_access_enabled\s*=\s*true|ipv4_enabled\s*=\s*true[\s\S]*?authorized_networks[\s\S]*?0\.0\.0\.0\/0/.exec(body);
    if (pub) out.push({ id: "SEC055", title: `Database ${m[2]} is reachable from the internet`, severity: "High", confidence: "high", controls: [8], rel, line: lineOfIndex(at + pub.index), guidance: G.SEC055 });
    const enc = /storage_encrypted\s*=\s*false/.exec(body);
    if (enc) out.push({ id: "SEC055", title: `Database ${m[2]} storage is not encrypted`, severity: "Medium", confidence: "high", controls: [13], rel, line: lineOfIndex(at + enc.index), guidance: "Turn on storage encryption (storage_encrypted = true with a KMS key); it can't be added to an existing instance without a snapshot restore." });
    const pw = /(?:password|master_password|administrator_login_password)\s*=\s*"([^"$]{6,})"/.exec(body);
    if (pw && !PLACEHOLDER.test(pw[1])) out.push({ id: "SEC053", title: `Database password written in Terraform (${m[2]})`, severity: "High", confidence: "high", controls: [15], rel, line: lineOfIndex(at + pw.index), guidance: G.SEC053 });
  }
}

// ---------- database server configs ----------

function dbConfig(rel: string, name: string, text: string, out: InfraHit[]) {
  const lines = text.split(/\r?\n/);
  if (name === "pg_hba.conf") {
    lines.forEach((l, i) => {
      const f = l.replace(/#.*/, "").trim().split(/\s+/);
      if (f[0] === "host" || f[0] === "hostssl" || f[0] === "hostnossl") {
        const addr = f[3] ?? "", method = f[f.length - 1];
        const remote = !/^(?:127\.|::1|localhost|samehost|samenet)/.test(addr);
        if (method === "trust" && remote) out.push({ id: "SEC056", title: `pg_hba.conf trusts remote connections without a password (${addr})`, severity: "Critical", confidence: "high", controls: [8], rel, line: i + 1, guidance: G.SEC056 });
        else if (method === "md5" && /^(?:0\.0\.0\.0\/0|::\/0|all)$/.test(addr)) out.push({ id: "SEC056", title: "pg_hba.conf accepts password logins from any address", severity: "Medium", confidence: "medium", controls: [8], rel, line: i + 1, guidance: G.SEC056 });
      }
    });
  } else if (/^mongod(?:\.conf|\.yaml|\.yml)$/.test(name)) {
    const bindAll = lines.findIndex((l) => /^\s*bindIp(?:All)?\s*:\s*(?:0\.0\.0\.0|true|::)/.test(l));
    const auth = /authorization\s*:\s*["']?enabled/.test(text);
    if (bindAll >= 0 && !auth) out.push({ id: "SEC056", title: "MongoDB listens on every interface without authorization", severity: "Critical", confidence: "high", controls: [8], rel, line: bindAll + 1, guidance: G.SEC056 });
  } else if (/^(?:redis|valkey)\.conf$/.test(name)) {
    const bind = lines.findIndex((l) => /^\s*bind\s+.*(?:0\.0\.0\.0|\*|::)/.test(l));
    const prot = lines.findIndex((l) => /^\s*protected-mode\s+no/.test(l));
    const pass = lines.some((l) => /^\s*requirepass\s+\S/.test(l) || /^\s*aclfile\s/.test(l) || /^\s*user\s+\S+\s+on\b/.test(l));
    if ((bind >= 0 || prot >= 0) && !pass) out.push({ id: "SEC056", title: "Redis reachable from other machines without a password", severity: "High", confidence: "high", controls: [8], rel, line: (bind >= 0 ? bind : prot) + 1, guidance: G.SEC056 });
  } else if (/^my(?:sql)?\.cnf$/.test(name)) {
    const bind = lines.findIndex((l) => /^\s*bind-address\s*=\s*(?:0\.0\.0\.0|\*|::)/.test(l));
    if (bind >= 0) out.push({ id: "SEC056", title: "MySQL listens on every interface", severity: "Low", confidence: "medium", controls: [8], rel, line: bind + 1, guidance: G.SEC056 });
    const skip = lines.findIndex((l) => /^\s*skip-grant-tables/.test(l));
    if (skip >= 0) out.push({ id: "SEC056", title: "MySQL runs with skip-grant-tables (no passwords checked)", severity: "Critical", confidence: "high", controls: [8], rel, line: skip + 1, guidance: G.SEC056 });
  }
}

// ---------- entry ----------

export function analyzeInfra(root: string, files: string[]): InfraHit[] {
  const out: InfraHit[] = [];
  for (const rel of files) {
    const name = rel.slice(rel.lastIndexOf("/") + 1);
    const lower = name.toLowerCase();
    const isDocker = /^(?:dockerfile|containerfile)(?:\.[\w.-]+)?$|\.dockerfile$/i.test(name);
    const isCompose = /^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/.test(lower);
    const isWorkflow = /^\.github\/workflows\/[^/]+\.ya?ml$/.test(rel) || /(?:^|\/)action\.ya?ml$/.test(rel) && rel.startsWith(".github/");
    const isYaml = /\.ya?ml$/.test(lower);
    const isTf = /\.tf$/.test(lower);
    const isDbConf = /^(?:pg_hba\.conf|mongod\.conf|mongod\.ya?ml|redis\.conf|valkey\.conf|my\.cnf|mysql\.cnf)$/.test(lower);
    if (!isDocker && !isYaml && !isTf && !isDbConf) continue;
    let text: string;
    try { text = readFileSync(join(root, rel), "utf8"); } catch { continue; }
    if (text.length > 2_000_000) continue;
    try {
      if (isDocker) dockerfile(rel, text, out);
      else if (isTf) terraform(rel, text, out);
      else if (isDbConf) dbConfig(rel, lower, text, out);
      else if (isCompose) compose(rel, yamlDocs(text), out);
      else if (isWorkflow) workflow(rel, yamlDocs(text), out);
      else if (/^\s*(?:apiVersion|kind)\s*:/m.test(text) && /^\s*kind\s*:/m.test(text)) kubernetes(rel, yamlDocs(text), out);
    } catch { /* one odd file never stops the scan */ }
  }
  return out;
}
