# saas-security-audit — SaaS Security Scanner CLI

**Scan any SaaS codebase in seconds for the security bugs that leak customer data:** cross-tenant access, IDOR/BOLA, missing Supabase row-level security (RLS), leaked secrets, SQL injection, permissive CORS, unsigned webhooks, SSRF, weak JWT sessions, and AI/LLM prompt injection. Every finding maps to one of 22 OWASP-aligned controls. It runs locally and read-only, and makes no network requests.

```bash
npx saas-security-audit
```

![saas-security-audit scanning a repository](https://raw.githubusercontent.com/navinnm/saas-security-audit-cli/main/docs/screenshot.png)

## Why

Generic linters miss the bugs that hurt SaaS companies most: **authorization bugs at trust boundaries**, such as one tenant reading another's invoices, a table shipped without RLS, or a Stripe webhook accepted without a signature check. `saas-security-audit` is tuned for exactly these, and it tells you *where* each control's enforcement should live, not just what it matched.

## What it finds

| Example | Control |
|---|---|
| Supabase `service_role` key in a `NEXT_PUBLIC_` env variable | Secrets |
| `create table public.invoices` with no `ENABLE ROW LEVEL SECURITY` | Tenant isolation / RLS |
| RLS policy `USING (true)`, Drizzle tables without RLS, Prisma models with no tenant key | Tenant isolation |
| `User.create(req.body)`: client can set `role` or `tenant_id` | Mass assignment |
| Stripe/GitHub webhook routes with no signature check or idempotency | Webhook security |
| `` db.query(`SELECT … ${id}`) ``, `"SELECT …" + id`, `f"SELECT … {id}"` | SQL injection |
| `cors({ origin: true, credentials: true })`, `rejectUnauthorized: false` | CORS / TLS |
| `requests.get(request.args["url"])` | SSRF |
| `jwt.verify(token, secret)` with no algorithm pin, `expiresIn: "365d"` | JWT sessions |
| `` systemPrompt = `…${req.body.notes}` ``, model output passed to `db.query()` | AI / LLM |
| Live `sk_live_` / AWS keys in `.env.production`, env files not in `.gitignore` | Secret exposure |

It supports JavaScript/TypeScript (Next.js, Express, NestJS, Fastify, Hono), Python (Django, Flask, FastAPI), Ruby (Rails), PHP (Laravel), Go, Java/Kotlin, C#, SQL migrations, Terraform, and Firebase rules.

## Usage

```bash
saas-audit [path] [options]

  --format <pretty|markdown|json>  Default: pretty in a terminal, markdown when piped/CI
  --json                           Shorthand for --format json
  --output <file>                  Also write a report (.json → JSON, otherwise Markdown)
  --min-severity <level>           informational | low | medium | high | critical
  --fail-on <level>                Exit 1 on a lead at/above this severity (CI gate)
  --baseline <file>                Diff against a previous JSON run: new / resolved / persisting
  --no-animation                   Skip the live scanner panel
```

In an interactive terminal you get the live scanner: a sweeping scan beam, a progress bar, per-category counters, and a feed of findings as they're discovered. With `CI` set, `NO_COLOR` set, or output piped, it switches automatically to plain Markdown.

### CI (GitHub Actions)

```yaml
- name: SaaS security scan
  run: npx saas-security-audit@0.3.0 --fail-on high --output security-report.md
```

Track progress between runs:
```bash
saas-audit --json --output baseline.json        # before
saas-audit --baseline baseline.json             # after: shows new / resolved / persisting
```

Suppress a reviewed false positive inline. It stays listed in the report with its reason:
```js
eval(expr) // security-audit: ignore[SEC002] -- constant expression from config
```

## Honest limits

This is a fast heuristic scanner. **It finds leads, not proof.** It reports false positives and misses vulnerabilities, and it never marks a control as passed. To verify findings, trace them end to end, and write fixes with regression tests, use the companion **Claude Code plugin**, [claude-code-security-audit](https://github.com/navinnm/claude-code-security-audit):

```
/plugin marketplace add navinnm/claude-code-security-audit
/plugin install saas-security-audit@claude-code-security-audit
/saas-security-audit:audit
```

The CLI and the plugin share one rule set and produce identical results.

## Privacy

- Runs entirely on your machine: no network requests, no telemetry, and it never executes your code.
- Secret values are redacted in every output.
- It doesn't read environment variables or credentials. The one exception is `PATH`, which it reads only to report which optional audit tools are installed.

## Development

```bash
npm install
npm test             # builds, runs engine tests, and parity tests against the Python plugin scanner
npm run sync-rules   # regenerate rules.json from the plugin's scripts/scan.py
```

`rules.json` is generated from the plugin's scanner, which is the single source of truth. The parity tests run both scanners on the same repos and require identical JSON and Markdown output.

## License

[MIT](LICENSE) © Fulgid Software Solutions Pvt Ltd
