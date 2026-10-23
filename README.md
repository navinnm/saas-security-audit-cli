# saas-security-audit — SaaS Security Scanner CLI

**Scan any SaaS codebase in seconds for the security bugs that leak customer data:** cross-tenant access, IDOR/BOLA, missing Supabase row-level security (RLS), leaked secrets, SQL injection, permissive CORS, unsigned webhooks, SSRF, weak JWT sessions, and AI/LLM prompt injection. Every finding is tagged with **OWASP Top 10, OWASP API Top 10, OWASP LLM Top 10 and CWE** IDs, mapped to 22 SaaS security controls, and related to **ASVS, PCI DSS, SOC 2, ISO 27001 and NIST SSDF** requirements. A built-in **vibe-code review** flags the mistakes AI-generated apps make most often. It runs locally and read-only; the scan never touches the network.

```bash
npx saas-security-audit
```

## Quick start

```bash
npm i -g saas-security-audit                      # or run any command below with npx saas-security-audit

cd your-app
saas-audit                                        # interactive scan in the terminal
saas-audit --output security-report.pdf           # also write a PDF report
saas-audit --output report.pdf --output report.html   # PDF + HTML from one scan
saas-audit ~/projects/other-app --output report.pdf   # scan another folder
saas-audit --fail-on high --format github         # CI gate with pull-request annotations
saas-audit show SEC031                            # every location and fix for one rule
saas-audit update                                 # update to the latest version
```

The report format comes from the file extension: `.pdf`, `.html`, `.json` or `.md`. After the scan, the CLI offers to open the first report; add `--yes` to skip all prompts.

![saas-security-audit scanning a repository](https://raw.githubusercontent.com/navinnm/saas-security-audit-cli/main/docs/screenshot.png)

## Why

Generic linters miss the bugs that hurt SaaS companies most: **authorization bugs at trust boundaries**, such as one tenant reading another's invoices, a table shipped without RLS, or a Stripe webhook accepted without a signature check. `saas-security-audit` is tuned for exactly these, and it tells you *where* each control's enforcement should live, not just what it matched.

For JavaScript and TypeScript it also **reads the code as code**, not line by line: it finds every Next.js route handler, server action and Express/Hono route, follows request data through variables into database calls, and follows sign-in checks into the helpers a handler calls (in the same file or imported). That is how it catches the bugs AI-written apps ship most, which pattern scanners can't see: a route nobody has to log in for, a record loaded by an id from the URL with no owner check, a request body saved as a whole.

## What it finds

| Example | Control |
|---|---|
| `export async function GET() { return Response.json(await prisma.invoice.findMany()) }` with no session check; a `"use server"` action that deletes without one | Login on every route (traced) |
| `prisma.post.findUnique({ where: { id: params.id } })` with no owner in the query and no check after it | IDOR / object-level access (traced) |
| `prisma.user.update({ data: await req.json() })`, `{ ...body, }` into a write | Mass assignment (traced) |
| `data: { userId: formData.get("userId"), price: body.price }` | Owner or price from the browser (traced) |
| `$queryRawUnsafe` / `exec` / `eval` / `fetch` / `redirect` fed by `req.json()`, `searchParams`, route params | Injection, SSRF, open redirect (traced) |
| Dockerfile without `USER`, `ENV STRIPE_SECRET_KEY=…`, `COPY .env`, `FROM node` (no version) | Containers |
| compose `"5432:5432"` with `POSTGRES_PASSWORD: postgres`, `POSTGRES_HOST_AUTH_METHOD: trust`, Redis without a password, docker.sock mounted | Databases & compose |
| Kubernetes `privileged: true`, `hostNetwork`, `runAsUser: 0`, a committed `kind: Secret` | Kubernetes |
| `pull_request_target` that checks out the PR's code, `${{ github.event.pull_request.title }}` in `run:`, unpinned third-party actions | CI supply chain |
| Terraform security group `0.0.0.0/0` on 5432/22, `publicly_accessible = true`, unencrypted RDS; `pg_hba.conf` trust, open `mongod.conf` / `redis.conf` | Cloud & database config |
| `next@14.1.0`: CVE-2025-29927, fixed in 14.2.25 · `Django==3.2.0`: 38 CVEs · `laravel/framework` v8 · `gin` 1.6.0 · Go 1.20 standard library | Vulnerable and outdated dependencies (OSV.dev) |
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
| `if (user.role === 'admin')` only in the UI, tokens in `localStorage`, `// TODO: add auth` | Vibe-code review |
| `new OpenAI({ dangerouslyAllowBrowser: true })`, Stripe secret key in browser code | Secrets in the frontend |

It supports JavaScript/TypeScript (Next.js, Express, NestJS, Fastify, Hono), Python (Django, Flask, FastAPI), Ruby (Rails), PHP (Laravel), Go, Java/Kotlin, C#, SQL migrations, Terraform, and Firebase rules.

## Usage

```bash
saas-audit [path] [options]
saas-audit show <rule> [path]        Every location, snippet and fix for one rule, e.g. saas-audit show SEC031
saas-audit update                    Update to the latest version

  --output <file>                    Write a report; repeatable. Format from extension: .pdf .html .json .md
  --fail-on <level>                  Exit 1 on a lead at/above: low | medium | high | critical (CI gate)
  --format <format>                  pretty | text | github | markdown | json | html
                                     (default: pretty in a terminal, text when piped or in CI)
  --json                             Shorthand for --format json
  --all                              Expand medium and low findings in the terminal
  --include-tests                    Include test files and gitignored env files without asking
  --yes, --no-input                  Skip the welcome screen; every prompt takes its default
  --min-severity <level>             Hide leads below this severity
  --baseline <file>                  Diff against a previous JSON run: new / resolved / persisting
  --no-animation                     Plain output, no live panel
  --no-update-check                  Don't check npm for a newer version
```

### What you see in a terminal

![Summary and verdict after a scan](https://raw.githubusercontent.com/navinnm/saas-security-audit-cli/main/docs/summary.png)

1. **Welcome:** the target (project, path, detected stack, file count) and run settings, the languages and top-level folders with their roles (source, build output, tests, docs…), a two-column grid of the six areas checked (each with its control count and what it looks for), and **"Start the scan now?"** (skip with `--yes`).
2. **Live scan:** an overall progress bar, a five-step pipeline (Discover → Classify → Analyse → Correlate → Report) with ETA, running severity counts, six area cards, and the latest critical and high findings as they're found. Press **Ctrl+C** to get "Stop the scan at 72%?"; the default is to keep going, and stopping keeps the partial results.
3. **Summary & verdict:** a release verdict (blocked, high-risk, gate passed, or clean), counts, where the worst findings live (application source vs generated build output), the severity shape, a by-area breakdown with the rules driving it, a by-folder breakdown, and the 22-control coverage grid.
4. **Findings by rule:** worst first, each with its locations as a tree and a `→` fix. Medium and low collapse into one table (`--all` expands them).
5. **Fix order:** numbered actions (every critical, then the high-severity rules), the controls that still need manual review, next commands, and the exit code.

Findings in test files and gitignored local env files aren't counted in the totals. The CLI asks whether to show them, with No as the default; `--include-tests` shows them straight away. Real-format secrets are always shown, even in tests, and report files always contain everything.

Prompts only appear in an interactive terminal. In CI or when piped, the CLI prints compact plain text with no colour, no spinner and no prompts, and never waits for input.

### Standards and vibe-code review

Every finding carries its standards, and every report (terminal, PDF, HTML, JSON, Markdown) includes:

| Standard | What you get |
|---|---|
| **OWASP Top 10 (2021)** | A01–A10 with leads per category and the rules that check it |
| **OWASP API Security Top 10 (2023)** | API1–API10; categories no rule can check are marked "not checked" instead of passing |
| **OWASP Top 10 for LLM Applications (2025)** | Prompt injection (LLM01), improper output handling (LLM05), secrets in the browser (LLM02) |
| **CWE**, with **CWE Top 25 (2024)** flags | Exact weakness IDs, e.g. CWE-89 SQL Injection, CWE-862 Missing Authorization |
| **OWASP ASVS 4.0.3, PCI DSS 4.0, SOC 2, ISO/IEC 27001:2022, NIST SSDF** | Related requirements per lead (e.g. PCI DSS 6.2.4, 8.6.2; ISO A.8.28; SSDF PW.5) |

The **vibe-code review** checks the 12 mistakes AI-generated ("vibe-coded") apps make most often: secret keys reachable from the browser, tables open without RLS, authorization only in the UI, security left as a TODO, tokens in localStorage, mass assignment, unsigned webhooks, wide-open CORS, hard-coded credentials, string-built SQL/shell, untrusted text in LLM prompts, and weak sessions.

> Mappings are indicative. A code scan alone does not demonstrate compliance with PCI DSS, SOC 2, ISO/IEC 27001, NIST SSDF or OWASP ASVS, and "not found" is never reported as "passed".

### Reports: PDF, HTML, JSON, Markdown

```bash
saas-audit --output security-report.pdf --output security-report.html
```

- **PDF:** a professional A4 report to share with clients, auditors, or your team. It has a branded cover, a risk summary, severity cards and chart, findings with redacted evidence, how-to-fix guidance, 22-control coverage, and page numbers. It's generated by a built-in writer, so no browser or Chromium download is needed.
- **HTML:** a single self-contained file with severity filters, search, expandable evidence, dark mode, and print-ready A4 styling. It loads nothing from the internet.
- **JSON:** machine-readable, for CI and dashboards. **Markdown:** for pull requests and wikis.

### CI (GitHub Actions)

```yaml
- name: SaaS security scan
  run: npx saas-security-audit@0.6.0 --fail-on high --format github --output security-report.md
```

`--format github` adds inline annotations on the pull request (errors for critical and high, warnings for medium), followed by the plain-text summary.

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

The plugin's scanner gives Claude its starting leads; the CLI started from the same rules and now goes further (code-flow analysis for JavaScript/TypeScript, fewer false positives). `SAAS_AUDIT_ENGINE=regex` runs only the line rules.

## Privacy

- The scan runs on your machine, never executes your code, and has no telemetry. Your code never leaves the machine.
- **Dependency check:** every scan sends the **names and versions** of the packages your project pins to [OSV.dev](https://osv.dev) to look up known vulnerabilities, and the names of your direct dependencies to their public registry (npm, PyPI, RubyGems, crates.io, Packagist, the Go module proxy, NuGet, Maven Central, pub.dev) for their latest version. Read from: package-lock.json, pnpm-lock.yaml, yarn.lock · poetry.lock, uv.lock, pdm.lock, Pipfile.lock, requirements*.txt · go.mod · Gemfile.lock · composer.lock · Cargo.lock · packages.lock.json, *.csproj · pom.xml, gradle.lockfile, build.gradle · pubspec.lock. Nothing else is sent. Turn it off with `--offline` or `SAAS_AUDIT_OFFLINE=1`; without network the scan continues and the report says the check was skipped.
- **Test files and gitignored local env files** (`.env.local`, `.env.*.local`) are not read by default: they don't ship. A `.env` that is *not* gitignored is still read and reported. `--include-tests` reads them.
- **Update check:** in an interactive terminal, the CLI asks the public npm registry (`registry.npmjs.org`) at most once a day whether a newer version exists. That request contains only the package name; nothing about your code or findings. It never runs in CI, when output is piped, or with `--json`/`--format markdown`. Turn it off with `--no-update-check`, `SAAS_AUDIT_NO_UPDATE_CHECK=1`, or `NO_UPDATE_NOTIFIER=1`. `saas-audit update` contacts the registry only when you run it.
- Secret values are redacted in every output.
- It doesn't read credentials. The only environment variables it reads are `PATH` (to report which optional audit tools are installed), the colour and update-check switches above, `SAAS_AUDIT_ENGINE` and `SAAS_AUDIT_OFFLINE`.

## Development

```bash
npm install
npm test                       # builds, runs engine, code-flow and UI tests
SAAS_AUDIT_PARITY=1 npm test   # also compare the line rules with the plugin's scripts/scan.py
```

`rules.json` holds the line rules and the rule metadata (titles, OWASP/CWE mapping, vibe-code groups) and is edited here; it started as an export of the plugin's scanner (`npm run sync-rules` would overwrite it). The code-flow analysis lives in `src/flow.ts` (rules SEC044–SEC049), with planted-bug tests in `test/flow.test.mjs`.

## License

[MIT](LICENSE) © Fulgid Software Solutions Pvt Ltd
