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

The CLI and the plugin share one rule set and produce identical results.

## Privacy

- The scan runs entirely on your machine. It makes no network requests, never executes your code, and has no telemetry.
- **Update check:** in an interactive terminal, the CLI asks the public npm registry (`registry.npmjs.org`) at most once a day whether a newer version exists. That request contains only the package name; nothing about your code or findings. It never runs in CI, when output is piped, or with `--json`/`--format markdown`. Turn it off with `--no-update-check`, `SAAS_AUDIT_NO_UPDATE_CHECK=1`, or `NO_UPDATE_NOTIFIER=1`. `saas-audit update` contacts the registry only when you run it.
- Secret values are redacted in every output.
- It doesn't read credentials. The only environment variables it reads are `PATH` (to report which optional audit tools are installed) and the colour and update-check switches above.

## Development

```bash
npm install
npm test             # builds, runs engine tests, and parity tests against the Python plugin scanner
npm run sync-rules   # regenerate rules.json from the plugin's scripts/scan.py
```

`rules.json` is generated from the plugin's scanner, which is the single source of truth. The parity tests run both scanners on the same repos and require identical JSON and Markdown output.

## License

[MIT](LICENSE) © Fulgid Software Solutions Pvt Ltd
