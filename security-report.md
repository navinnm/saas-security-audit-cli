# Local SaaS Security Heuristic Scan

- **Scanner:** v0.3.0, read-only local heuristics; no network requests, no target-code execution.
- **Files scanned:** 16
- **Interpretation:** Every finding is a lead to validate in code, not a confirmed vulnerability.
- **Coverage:** No control is automatically marked PASS.

## Summary

| Severity | Leads |
|---|---|
| Critical | 1 |
| High | 28 |
| Medium | 9 |
| Low | 0 |
| Informational | 0 |

Suppressed inline: 1. Findings in test paths or gitignored local env files are marked by context.

## Leads by control

### C1. Row-level security and tenant isolation

**SEC022 — Permissive data access rule or RLS bypass** · confidence medium

Guidance: Policies must scope rows to the caller's tenant/user; SECURITY DEFINER functions bypass RLS and need their own checks.

- High — `rules.json:1292` — `"guidance": "Policies must scope rows to the caller's tenant/user; SECURITY DEFINER functions bypass RLS and need their own checks.",`
- High — `test/fixtures.mjs:37` _(test)_ — `'create policy "all" on public.orgs using (true);',`
- High — `test/fixtures.mjs:38` _(test)_ — `"-- alter table public.x disable row level security;",`
- High — `test/fixtures.mjs:71` _(test)_ — `"firestore.rules": "allow read, write: if true;\n",`

**SEC030 — Table without row-level security** · confidence low

Guidance: Use pgTable.withRLS / .enableRLS() and pgPolicy for tenant-owned tables, or confirm RLS is applied in SQL migrations.

- High Drizzle table 'projects' defined without RLS — `test/fixtures.mjs:67` _(test)_ — `"db/schema.ts": 'export const projects = pgTable("projects", { id: uuid("id") });\nexport const orgs = pgTable("orgs", { id: uuid("id") }).enableRLS();\n',`

### C2. Authentication and authorization on every API route

**SEC021 — Insecure randomness for a security value** · confidence low

Guidance: Use a CSPRNG (crypto.randomBytes / secrets / random_bytes) for tokens, codes, and identifiers.

- Medium — `test/fixtures.mjs:21` _(test)_ — `"const token = Math.random().toString(36);",`

### C3. Server-side enforcement of permissions and business rules

**SEC018 — CSRF protection disabled** · confidence medium

Guidance: Cookie-authenticated state-changing routes need CSRF tokens or strict SameSite plus origin checks.

- Medium — `rules.json:1053` — `"source": "@csrf_exempt\\b\|\\bcsrf_exempt\\s*\\(",`

**SEC019 — Possible mass assignment from request body** · confidence low · also C9, C1

Guidance: Bind an explicit field allowlist; tenant_id, owner_id, role, and plan must come from the server-side session.

- Medium — `test/fixtures.mjs:24` _(test)_ — `"await User.create(req.body);",`

### C5. Input validation, output encoding, and safe deserialization

**SEC002 — Dynamic code evaluation** · confidence medium

Guidance: Never evaluate request-influenced strings; use explicit parsers and allowlisted operations.

- High — `test/engine.test.mjs:99` _(test)_ — `await withRepo({ "node_modules/bad.js": "eval(userInput)\n" }, async (root) => {`
- High — `test/engine.test.mjs:120` _(test)_ — `await withRepo({ "a.py": "eval(x)\n" }, async (root) => {`
- High — `test/engine.test.mjs:136` _(test)_ — `await withRepo({ "a.py": "eval(x)\n" }, async (root) => {`
- High — `test/engine.test.mjs:148` _(test)_ — `await withRepo({ "app.py": "eval(x)\n", "tests/test_app.py": "eval(y)\nexec(z)\n" }, async (root) => {`
- High — `test/fixtures.mjs:79` _(test)_ — `"bin.png": "\u0000PNGDATA eval(x)",`
- High — `test/fixtures.mjs:80` _(test)_ — `"bundle.min.js": "eval(x)\n",`
- High — `test/fixtures.mjs:84` _(test)_ — `"A/upper.js": "eval(a)\n",`
- High — `test/fixtures.mjs:85` _(test)_ — `"a/lower.js": "eval(b)\n",`

**SEC013 — OS command execution** · confidence medium

Guidance: Avoid shells; pass argument arrays to a fixed executable and allowlist any user-influenced values.

- High — `test/fixtures.mjs:18` _(test)_ — `"exec('convert ${req.query.file} out.png');",`

**SEC015 — Raw HTML sink (possible XSS)** · confidence medium

Guidance: Confirm the value is sanitized with a vetted HTML sanitizer or never user-controlled; prefer escaped rendering.

- Medium — `test/fixtures.mjs:23` _(test)_ — `"el.innerHTML = userBio;",`
- Medium — `test/fixtures.mjs:62` _(test)_ — `"f.jsx": "<div dangerouslySetInnerHTML={{ __html: bio }} />\n// el.innerHTML = x\n",`
- Medium — `test/fixtures.mjs:76` _(test)_ — `"crlf.js": "const a = 1;\r\nel.innerHTML = x;\r\nconst b = 2;\r\n",`

**SEC027 — Redirect to a request-controlled URL (possible open redirect)** · confidence low

Guidance: Allow only relative paths or allowlisted hosts for post-login and return URLs.

- Medium — `test/fixtures.mjs:25` _(test)_ — `"res.redirect(req.query.next);",`

### C6. Parameterized database queries

**SEC003 — SQL built with string interpolation or concatenation** · confidence medium · also C1

Guidance: Use bound parameters or tagged/query-builder APIs. Identifiers (columns, sort order) must come from an allowlist.

- High — `test/fixtures.mjs:26` _(test)_ — `'db.query("SELECT * FROM users WHERE id = " + req.params.id);',`
- High — `test/fixtures.mjs:27` _(test)_ — `"db.query('SELECT * FROM users WHERE id = ${req.params.id}');",`
- High — `test/fixtures.mjs:57` _(test)_ — `"a.py": 'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\ncur.execute(f"SELECT * FROM t WHERE id = {uid}")\ncur.execute("SELECT * FROM t WHERE id = %s" % uid)\nexec(user_code)\nast.literal_eval(v)\nyaml.load(data)\nyaml.load(data, Load`
- High — `test/fixtures.mjs:58` _(test)_ — `"b.ts": "await prisma.$queryRaw'SELECT * FROM t WHERE id = ${id}';\nconst rows = await sql'SELECT * FROM t WHERE id = ${id}';\ndb.query('SELECT * FROM t WHERE id = ${id}');\n",`

**SEC029 — Query object taken directly from request (possible NoSQL injection)** · confidence low · also C5

Guidance: Validate types (reject objects where strings are expected) and build query filters from explicit fields.

- High — `test/fixtures.mjs:63` _(test)_ — `"g.js": "Model.find(req.body)\nres.sendFile(path.join(__dirname, req.params.file))\nconst r = jwt.decode(token)\nconst ok = jwt.verify(token, secret);\njwt.sign(p, key, { expiresIn: \"365d\" });\n",`

### C7. CORS allowlist and credential policy

**SEC005 — Permissive CORS policy** · confidence medium

Guidance: Use an explicit origin allowlist. Reflecting any origin with credentials lets any site act as the user.

- High — `test/fixtures.mjs:20` _(test)_ — `"app.use(cors({ origin: true, credentials: true }));",`

### C8. HTTPS, secure cookies, and trusted proxy configuration

**SEC016 — TLS certificate verification disabled** · confidence high

Guidance: Keep certificate verification on; trust a private CA explicitly instead of disabling checks.

- High — `test/fixtures.mjs:22` _(test)_ — `"https.request({ rejectUnauthorized: false });",`

### C10. Production debug mode and safe error handling

**SEC004 — Debug mode or verbose errors may be enabled** · confidence low

Guidance: Confirm which environment loads this value; production must not expose debug pages or stack traces.

- Medium — `test/fixtures.mjs:50` _(test)_ — `"app.py": 'APP_DEBUG = True\nAPI_KEY = "${FAKE.api}"\npassword = "[REDACTED]"\n',`

### C13. Private storage and authorized file access

**SEC026 — Public storage bucket or object ACL** · confidence medium

Guidance: Keep tenant files private; serve them through short-lived signed URLs after an authorization check.

- High — `rules.json:1444` — `"source": "[\\\"']allUsers[\\\"']\|\\ballUsers\\b\|[\\\"']allAuthenticatedUsers[\\\"']",`
- High — `test/fixtures.mjs:72` _(test)_ — `"main.tf": 'resource "x" "y" {\n  member = "allUsers"\n  acl = "public-read"\n}\n',`

**SEC028 — File path built from request input (possible path traversal)** · confidence low · also C16

Guidance: Resolve the path and confirm it stays inside the intended directory, or map IDs to server-generated names.

- High — `test/fixtures.mjs:63` _(test)_ — `"g.js": "Model.find(req.body)\nres.sendFile(path.join(__dirname, req.params.file))\nconst r = jwt.decode(token)\nconst ok = jwt.verify(token, secret);\njwt.sign(p, key, { expiresIn: \"365d\" });\n",`

### C15. Dependency vulnerability management and secret exposure

**SEC001 — Possible hardcoded credential** · confidence medium

Guidance: Confirm whether the value is real. If so, rotate it, remove it from history, and load it from a secret store.

- High — `security-report.md:133` — `- Medium — 'test/fixtures.mjs:50' _(test)_ — '"app.py": 'APP_DEBUG = True\nAPI_KEY = "${FAKE.api}"\npassword = "[REDACTED]"\n','`

**SEC012 — Known-format secret** · confidence high

Guidance: Treat as exposed: rotate first, then purge from git history and move to a secret store.

- Critical Known-format secret: Private key block — `test/fixtures.mjs:53` _(test)_ — `"keys/id.pem": "[REDACTED_TOKEN]\nMIIB\n-----END RSA PRIVATE KEY-----\n",`

**SEC023 — Secret exposed through a public client-side env variable** · confidence high · also C3

Guidance: Public-prefixed variables are bundled into browser code. Move the secret server-side and rotate it.

- High — `test/fixtures.mjs:42` _(test)_ — `".env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=abc\n",`

### C21. JWT and session lifecycle security

**SEC017 — JWT verification weakened or decoded without verification** · confidence medium · also C2

Guidance: Verify signature, algorithm allowlist, expiry, issuer, and audience before trusting any claim.

- High — `test/fixtures.mjs:63` _(test)_ — `"g.js": "Model.find(req.body)\nres.sendFile(path.join(__dirname, req.params.file))\nconst r = jwt.decode(token)\nconst ok = jwt.verify(token, secret);\njwt.sign(p, key, { expiresIn: \"365d\" });\n",`

### C22. AI/LLM security and prompt injection

**SEC035 — Untrusted input interpolated into an LLM system prompt** · confidence low

Guidance: Keep untrusted text out of the system prompt; pass it as delimited user content and treat model output as untrusted.

- Medium — `test/fixtures.mjs:64` _(test)_ — `"h.ts": "const systemPrompt = 'You are a helper. Context: ${req.body.notes}';\nconst rows = await db.query(completion.choices[0].message.content);\n",`

**SEC036 — LLM output passed to an execution or query sink** · confidence low · also C5

Guidance: Never execute, query, or fetch model output directly; validate it against a strict schema and an allowlist of actions.

- High — `test/fixtures.mjs:64` _(test)_ — `"h.ts": "const systemPrompt = 'You are a helper. Context: ${req.body.notes}';\nconst rows = await db.query(completion.choices[0].message.content);\n",`

## Control coverage

Status stays NOT VERIFIED until enforcement and tests are confirmed in code. Signals are places where enforcement probably lives (source hits / test hits).

| # | Control | Status | Leads | Signals (src/test) | Look first |
|---|---|---|---|---|---|
| 1 | Row-level security and tenant isolation | NOT VERIFIED | 5 | 2/6 | `rules.json:1098`, `src/engine.ts:477` |
| 2 | Authentication and authorization on every API route | NOT VERIFIED | 1 | 1/2 | `rules.json:1810` |
| 3 | Server-side enforcement of permissions and business rules | NOT VERIFIED | 2 | 9/2 | `rules.json:12`, `src/ui/theme.ts:60` |
| 4 | Rate limiting and abuse prevention | NOT VERIFIED | 0 | 15/2 | `rules.json:9`, `src/ui/theme.ts:59` |
| 5 | Input validation, output encoding, and safe deserialization | NOT VERIFIED | 13 | 9/0 | `rules.json:1822` |
| 6 | Parameterized database queries | NOT VERIFIED | 5 | 22/6 | `rules.json:109`, `src/engine.ts:363` |
| 7 | CORS allowlist and credential policy | NOT VERIFIED | 1 | 14/1 | `package.json:4`, `rules.json:12`, `src/cli.tsx:22` |
| 8 | HTTPS, secure cookies, and trusted proxy configuration | NOT VERIFIED | 1 | 2/0 | `rules.json:579` |
| 9 | IDOR/BOLA and object-level authorization | NOT VERIFIED | 0 | 1/1 | `rules.json:1838` |
| 10 | Production debug mode and safe error handling | NOT VERIFIED | 1 | 1/0 | `rules.json:1842` |
| 11 | CAPTCHA or proportionate anti-automation controls | NOT VERIFIED | 0 | 8/0 | `rules.json:16` |
| 12 | Admin and security audit logging | NOT VERIFIED | 0 | 2/0 | `rules.json:17`, `src/ui/theme.ts:61` |
| 13 | Private storage and authorized file access | NOT VERIFIED | 3 | 3/0 | `rules.json:1414` |
| 14 | Admin interface and privileged-operation protection | NOT VERIFIED | 0 | 1/0 | `rules.json:1858` |
| 15 | Dependency vulnerability management and secret exposure | NOT VERIFIED | 3 | — | dependency tools |
| 16 | File upload security | NOT VERIFIED | 0 | 4/0 | `rules.json:1862` |
| 17 | Independent AI-assisted review | NOT VERIFIED | 0 | — | agent review |
| 18 | Security headers | NOT VERIFIED | 0 | 2/1 | `rules.json:1866` |
| 19 | Webhook authenticity, replay protection, and idempotency | NOT VERIFIED | 0 | 27/3 | `package.json:4`, `rules.json:24`, `scripts/sync-rules.py:73` |
| 20 | SSRF and outbound egress control | NOT VERIFIED | 0 | 0/0 | none found — check for a gap |
| 21 | JWT and session lifecycle security | NOT VERIFIED | 1 | 3/1 | `rules.json:1618` |
| 22 | AI/LLM security and prompt injection | NOT VERIFIED | 2 | 5/0 | `rules.json:1882` |

## Inventory

- Dependency manifests: `package.json`
- Test files detected: 3
- CI files: none found

Recommended tools (ask before running anything that needs network access):

- `npm audit --omit=dev` — npm dependency audit; installed; needs network
- `osv-scanner scan -r .` — npm dependency audit; not installed; needs network
- `gitleaks dir . --redact` — secrets/static analysis; not installed; offline
- `semgrep scan --config p/owasp-top-ten` — secrets/static analysis; not installed; needs network
- `trivy fs --scanners vuln,secret,misconfig .` — secrets/static analysis; not installed; needs network

## Suppressed leads

Inline `security-audit: ignore` markers. Each still needs a reviewer to agree with the reason.

- SEC002 `test/fixtures.mjs:81` — reason: constant expression only\n# security-audit: ignore\nexec(y)\neval(z)  # security-audit: ignore[SEC999] -- wrong id\n",

## Limitations

- Regex heuristics only; false positives and false negatives are expected.
- No control is automatically marked PASS; signals show where to look, not that a control is enforced.
- Only the root .gitignore is parsed; git history and tracked-but-ignored files are not inspected.
- No network access or target-code execution; dependency CVEs require the recommended tools.
