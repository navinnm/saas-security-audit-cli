#!/usr/bin/env node
import React from "react";
import { render } from "ink";
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { homedir } from "node:os";
import { parseArgs } from "node:util";
import { gateCounts, newState, scan, type Finding } from "./engine.js";
import { buildResult, markdown, sortFindings, type Result } from "./report.js";
import { SEVERITY_RANK } from "./rules.js";
import { LiveScan } from "./ui/LiveScan.js";
import { renderSummary } from "./ui/summary.js";
import { c, gradient } from "./ui/theme.js";
import { latestVersion, runUpdate, updateCheckEnabled, updateNotice, withDeadline } from "./update.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const SEVERITIES = Object.keys(SEVERITY_RANK).map((s) => s.toLowerCase());
const FAIL_ON = ["none", ...SEVERITIES.filter((s) => s !== "informational")];

const HELP = `
${gradient("◢◤ SAAS SECURITY AUDIT")}  ${c.gray(`v${pkg.version}`)}
Read-only SaaS security scanner: tenant isolation, IDOR/BOLA, Supabase RLS, secrets,
injection, CORS, webhooks, SSRF, JWT sessions, and AI/LLM risks across 22 controls.

${c.bold("Usage")}
  saas-audit [path] [options]
  saas-audit update                Update to the latest version

${c.bold("Options")}
  --format <pretty|markdown|json>  Output format (default: pretty in a terminal, markdown otherwise)
  --json                           Shorthand for --format json
  --output <file>                  Also write the report to a file (.json → JSON, otherwise Markdown)
  --min-severity <level>           Hide leads below: ${SEVERITIES.join(", ")}
  --fail-on <level>                Exit 1 on an unsuppressed lead at/above: ${FAIL_ON.join(", ")}
  --baseline <file>                Previous JSON output; adds new/resolved/persisting comparison
  --no-animation                   Skip the live scanner panel
  --no-update-check                Don't check npm for a newer version (also: SAAS_AUDIT_NO_UPDATE_CHECK=1)
  -v, --version                    Print the version
  -h, --help                       Show this help

${c.bold("Examples")}
  npx saas-security-audit                         Scan the current directory
  saas-audit ./apps/web --min-severity medium     Focus on medium and above
  saas-audit --fail-on high --format json         CI gate
  saas-audit --output security-report.md          Keep a Markdown report

The scanner never executes your code and makes no network requests.
For full verification and fixes, use the Claude Code plugin: /saas-security-audit:audit
`;

function fail(message: string): never {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(2);
}

const tildify = (p: string) => (p.startsWith(homedir()) ? "~" + p.slice(homedir().length) : p);
const displayTarget = (p: string) => {
  const t = tildify(p);
  return t.length <= 48 ? t : "…/" + t.split("/").slice(-2).join("/");
};

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        root: { type: "string" }, format: { type: "string" }, json: { type: "boolean" }, output: { type: "string" },
        "min-severity": { type: "string" }, "fail-on": { type: "string" }, baseline: { type: "string" },
        "no-animation": { type: "boolean" }, "no-update-check": { type: "boolean" }, "dry-run": { type: "boolean" }, help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" },
      },
    });
  } catch (err) {
    fail((err as Error).message);
  }
  const a = parsed.values;
  if (a.help) { process.stdout.write(HELP + "\n"); return 0; }
  if (a.version) { process.stdout.write(pkg.version + "\n"); return 0; }
  if (parsed.positionals[0] === "update" && parsed.positionals.length === 1) return runUpdate(pkg.version, Boolean(a["dry-run"]));

  const interactive = Boolean(process.stdout.isTTY) && !process.env.CI && !a["no-animation"] && process.env.TERM !== "dumb";
  const format = a.format ?? (a.json ? "json" : interactive ? "pretty" : "markdown");
  if (!["pretty", "markdown", "json"].includes(format)) fail(`--format must be one of pretty, markdown, json`);
  const minSeverity = (a["min-severity"] ?? "informational").toLowerCase();
  if (!SEVERITIES.includes(minSeverity)) fail(`--min-severity must be one of ${SEVERITIES.join(", ")}`);
  const failOn = (a["fail-on"] ?? "none").toLowerCase();
  if (!FAIL_ON.includes(failOn)) fail(`--fail-on must be one of ${FAIL_ON.join(", ")}`);

  let root = resolve((a.root ?? parsed.positionals[0] ?? ".").replace(/^~(?=$|\/)/, homedir()));
  let isDir = false;
  try { isDir = statSync(root).isDirectory(); } catch { /* missing */ }
  if (!isDir) fail("--root must be an existing directory");
  root = realpathSync(root); // like Path.resolve(): follow symlinks so reports match the plugin scanner

  let baseline: { findings?: Finding[] } | undefined;
  if (a.baseline) {
    try {
      baseline = JSON.parse(readFileSync(resolve(a.baseline), "utf8"));
    } catch (err) {
      fail(`cannot read baseline: ${(err as Error).message}`);
    }
  }

  // Version check runs in the background during the scan; the scan itself never uses the network.
  const updateCheck = format === "pretty" && updateCheckEnabled(interactive, Boolean(a["no-update-check"])) ? latestVersion() : null;
  const state = newState();
  let findings: Finding[] = [];
  let filesWalked: number | undefined;
  const started = Date.now();

  if (format === "pretty" && interactive) {
    const app = render(
      <LiveScan version={pkg.version} target={displayTarget(root)} run={async (ev) => { findings = await scan(root, state, { ...ev, onDiscover: (n) => { filesWalked = n; ev.onDiscover?.(n); } }); }} />,
      { patchConsole: false },
    );
    await app.waitUntilExit();
  } else {
    findings = await scan(root, state);
  }

  const floor = SEVERITY_RANK[capitalize(minSeverity)];
  const shown = sortFindings(findings.filter((f) => SEVERITY_RANK[f.severity] >= floor));
  const result: Result = buildResult(root, shown, state, baseline);

  if (a.output) {
    const target = resolve(a.output.replace(/^~(?=$|\/)/, homedir()));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, target.endsWith(".json") ? JSON.stringify(result, null, 2) : markdown(result), "utf8");
  }
  if (format === "json") process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  else if (format === "markdown") { if (!a.output) process.stdout.write(markdown(result) + "\n"); }
  else process.stdout.write(renderSummary(result, { elapsedMs: Date.now() - started, columns: process.stdout.columns,
    outputPath: a.output ? tildify(resolve(a.output)) : undefined, filesWalked }) + "\n");
  if (updateCheck) {
    const notice = updateNotice(pkg.version, await withDeadline(updateCheck, 400));
    if (notice) process.stdout.write(notice + "\n");
  }

  if (failOn !== "none") {
    const threshold = SEVERITY_RANK[capitalize(failOn)];
    if (findings.some((f) => gateCounts(f) && SEVERITY_RANK[f.severity] >= threshold)) return 1;
  }
  return 0;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

main().then((code) => process.exit(code), (err) => {
  process.stderr.write(`ERROR: ${(err as Error)?.stack ?? err}\n`);
  process.exit(2);
});
