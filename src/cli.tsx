#!/usr/bin/env node
import React from "react";
import { render } from "ink";
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { homedir } from "node:os";
import { parseArgs } from "node:util";
import { gateCounts, newState, preflight, scan, type Finding, type ScanEvents } from "./engine.js";
import { buildResult, markdown, sortFindings, type Result } from "./report.js";
import { SEVERITY_RANK } from "./rules.js";
import { LiveScan } from "./ui/LiveScan.js";
import { ask, canAsk, collapsed } from "./ui/prompt.js";
import {
  ciText, estimate, findingsScreen, fixScreen, githubAnnotations, showRule, summaryScreen, welcomeFooter, welcomeScreen, type RunInfo,
} from "./ui/screens.js";
import { renderHtml } from "./html.js";
import { renderPdf } from "./pdf.js";
import { attackLayer } from "./standards.js";
import { bold, c, contentWidth, gradient, withMargin } from "./ui/theme.js";
import { stackOf } from "./view.js";
import { profile } from "./profile.js";
import { CLI_VERSION } from "./version.js";
import { latestVersion, runUpdate, updateCheckEnabled, updateNotice, withDeadline } from "./update.js";

const pkg = { version: CLI_VERSION };
const SEVERITIES = Object.keys(SEVERITY_RANK).map((s) => s.toLowerCase());
const FAIL_ON = ["none", ...SEVERITIES.filter((s) => s !== "informational")];
const FORMATS = ["pretty", "text", "github", "markdown", "json", "html"];

const HELP = `
${gradient("◆ SaaS Security Audit")}  ${c.muted(`v${pkg.version}`)}  ${c.dim("· powered by Fulgid · https://www.fulgid.in")}
Offline security review for SaaS codebases: tenant isolation, IDOR/BOLA, Supabase RLS, secrets,
injection, CORS, webhooks, SSRF, JWT sessions, and AI/LLM risks across 22 controls.

${bold("Usage")}
  saas-audit [path] [options]
  saas-audit show <rule> [path]      Every location, snippet and fix for one rule (e.g. SEC031)
  saas-audit update                  Update to the latest version

${bold("Options")}
  --output <file>                    Write a report; repeatable. Format from extension: .pdf .html .json .md
  --attack-layer <file>              Write a MITRE ATT&CK Navigator layer (.json) of checked techniques and leads
  --fail-on <level>                  Exit 1 on a lead at/above: ${FAIL_ON.join(", ")}
  --format <format>                  ${FORMATS.join(" | ")}  (default: pretty in a terminal, text otherwise)
  --json                             Shorthand for --format json
  --all                              Expand medium and low findings in the terminal
  --include-tests                    Also read test files and gitignored local env files (skipped by default)
  --offline                          Skip the dependency check (it sends package names + versions to OSV.dev and npm)
  --yes, --no-input                  Skip the welcome screen; every prompt takes its default
  --min-severity <level>             Hide leads below: ${SEVERITIES.join(", ")}
  --baseline <file>                  Previous JSON output; adds new/resolved/persisting comparison
  --no-animation                     Plain output, no live panel
  --no-update-check                  Don't check npm for a newer version (also SAAS_AUDIT_NO_UPDATE_CHECK=1)
  -v, --version · -h, --help

${bold("Examples")}
  npx saas-security-audit                              Scan the current directory
  saas-audit --output report.pdf --output report.html  Shareable PDF and HTML reports
  saas-audit --fail-on high --format github            CI gate with GitHub annotations
  saas-audit show SEC031                               Drill into one rule
  saas-audit --attack-layer layer.json                 Open in https://mitre-attack.github.io/attack-navigator/

The scan never executes your code and never sends it anywhere.
For full verification and fixes, use the Claude Code plugin: /saas-security-audit:audit
`;

function fail(message: string): never {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(2);
}

const tildify = (p: string) => (p.startsWith(homedir()) ? "~" + p.slice(homedir().length) : p);

function displayPath(p: string): string {
  const rel = relative(process.cwd(), p);
  return rel && !rel.startsWith("..") && !rel.startsWith("/") ? rel : tildify(p);
}

function openFile(file: string): void {
  const [cmd, args] = process.platform === "darwin" ? ["open", [file]]
    : process.platform === "win32" ? ["cmd", ["/c", "start", "", file]] : ["xdg-open", [file]];
  try {
    spawn(cmd as string, args as string[], { detached: true, stdio: "ignore" }).on("error", () => undefined).unref();
  } catch { /* no opener available; the path is printed above */ }
}

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        root: { type: "string" }, format: { type: "string" }, json: { type: "boolean" }, output: { type: "string", multiple: true }, "attack-layer": { type: "string" },
        "min-severity": { type: "string" }, "fail-on": { type: "string" }, baseline: { type: "string" },
        "no-animation": { type: "boolean" }, "no-update-check": { type: "boolean" }, "include-tests": { type: "boolean" }, offline: { type: "boolean" },
        "dry-run": { type: "boolean" }, yes: { type: "boolean", short: "y" }, "no-input": { type: "boolean" }, all: { type: "boolean" },
        help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" },
      },
    });
  } catch (err) {
    fail((err as Error).message);
  }
  const a = parsed.values;
  const pos = parsed.positionals;
  if (a.help) { process.stdout.write(HELP + "\n"); return 0; }
  if (a.version) { process.stdout.write(pkg.version + "\n"); return 0; }
  if (pos[0] === "update" && pos.length === 1) return runUpdate(pkg.version, Boolean(a["dry-run"]));
  const isShow = pos[0] === "show";
  if (isShow && !pos[1]) fail("usage: saas-audit show <rule> [path]   e.g. saas-audit show SEC031");

  const interactive = Boolean(process.stdout.isTTY) && !process.env.CI && !a["no-animation"] && process.env.TERM !== "dumb";
  const format = a.format ?? (a.json ? "json" : interactive ? "pretty" : "text");
  if (!FORMATS.includes(format)) {
    fail(format === "pdf" ? "PDF is binary; write it to a file with --output report.pdf" : `--format must be one of ${FORMATS.join(", ")}`);
  }
  const outputs = (a.output ?? []).map((o) => resolve(o.replace(/^~(?=$|\/)/, homedir())));
  const layerFile = a["attack-layer"] ? resolve(a["attack-layer"].replace(/^~(?=$|\/)/, homedir())) : null;
  const minSeverity = (a["min-severity"] ?? "informational").toLowerCase();
  if (!SEVERITIES.includes(minSeverity)) fail(`--min-severity must be one of ${SEVERITIES.join(", ")}`);
  const failOn = (a["fail-on"] ?? "none").toLowerCase();
  if (!FAIL_ON.includes(failOn)) fail(`--fail-on must be one of ${FAIL_ON.join(", ")}`);

  const pathArg = a.root ?? (isShow ? pos[2] : pos[0]) ?? ".";
  let root = resolve(pathArg.replace(/^~(?=$|\/)/, homedir()));
  let isDir = false;
  try { isDir = statSync(root).isDirectory(); } catch { /* missing */ }
  if (!isDir) fail(`not a directory: ${pathArg}  (usage: saas-audit [path] [options] · saas-audit show <rule> · saas-audit --help)`);
  root = realpathSync(root); // like Path.resolve(): follow symlinks so reports match the plugin scanner

  let baseline: { findings?: Finding[] } | undefined;
  if (a.baseline) {
    try {
      baseline = JSON.parse(readFileSync(resolve(a.baseline), "utf8"));
    } catch (err) {
      fail(`cannot read baseline: ${(err as Error).message}`);
    }
  }

  const width = contentWidth(process.stdout.columns);
  const pre = preflight(root);
  const repo = profile(root, pre.files);
  const info: RunInfo = { version: pkg.version, project: basename(root), path: tildify(root), stack: stackOf(Object.keys(pre.packages)), width };
  const reportName = outputs.length ? displayPath(outputs[0]) : null;
  const yes = Boolean(a.yes || a["no-input"]);
  const askable = format === "pretty" && interactive && canAsk() && !yes;
  const out = (lines: string[] | string) => process.stdout.write((Array.isArray(lines) ? lines.join("\n") : lines) + "\n");
  // Interactive screens get a left margin; machine formats (json/text/github/markdown) never do.
  const screen = (lines: string[] | string) => out(withMargin(Array.isArray(lines) ? lines : lines.split("\n")));

  if (isShow) {
    const all = await scan(root, newState(), {}, { files: pre.files, includeTests: Boolean(a["include-tests"]), offline: Boolean(a.offline) });
    screen(["", ...showRule(pos[1], sortFindings(all), width)]);
    return 0;
  }

  // 1 · Welcome
  if (format === "pretty" && interactive && !yes) {
    screen(welcomeScreen({ ...info, files: pre.total, profile: repo, report: reportName, failOn }));
    if (askable) {
      const go = await ask({ question: "Start the scan now?", note: estimate(pre.analysable), defaultYes: true });
      if (!go) { screen(["", " " + c.muted("Scan not started. Nothing was read or written."), ""]); return 0; }
    }
    screen(["", welcomeFooter(width), "", ""]);
  }

  // 2 · Scan, then write reports (shown as the pipeline's last step)
  const updateCheck = format === "pretty" && updateCheckEnabled(interactive, Boolean(a["no-update-check"])) ? latestVersion() : null;
  const state = newState();
  const includeTestsFlag = Boolean(a["include-tests"]);
  let findings: Finding[] = [];
  let result!: Result;
  let partial: { percent: number } | undefined;
  const started = Date.now();
  const doRun = async (ev: ScanEvents, signal: { aborted: boolean }) => {
    findings = await scan(root, state, ev, { files: pre.files, signal, includeTests: includeTestsFlag, offline: Boolean(a.offline) });
    ev.onPhase?.("report");
    const floor = SEVERITY_RANK[capitalize(minSeverity)];
    result = buildResult(root, sortFindings(findings.filter((f) => SEVERITY_RANK[f.severity] >= floor)), state, baseline);
    if (signal.aborted) result.partial = { stopped_at_percent: Math.round(partial?.percent ?? 0) };
    for (const target of outputs) {
      mkdirSync(dirname(target), { recursive: true });
      const ext = target.toLowerCase().split(".").pop();
      if (ext === "pdf") writeFileSync(target, renderPdf(result, { includeTests: includeTestsFlag }));
      else writeFileSync(target, ext === "json" ? JSON.stringify(result, null, 2)
        : ext === "html" || ext === "htm" ? renderHtml(result, { includeTests: includeTestsFlag }) : markdown(result, { includeTests: includeTestsFlag }), "utf8");
    }
    if (layerFile) {
      mkdirSync(dirname(layerFile), { recursive: true });
      writeFileSync(layerFile, JSON.stringify(attackLayer(result, basename(root)), null, 2) + "\n", "utf8");
    }
  };
  if (format === "pretty" && interactive) {
    const app = render(
      <LiveScan info={info} report={reportName} includeTests={includeTestsFlag} run={doRun} onStopped={(p) => { partial = { percent: p }; }} />,
      { patchConsole: false, exitOnCtrlC: false },
    );
    await app.waitUntilExit();
  } else {
    await doRun({}, { aborted: false });
  }
  const elapsed = (Date.now() - started) / 1000;
  const gateTripped = failOn !== "none" &&
    findings.some((f) => gateCounts(f) && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[capitalize(failOn)]);

  // 3–6 · Output
  if (format === "json") out(JSON.stringify(result, null, 2));
  else if (format === "html") process.stdout.write(renderHtml(result, { includeTests: includeTestsFlag }));
  else if (format === "markdown") { if (!outputs.length) out(markdown(result, { includeTests: includeTestsFlag })); }
  else if (format === "text" || format === "github") {
    if (format === "github") process.stdout.write(githubAnnotations(result));
    process.stdout.write(ciText(result, { version: pkg.version, project: info.project, elapsed, filesWalked: pre.total, failOn, gateTripped, report: reportName, profile: repo }));
  } else {
    const summary = summaryScreen(result, { ...info, elapsed, filesWalked: pre.total, report: reportName, failOn, gateTripped, partial, includeTests: includeTestsFlag, profile: repo });
    screen(summary.lines);
    let withTests = includeTestsFlag;
    const hidden = summary.view.hidden.length;
    if (hidden && !includeTestsFlag) {
      const q = `Show ${hidden} more finding${hidden === 1 ? "" : "s"} from test files and local env files?`;
      if (askable) withTests = (await ask({ question: q, defaultYes: false, hint: "enter keeps the default · y / n" })) === true;
      else if (interactive) screen(" " + collapsed(q, null, yes ? "--yes" : "no input"));
      out("");
    }
    out("");
    screen(findingsScreen({ width, all: Boolean(a.all), report: reportName, findings: withTests ? result.findings : summary.view.shown,
      scope: withTests ? "incl. tests" : "in source" }));
    out("");
    screen(fixScreen({ width, view: summary.view, verdict: summary.verdict, report: reportName, failOn, elapsed }));
    if (outputs.length) {
      const q = `Open ${basename(outputs[0])} now?`;
      if (askable) { if ((await ask({ question: q, defaultYes: true, hint: "y / n" })) === true) openFile(outputs[0]); }
      else if (interactive) screen(" " + collapsed(q, null, yes ? "--yes" : "no input"));
      out("");
    }
  }
  if (updateCheck) {
    const notice = updateNotice(pkg.version, await withDeadline(updateCheck, 400));
    if (notice) out(notice);
  }
  return gateTripped ? 1 : 0;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Exit only after stdout has drained: process.exit() right after a large write to a pipe cuts it off at 64 KB.
main().then((code) => process.stdout.write("", () => process.exit(code)), (err) => {
  process.stderr.write(`ERROR: ${(err as Error)?.stack ?? err}\n`);
  process.exit(2);
});
