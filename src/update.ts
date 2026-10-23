/**
 * Update notifier and `saas-audit update`.
 *
 * The scan itself never touches the network. This module makes at most one request per day,
 * only in interactive terminals, to ask the public npm registry for the latest published
 * version of this package. It sends nothing about the scanned code. Disable with
 * --no-update-check, SAAS_AUDIT_NO_UPDATE_CHECK=1, or NO_UPDATE_NOTIFIER=1.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { c, gradient } from "./ui/theme.js";

export const PACKAGE = "saas-security-audit";
const REGISTRY_URL = `https://registry.npmjs.org/${PACKAGE}/latest`;
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const BACKGROUND_TIMEOUT_MS = 2000;
const EXPLICIT_TIMEOUT_MS = 10000;

const cacheFile = () =>
  join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), PACKAGE, "update-check.json");

/** -1 if a < b, 0 if equal, 1 if a > b. Pre-releases sort before their release. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core, pre] = v.replace(/^v/, "").split("-", 2);
    return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre: pre ?? "" };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d) return d > 0 ? 1 : -1;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}

export function updateCheckEnabled(interactive: boolean, flagDisabled: boolean): boolean {
  const env = process.env;
  return interactive && !flagDisabled && !env.CI && !env.SAAS_AUDIT_NO_UPDATE_CHECK && !env.NO_UPDATE_NOTIFIER;
}

async function fetchLatest(timeoutMs = BACKGROUND_TIMEOUT_MS): Promise<string | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(REGISTRY_URL, { signal: ctrl.signal, headers: { accept: "application/json" } });
    if (!res.ok) return null;
    const body = (await res.json()) as { version?: unknown };
    return typeof body.version === "string" ? body.version : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Latest published version (cached for a day), or null if unknown. Never throws. */
export async function latestVersion(): Promise<string | null> {
  const file = cacheFile();
  try {
    const cached = JSON.parse(readFileSync(file, "utf8")) as { checkedAt: number; latest: string | null };
    if (Date.now() - cached.checkedAt < CHECK_INTERVAL_MS) return cached.latest;
  } catch { /* no cache yet */ }
  const latest = await fetchLatest();
  try {
    mkdirSync(join(file, ".."), { recursive: true });
    writeFileSync(file, JSON.stringify({ checkedAt: Date.now(), latest }));
  } catch { /* read-only home; just skip caching */ }
  return latest;
}

/** Resolve within `ms` or give up, so the notifier can never delay the CLI. */
export function withDeadline<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([p, new Promise<null>((r) => setTimeout(() => r(null), ms).unref())]);
}

export function updateNotice(current: string, latest: string | null): string {
  if (!latest || compareVersions(latest, current) <= 0) return "";
  const line1 = `Update available  ${c.gray(current)} → ${c.green(c.bold(latest))}`;
  const line2 = `Run  ${c.cyan("saas-audit update")}`;
  const width = 44;
  const pad = (plain: string, styled: string) => styled + " ".repeat(Math.max(0, width - [...plain].length));
  return [
    "",
    gradient(" ╭" + "─".repeat(width + 2) + "╮"),
    `${gradient(" │")} ${pad(`Update available  ${current} → ${latest}`, line1)} ${gradient("│")}`,
    `${gradient(" │")} ${pad("Run  saas-audit update", line2)} ${gradient("│")}`,
    gradient(" ╰" + "─".repeat(width + 2) + "╯"),
    "",
  ].join("\n");
}

/** Fallback through npm itself, which honours the user's proxy and registry config (Node's fetch does not). */
function npmViewLatest(): string | null {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const r = spawnSync(npm, ["view", PACKAGE, "version", "--prefer-online"], { encoding: "utf8", timeout: 20000 });
  const v = (r.stdout ?? "").trim();
  return r.status === 0 && /^\d+\.\d+\.\d+/.test(v) ? v : null;
}

const ranViaNpx = () => /[\\/]_npx[\\/]/.test(process.argv[1] ?? "");

/** `saas-audit update [--dry-run]` */
export async function runUpdate(current: string, dryRun: boolean): Promise<number> {
  const out = (s = "") => process.stdout.write(s + "\n");
  if (ranViaNpx()) {
    out(`You're running through npx. ${c.cyan(`npx ${PACKAGE}@latest`)} always fetches the newest version.`);
    return 0;
  }
  out(`${gradient("◢◤")} Checking the npm registry for the latest ${PACKAGE}…`);
  const latest = (await fetchLatest(EXPLICIT_TIMEOUT_MS)) ?? npmViewLatest();
  if (!latest) {
    out(c.yellow("Couldn't reach the npm registry. Check your connection and try again."));
    return 1;
  }
  if (compareVersions(latest, current) <= 0) {
    out(`${c.green("✔")} You're on the latest version (${current}).`);
    return 0;
  }
  const args = ["install", "-g", `${PACKAGE}@${latest}`, "--prefer-online"];
  out(`Updating ${current} → ${c.bold(latest)}:  ${c.gray("npm " + args.join(" "))}`);
  if (dryRun) return 0;
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npm, args, { stdio: "inherit" });
  if (result.status === 0) {
    out(`${c.green("✔")} Updated to ${latest}.`);
    return 0;
  }
  out(c.yellow("Update failed. If you see EACCES, fix npm permissions (or use nvm) instead of running with sudo:"));
  out(c.gray("  https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally"));
  return 1;
}
