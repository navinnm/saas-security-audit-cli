import { readFileSync } from "node:fs";

/** The CLI's own published version (the rule set has its own version in rules.json). */
export const CLI_VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;
