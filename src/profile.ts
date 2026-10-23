/** Repository profile for the terminal UI: languages by file count, top-level folders and their roles. */
import { readdirSync } from "node:fs";
import type { WalkedFile } from "./engine.js";
import { SKIP_DIRS } from "./rules.js";

const LANGUAGES: Record<string, string> = {
  ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
  ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
  ".py": "Python", ".php": "PHP", ".rb": "Ruby", ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
  ".cs": "C#", ".rs": "Rust", ".swift": "Swift", ".scala": "Scala", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir",
  ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
  ".vue": "Vue", ".svelte": "Svelte", ".astro": "Astro",
  ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "CSS", ".sass": "CSS", ".less": "CSS",
  ".erb": "Templates", ".ejs": "Templates", ".hbs": "Templates", ".njk": "Templates", ".twig": "Templates", ".jinja": "Templates", ".j2": "Templates",
  ".sql": "SQL", ".prisma": "Prisma", ".graphql": "GraphQL", ".gql": "GraphQL",
  ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ps1": "PowerShell",
  ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".toml": "TOML", ".tf": "Terraform", ".tfvars": "Terraform",
  ".md": "Markdown", ".mdx": "Markdown",
};

export type FolderRole = "source" | "build output" | "tests" | "docs" | "config" | "dependencies" | "assets";

const ROLE_BY_NAME: [RegExp, FolderRole][] = [
  [/^(?:\.next(?:-.+)?|dist|build|out|\.output|\.nuxt|\.svelte-kit|\.vercel|\.turbo|storybook-static|public\/build|bootstrap\/cache|storage)$/i, "build output"],
  [/^(?:tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|testdata)$/i, "tests"],
  [/^(?:docs?|\.agents|\.claude|\.cursor|examples?|samples?)$/i, "docs"],
  [/^(?:\.github|\.circleci|\.husky|\.vscode|config|infra|deploy|docker|k8s|helm|terraform|\.devcontainer)$/i, "config"],
  [/^(?:public|static|assets|images|img|fonts|media|resources\/(?:css|js|images))$/i, "assets"],
];

export function folderRole(name: string): FolderRole {
  for (const [re, role] of ROLE_BY_NAME) if (re.test(name)) return role;
  return "source";
}

export function languageOf(name: string): string | null {
  if (/\.blade\.php$/i.test(name)) return "Blade";
  const i = name.lastIndexOf(".");
  if (i <= 0) return name === "Dockerfile" || name.startsWith("Dockerfile.") ? "Docker" : null;
  return LANGUAGES[name.slice(i).toLowerCase()] ?? null;
}

export interface Profile {
  languages: { name: string; files: number; share: number }[];
  otherFiles: number;
  folders: { name: string; files: number; role: FolderRole }[];
  rootFiles: number;
  /** Heavy folders present at the root that the scan skips by design (node_modules, vendor, .git…). */
  skippedDirs: string[];
}

export function profile(root: string, files: WalkedFile[]): Profile {
  const langCounts = new Map<string, number>();
  let otherFiles = 0;
  const folderCounts = new Map<string, number>();
  let rootFiles = 0;
  for (const f of files) {
    const lang = languageOf(f.name);
    if (lang) langCounts.set(lang, (langCounts.get(lang) ?? 0) + 1);
    else otherFiles++;
    const slash = f.rel.indexOf("/");
    if (slash < 0) rootFiles++;
    else {
      const top = f.rel.slice(0, slash);
      folderCounts.set(top, (folderCounts.get(top) ?? 0) + 1);
    }
  }
  const known = [...langCounts.values()].reduce((a, b) => a + b, 0) || 1;
  const languages = [...langCounts.entries()]
    .map(([name, n]) => ({ name, files: n, share: n / known }))
    .sort((a, b) => b.files - a.files || (a.name < b.name ? -1 : 1));
  const folders = [...folderCounts.entries()]
    .map(([name, n]) => ({ name, files: n, role: folderRole(name) }))
    .sort((a, b) => b.files - a.files || (a.name < b.name ? -1 : 1));
  let skippedDirs: string[] = [];
  try {
    skippedDirs = readdirSync(root, { withFileTypes: true })
      .filter((e) => e.isDirectory() && SKIP_DIRS.has(e.name)).map((e) => e.name).sort();
  } catch { /* unreadable root: nothing to report */ }
  return { languages, otherFiles, folders, rootFiles, skippedDirs };
}

/** Top-level folder of a repo-relative path, or "(root)". */
export const topFolder = (rel: string) => (rel.includes("/") ? rel.slice(0, rel.indexOf("/")) : "(root)");
