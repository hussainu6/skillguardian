import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, sep } from "node:path";
import type { Component, ScannedFile } from "./types.js";

/** Directories we never descend into. */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
]);

/** File extensions worth reading as text for scanning. */
const TEXT_EXT = new Set([
  ".md",
  ".markdown",
  ".mdx",
  ".json",
  ".jsonc",
  ".yaml",
  ".yml",
  ".toml",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".py",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".txt",
]);

const MAX_FILE_BYTES = 1_000_000; // skip anything larger; payloads live in text

interface RawFile {
  path: string;
  relativePath: string;
}

function walk(root: string, dir: string, out: RawFile[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      walk(root, full, out);
    } else if (st.isFile()) {
      if (st.size > MAX_FILE_BYTES) continue;
      const ext = extname(entry).toLowerCase();
      const name = basename(entry).toLowerCase();
      if (TEXT_EXT.has(ext) || name === "skill" || name === "readme") {
        out.push({ path: full, relativePath: relative(root, full).split(sep).join("/") });
      }
    }
  }
}

function readFile(raw: RawFile): ScannedFile | undefined {
  try {
    return { path: raw.path, relativePath: raw.relativePath, content: readFileSync(raw.path, "utf8") };
  } catch {
    return undefined;
  }
}

/** The directory key one level above a file, used to group a component. */
function componentRoot(relativePath: string): string {
  const parts = relativePath.split("/");
  return parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
}

function classify(files: ScannedFile[], rootName: string): Component {
  const names = files.map((f) => basename(f.relativePath).toLowerCase());
  let kind: Component["kind"] = "unknown";
  if (names.some((n) => n === "skill.md" || n === "skill")) kind = "skill";
  else if (names.some((n) => n.includes("mcp") || n === "mcp.json")) kind = "mcp";
  else if (names.some((n) => n === "plugin.json" || n === "manifest.json")) kind = "plugin";
  else if (files.some((f) => /mcpServers\s*[:"]/.test(f.content))) kind = "mcp";
  else if (names.some((n) => n.endsWith(".md"))) kind = "skill";

  return { kind, name: rootName === "." ? basename(process.cwd()) : rootName.split("/").pop() ?? rootName, root: rootName, files };
}

/** Convert a minimal glob (`*`, `**`, `?`) to a RegExp anchored to the whole path. */
function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*"; // ** matches across path separators
        i++;
        if (glob[i + 1] === "/") i++; // swallow the slash after **
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (".+^${}()|[]\\".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp("^" + re + "$");
}

function makeIgnore(patterns: string[] | undefined): (path: string) => boolean {
  if (!patterns || patterns.length === 0) return () => false;
  const res = patterns.map(globToRegExp);
  return (path: string) => res.some((r) => r.test(path));
}

/**
 * Discover components under `root`. Files are grouped by their containing
 * directory; each group becomes one component whose kind is inferred from the
 * files present (SKILL.md → skill, mcp config → mcp, plugin manifest → plugin).
 * `ignore` is a list of globs (matched against each file's relative path) to skip.
 */
export function discover(root: string, ignore?: string[]): Component[] {
  const st = statSync(root);
  const raws: RawFile[] = [];
  const ignored = makeIgnore(ignore);

  if (st.isFile()) {
    raws.push({ path: root, relativePath: basename(root) });
  } else {
    walk(root, root, raws);
  }

  const byDir = new Map<string, ScannedFile[]>();
  for (const raw of raws) {
    if (ignored(raw.relativePath)) continue;
    const sf = readFile(raw);
    if (!sf) continue;
    const key = componentRoot(sf.relativePath);
    const arr = byDir.get(key) ?? [];
    arr.push(sf);
    byDir.set(key, arr);
  }

  const components: Component[] = [];
  for (const [dir, files] of byDir) {
    components.push(classify(files, dir));
  }
  // Stable order for reproducible reports.
  components.sort((a, b) => a.root.localeCompare(b.root));
  return components;
}
