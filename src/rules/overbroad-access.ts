import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS013 — Overbroad filesystem access.
 *
 * A focused skill reads the files it needs. One that recursively walks the whole
 * home directory or the entire tree is casting a net wide enough to scoop up
 * credentials, keys, and private data by accident or design. Medium-risk on its
 * own; a strong amplifier for any egress path.
 */
const OVERBROAD =
  /(find\s+(~|\/|\$HOME)\s+-type\s+f|ls\s+-R\s+(~|\/|\$HOME)|Get-ChildItem\s+.*-Recurse.*(\$env:USERPROFILE|~|C:\\Users)|glob(\.glob)?\(['"][^'"]*\*\*|globby?\(['"][^'"]*\*\*|fs\.readdir[a-zA-Z]*\([^)]*recursive\s*:\s*true|tar\s+-?c[a-z]*f?\s+\S+\s+(~|\/home|\$HOME)|cp\s+-r\s+(~|\/home|\$HOME)|readdirSync\([^)]*recursive)/gi;

export const overbroadAccess: Rule = {
  id: "SS013",
  title: "Overbroad filesystem access",
  severity: "medium",
  description: "Flags recursive reads of the home directory or whole-tree glob(**) that can scoop up secrets and private files.",
  scan(component) {
    return findingsFromMatches(
      overbroadAccess,
      matchAll(component, OVERBROAD),
      "Recursively reads a very broad path (home directory or entire tree), which can sweep up credentials and private files.",
      "Scope file access to the specific directory the skill needs, not the whole home directory or a `**` glob.",
    );
  },
};
