import type { Finding, Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS012 — Typosquatted install targets.
 *
 * A classic supply-chain trick: a skill's setup steps install a package whose
 * name is one character off a popular one (`expres`, `loadsh`, `reqeusts`), so a
 * reviewer's eye slides right over it. We extract install targets from common
 * package-manager commands and flag any that are edit-distance 1 from a
 * well-known package without matching it exactly.
 */

// A small, high-signal list of frequently-squatted packages (npm + PyPI).
const POPULAR = [
  "react", "react-dom", "express", "lodash", "axios", "chalk", "commander",
  "dotenv", "webpack", "vite", "next", "vue", "angular", "typescript", "eslint",
  "prettier", "jest", "mocha", "nodemon", "mongoose", "sequelize", "bcrypt",
  "jsonwebtoken", "redux", "moment", "uuid", "cors", "body-parser", "socket.io",
  "requests", "numpy", "pandas", "flask", "django", "tensorflow", "scipy",
  "matplotlib", "pillow", "beautifulsoup4", "pytest", "setuptools", "urllib3",
  "colorama", "cryptography", "discord.py", "selenium", "pydantic",
];
const POPULAR_SET = new Set(POPULAR);

// Matches the install command prefix; the packages follow on the rest of the line.
const INSTALL_PREFIX =
  /(?:npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+(?:add|install)|bun\s+add|pip3?\s+install|poetry\s+add)\b/gi;

/**
 * Damerau (optimal string alignment) distance. Counts a substitution, an
 * insertion, a deletion, or an adjacent transposition each as one edit — so
 * classic squats like "loadsh"→"lodash" and "reqeusts"→"requests" register as
 * distance 1, not 2.
 */
function distance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 1) return 2;
  const la = a.length;
  const lb = b.length;
  const d: number[][] = Array.from({ length: la + 1 }, () => new Array<number>(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) d[i]![0] = i;
  for (let j = 0; j <= lb; j++) d[0]![j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, d[i - 2]![j - 2]! + 1);
      }
      d[i]![j] = best;
    }
  }
  return d[la]![lb]!;
}

/** Strip a scope and version range so "express@4" / "@scope/express" → "express". */
function normalize(pkg: string): string {
  let name = pkg.trim();
  if (name.startsWith("@") && name.includes("/")) name = name.split("/")[1] ?? name;
  name = name.replace(/@[\d^~<>=. *x-]+$/, ""); // drop trailing version
  return name.toLowerCase();
}

export const typosquatting: Rule = {
  id: "SS012",
  title: "Installs a possible typosquatted package",
  severity: "high",
  description: "Flags install targets that are one character off a popular package name (e.g. 'expres', 'reqeusts').",
  scan(component) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const re = new RegExp(INSTALL_PREFIX.source, "gi");
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
          // Everything after the command are the install targets (until a shell separator).
          const rest = line.slice(m.index + m[0].length).split(/[|&;><]/)[0] ?? "";
          const tokens = rest.split(/\s+/).filter((t) => t && !t.startsWith("-"));
          for (const token of tokens) {
            const name = normalize(token);
            if (!name || POPULAR_SET.has(name)) continue;
            const near = POPULAR.find((p) => distance(name, p) === 1);
            if (!near) continue;
            const key = `${file.relativePath}:${i + 1}:${name}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push(
              finding(typosquatting, {
                file: file.relativePath,
                line: i + 1,
                evidence: `installs "${name}" (looks like "${near}")`,
                message: `Installs "${name}", which is one character away from the popular package "${near}" — a classic typosquat.`,
                remediation: `Confirm the package name is correct. If you meant "${near}", fix the spelling; if not, verify the package is trustworthy.`,
              }),
            );
          }
        }
      }
    }
    return findings;
  },
};
