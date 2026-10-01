import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Severity } from "./types.js";

/**
 * Optional project configuration, read from `.skillguardianrc.json` at the scan
 * root (or the nearest parent directory). Every field is optional; CLI flags
 * always take precedence over the file.
 */
export interface SkillguardianConfig {
  /** Rule ids to skip entirely, e.g. ["SS008"]. */
  disable?: string[];
  /** Default severity threshold that fails a run. */
  failOn?: Severity | "never";
  /** Drop findings below this severity from the report. */
  minSeverity?: Severity;
  /** Globs (matched against each file's relative path) to skip during discovery. */
  ignore?: string[];
}

const CONFIG_NAME = ".skillguardianrc.json";
const VALID_SEV = new Set(["critical", "high", "medium", "low", "info"]);

/** Walk up from `start` looking for a config file; stop at the filesystem root. */
function findConfigFile(start: string): string | undefined {
  let dir = start;
  try {
    if (statSync(dir).isFile()) dir = dirname(dir);
  } catch {
    return undefined;
  }
  for (;;) {
    const candidate = join(dir, CONFIG_NAME);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** Load and validate config. Returns an empty object when none is present or it's invalid. */
export function loadConfig(root: string): SkillguardianConfig {
  const file = findConfigFile(root);
  if (!file) return {};
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    process.stderr.write(`skillguardian: ignoring malformed ${file}\n`);
    return {};
  }
  if (typeof raw !== "object" || raw === null) return {};
  const obj = raw as Record<string, unknown>;
  const config: SkillguardianConfig = {};

  if (Array.isArray(obj.disable)) {
    config.disable = obj.disable.filter((x): x is string => typeof x === "string");
  }
  if (typeof obj.failOn === "string" && (obj.failOn === "never" || VALID_SEV.has(obj.failOn))) {
    config.failOn = obj.failOn as SkillguardianConfig["failOn"];
  }
  if (typeof obj.minSeverity === "string" && VALID_SEV.has(obj.minSeverity)) {
    config.minSeverity = obj.minSeverity as Severity;
  }
  if (Array.isArray(obj.ignore)) {
    config.ignore = obj.ignore.filter((x): x is string => typeof x === "string");
  }
  return config;
}
