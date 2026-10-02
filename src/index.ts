/**
 * skillguardian — programmatic API.
 *
 * @example
 * import { scan } from "skillguardian";
 * const report = scan("./my-skill");
 * if (report.grade === "F") process.exit(1);
 */
export { discover } from "./discover.js";
export { scanComponents, scanComponent, hasSeverityAtLeast, type ScanOptions } from "./scanner.js";
export { RULES } from "./rules/index.js";
export { renderJson } from "./reporters/json.js";
export { renderSarif } from "./reporters/sarif.js";
export { renderMarkdown } from "./reporters/markdown.js";
export { renderTerminal } from "./reporters/terminal.js";
export { loadConfig, type SkillguardianConfig } from "./config.js";
export { badgeUrl, badgeMarkdown, badgeHtml } from "./badge.js";
export {
  RULE_CAPABILITIES,
  CAPABILITY_LABEL,
  capabilitiesFor,
  detectComposedRisks,
  unionCapabilities,
} from "./capabilities.js";
export * from "./types.js";

import { discover } from "./discover.js";
import { scanComponents, type ScanOptions } from "./scanner.js";
import type { ScanReport } from "./types.js";

/** Convenience: discover components under `path` and scan them. */
export function scan(path: string, opts: ScanOptions = {}): ScanReport {
  const components = discover(path, opts.ignore);
  return scanComponents(components, path, opts);
}
