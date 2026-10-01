import { gradeForScore, scoreFindings, tallyTotals } from "./grade.js";
import { RULES } from "./rules/index.js";
import type { Component, ComponentResult, Finding, Rule, ScanReport, Severity } from "./types.js";
import { emptyTotals } from "./grade.js";

export interface ScanOptions {
  /** Restrict to these rule ids (default: all). */
  only?: string[];
  /** Exclude these rule ids. */
  skip?: string[];
  /** Override the rule set entirely (used in tests). */
  rules?: Rule[];
  /** Drop findings below this severity from the report. */
  minSeverity?: Severity;
  /** Honor inline `skillguardian-ignore` comments (default: true). */
  suppressions?: boolean;
  /** Globs (matched against each file's relative path) to skip during discovery. */
  ignore?: string[];
}

const VERSION = "0.4.0";

function selectRules(opts: ScanOptions): Rule[] {
  let rules = opts.rules ?? RULES;
  if (opts.only?.length) rules = rules.filter((r) => opts.only!.includes(r.id));
  if (opts.skip?.length) rules = rules.filter((r) => !opts.skip!.includes(r.id));
  return rules;
}

/** Scan a single already-loaded component. */
export function scanComponent(component: Component, opts: ScanOptions = {}): ComponentResult {
  const rules = selectRules(opts);
  let findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.scan(component));
    } catch {
      // A misbehaving rule must never crash the scan.
    }
  }
  if (opts.suppressions !== false) findings = findings.filter((f) => !isSuppressed(component, f));
  if (opts.minSeverity) {
    const limit = SEVERITY_ORDER[opts.minSeverity];
    findings = findings.filter((f) => SEVERITY_ORDER[f.severity] <= limit);
  }
  findings.sort(bySeverityThenLocation);
  const score = scoreFindings(findings);
  return {
    component: { kind: component.kind, name: component.name, root: component.root },
    findings,
    score,
    grade: gradeForScore(score),
  };
}

// Matches `skillguardian-ignore` / `-ignore-line` / `-disable` with an optional rule list.
const IGNORE_LINE = /skillguardian-(?:ignore|disable)(?:-line|-next-line)?\b(?:\s*[:=]?\s*([A-Za-z0-9,\s]+))?/i;
const IGNORE_FILE = /skillguardian-(?:ignore|disable)-file\b(?:\s*[:=]?\s*([A-Za-z0-9,\s]+))?/i;

function ruleListMatches(captured: string | undefined, ruleId: string): boolean {
  if (!captured || !captured.trim()) return true; // bare marker suppresses everything
  const ids = captured
    .toUpperCase()
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return ids.includes(ruleId.toUpperCase());
}

/**
 * A finding is suppressed when its own line, or the line directly above it,
 * carries a `skillguardian-ignore` marker (optionally naming this rule), or when
 * the file opens with a `skillguardian-ignore-file` marker.
 */
function isSuppressed(component: Component, finding: Finding): boolean {
  const file = component.files.find((f) => f.relativePath === finding.file);
  if (!file) return false;
  const lines = file.content.split(/\r?\n/);

  // File-level marker in the first 10 lines.
  for (const line of lines.slice(0, 10)) {
    const m = IGNORE_FILE.exec(line);
    if (m && ruleListMatches(m[1], finding.ruleId)) return true;
  }

  if (finding.line === undefined) return false;
  const here = lines[finding.line - 1];
  const above = lines[finding.line - 2];
  for (const line of [here, above]) {
    if (line === undefined) continue;
    if (IGNORE_FILE.test(line)) continue; // handled above; don't double-match
    const m = IGNORE_LINE.exec(line);
    if (m && ruleListMatches(m[1], finding.ruleId)) return true;
  }
  return false;
}

/** Scan many components and roll up totals. */
export function scanComponents(components: Component[], root: string, opts: ScanOptions = {}): ScanReport {
  const results = components.map((c) => scanComponent(c, opts));
  const allFindings = results.flatMap((r) => r.findings);
  const totals = components.length ? tallyTotals(allFindings) : emptyTotals();
  const score = scoreFindings(allFindings);
  return {
    version: VERSION,
    scannedAt: new Date().toISOString(),
    root,
    components: results,
    totals,
    score,
    grade: gradeForScore(score),
  };
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function bySeverityThenLocation(a: Finding, b: Finding): number {
  const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  if (s !== 0) return s;
  const f = a.file.localeCompare(b.file);
  if (f !== 0) return f;
  return (a.line ?? 0) - (b.line ?? 0);
}

/** Does this report contain a finding at or above the given severity? */
export function hasSeverityAtLeast(report: ScanReport, threshold: Severity): boolean {
  const limit = SEVERITY_ORDER[threshold];
  return report.components.some((c) => c.findings.some((f) => SEVERITY_ORDER[f.severity] <= limit));
}
