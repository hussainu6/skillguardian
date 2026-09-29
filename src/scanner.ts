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
}

const VERSION = "0.1.0";

function selectRules(opts: ScanOptions): Rule[] {
  let rules = opts.rules ?? RULES;
  if (opts.only?.length) rules = rules.filter((r) => opts.only!.includes(r.id));
  if (opts.skip?.length) rules = rules.filter((r) => !opts.skip!.includes(r.id));
  return rules;
}

/** Scan a single already-loaded component. */
export function scanComponent(component: Component, opts: ScanOptions = {}): ComponentResult {
  const rules = selectRules(opts);
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.scan(component));
    } catch {
      // A misbehaving rule must never crash the scan.
    }
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
