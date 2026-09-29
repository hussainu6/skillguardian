import { type Finding, type Grade, type Severity, SEVERITY_WEIGHT } from "./types.js";

/**
 * Turn a set of findings into a 0-100 risk score.
 *
 * 100 = clean. Each finding subtracts its severity weight. A single critical
 * finding alone drops a component out of the "A" band, which is intentional:
 * one credential-exfiltration pattern is enough to fail a skill.
 */
export function scoreFindings(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.max(0, 100 - penalty);
}

export function gradeForScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

export function emptyTotals(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function tallyTotals(findings: Finding[]): Record<Severity, number> {
  const totals = emptyTotals();
  for (const f of findings) totals[f.severity] += 1;
  return totals;
}
