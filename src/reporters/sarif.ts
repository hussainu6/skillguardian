import { RULES } from "../rules/index.js";
import type { ScanReport, Severity } from "../types.js";

/**
 * SARIF 2.1.0 output for GitHub code scanning. Uploading this in a workflow puts
 * each finding on the "Security" tab and inline on the PR diff.
 */

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

// security-severity drives GitHub's severity bucketing (0.0–10.0).
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export function renderSarif(report: ScanReport): string {
  const rules = RULES.map((r) => ({
    id: r.id,
    name: r.title.replace(/\s+/g, ""),
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
    properties: {
      "security-severity": SECURITY_SEVERITY[r.severity],
      tags: ["security", "ai-agent", "supply-chain"],
    },
  }));

  const results = report.components.flatMap((comp) =>
    comp.findings.map((f) => ({
      ruleId: f.ruleId,
      level: SARIF_LEVEL[f.severity],
      message: { text: `${f.message} ${f.remediation}`.trim() },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line ?? 1 },
          },
        },
      ],
      properties: { component: comp.component.name, severity: f.severity },
    })),
  );

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "skillguardian",
            informationUri: "https://github.com/hussainu6/skillguardian",
            version: report.version,
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
