import type { ScanReport, Severity } from "../types.js";

const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const c = (code: string, s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const bold = (s: string) => c("1", s);
const dim = (s: string) => c("2", s);

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => c("41;97", s), // white on red bg
  high: (s) => c("31;1", s),
  medium: (s) => c("33", s),
  low: (s) => c("36", s),
  info: (s) => c("2", s),
};

const GRADE_COLOR: Record<string, (s: string) => string> = {
  A: (s) => c("32;1", s),
  B: (s) => c("32", s),
  C: (s) => c("33", s),
  D: (s) => c("31", s),
  F: (s) => c("41;97", s),
};

function badge(sev: Severity): string {
  return SEV_COLOR[sev](` ${sev.toUpperCase()} `);
}

export function renderTerminal(report: ScanReport): string {
  const out: string[] = [];
  out.push("");
  out.push(bold(`skill-safe v${report.version}`) + dim(`  ·  ${report.root}`));
  out.push("");

  if (report.components.length === 0) {
    out.push(dim("No skills, plugins, or MCP configs found to scan."));
    return out.join("\n");
  }

  for (const comp of report.components) {
    const g = GRADE_COLOR[comp.grade] ?? ((s: string) => s);
    const header = `${g(` ${comp.grade} `)} ${bold(comp.component.name)} ${dim(`(${comp.component.kind}) · ${comp.component.root}`)}`;
    out.push(header);
    if (comp.findings.length === 0) {
      out.push("   " + c("32", "✓ no issues"));
    } else {
      for (const f of comp.findings) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        out.push(`   ${badge(f.severity)} ${bold(f.ruleId)} ${f.title}`);
        out.push(`      ${dim(loc)}  ${f.message}`);
        if (f.evidence) out.push(`      ${dim("evidence:")} ${f.evidence}`);
        out.push(`      ${dim("fix:")} ${f.remediation}`);
      }
    }
    out.push("");
  }

  const t = report.totals;
  const summary =
    `${SEV_COLOR.critical(String(t.critical) + " critical")}  ` +
    `${SEV_COLOR.high(String(t.high) + " high")}  ` +
    `${SEV_COLOR.medium(String(t.medium) + " medium")}  ` +
    `${SEV_COLOR.low(String(t.low) + " low")}`;
  const g = GRADE_COLOR[report.grade] ?? ((s: string) => s);
  out.push(bold("Summary: ") + summary);
  out.push(bold("Overall: ") + g(` ${report.grade} `) + dim(`  score ${report.score}/100`));
  out.push("");
  return out.join("\n");
}
