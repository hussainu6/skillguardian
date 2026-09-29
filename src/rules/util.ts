import type { Component, Finding, ScannedFile, Severity } from "../types.js";

export interface Match {
  file: ScannedFile;
  line: number;
  text: string;
  /** The specific captured substring that triggered the match. */
  captured: string;
}

/**
 * Run a regex against every file in a component and yield line-anchored matches.
 * The regex should be global; we reset lastIndex per line to keep line numbers.
 */
export function matchAll(component: Component, pattern: RegExp): Match[] {
  const matches: Match[] = [];
  for (const file of component.files) {
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        matches.push({ file, line: i + 1, text: line, captured: m[0] });
        if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width loops
      }
    }
  }
  return matches;
}

/** Trim and cap a snippet so reports never dump huge or raw payloads. */
export function defang(snippet: string, max = 160): string {
  const collapsed = snippet.replace(/\s+/g, " ").trim();
  const clipped = collapsed.length > max ? collapsed.slice(0, max) + "…" : collapsed;
  // Escape control chars so terminals/markdown can't be driven by evidence.
  return clipped.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
}

/** Build a finding with consistent defaults. */
export function finding(
  rule: { id: string; title: string; severity: Severity },
  part: { file: string; line?: number; evidence?: string; message: string; remediation: string },
): Finding {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    file: part.file,
    line: part.line,
    evidence: part.evidence ? defang(part.evidence) : undefined,
    message: part.message,
    remediation: part.remediation,
  };
}

/** Collapse many matches of one rule into findings (one per match, deduped by line). */
export function findingsFromMatches(
  rule: { id: string; title: string; severity: Severity },
  matches: Match[],
  message: string,
  remediation: string,
): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const m of matches) {
    const key = `${m.file.relativePath}:${m.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding(rule, { file: m.file.relativePath, line: m.line, evidence: m.captured, message, remediation }));
  }
  return out;
}
