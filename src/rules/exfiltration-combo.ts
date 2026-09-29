import type { Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS010 — Exfiltration combination (the dangerous pairing).
 *
 * Reading secrets is medium-risk. A network drop point is high-risk. Together in
 * one component they form a complete credential-theft path — read, then send —
 * so we raise a single critical finding for the pairing. This catches skills
 * that look benign rule-by-rule but are malicious as a whole.
 */
const READS_SENSITIVE =
  /(\.env\b|id_rsa|id_ed25519|\.ssh\/|\.aws\/credentials|process\.env|os\.environ|GITHUB_TOKEN|API_KEY|SECRET|private[_-]?key)/i;

const SENDS_OUT =
  /(fetch\(|axios|requests\.(post|get)|urllib|curl|wget|XMLHttpRequest|http\.request|webhook|https?:\/\/)/i;

export const exfiltrationCombo: Rule = {
  id: "SS010",
  title: "Reads secrets and sends data out",
  severity: "critical",
  description: "Fires when one component both accesses secrets and has a network egress path — a complete exfiltration chain.",
  scan(component) {
    let readsAt: { file: string; line: number } | undefined;
    let sendsAt: { file: string; line: number } | undefined;

    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (!readsAt && READS_SENSITIVE.test(line)) readsAt = { file: file.relativePath, line: i + 1 };
        if (!sendsAt && SENDS_OUT.test(line)) sendsAt = { file: file.relativePath, line: i + 1 };
      }
    }

    if (readsAt && sendsAt) {
      return [
        finding(exfiltrationCombo, {
          file: readsAt.file,
          line: readsAt.line,
          evidence: `reads secrets (${readsAt.file}:${readsAt.line}) and sends data out (${sendsAt.file}:${sendsAt.line})`,
          message: "This component both accesses secret material and can send data over the network — the two halves of an exfiltration.",
          remediation: "Separate these concerns or remove one side. A skill that reads credentials should never also have an egress path.",
        }),
      ];
    }
    return [];
  },
};
