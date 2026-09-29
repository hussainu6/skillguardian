import type { Finding, Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS015 — Hardcoded secret.
 *
 * A live API key or token committed into a skill, plugin manifest, or MCP config
 * leaks that credential to everyone who installs it. We match well-known key
 * shapes and skip obvious placeholders so real secrets stand out. The finding
 * never echoes the secret itself — only the provider and a masked hint.
 */
const PATTERNS: { provider: string; re: RegExp }[] = [
  { provider: "OpenAI", re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g },
  { provider: "Anthropic", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { provider: "GitHub", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
  { provider: "GitHub (fine-grained)", re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { provider: "AWS", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { provider: "Google", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { provider: "Slack", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { provider: "Stripe", re: /\bsk_live_[A-Za-z0-9]{20,}\b/g },
  { provider: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
];

// Obvious non-secrets we don't want to flag.
const PLACEHOLDER = /(x{4,}|0{4,}|1234|your[_-]?|example|placeholder|dummy|test|sample|redacted|<[^>]+>)/i;

function mask(secret: string): string {
  if (secret.length <= 8) return secret[0] + "***";
  return secret.slice(0, 4) + "…" + secret.slice(-2);
}

export const hardcodedSecret: Rule = {
  id: "SS015",
  title: "Hardcoded API key or token",
  severity: "high",
  description: "Detects committed credentials (OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe, JWT) and skips placeholders.",
  scan(component) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        for (const { provider, re } of PATTERNS) {
          re.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = re.exec(line)) !== null) {
            const secret = m[0];
            if (PLACEHOLDER.test(secret)) continue;
            const key = `${file.relativePath}:${i + 1}:${provider}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push(
              finding(hardcodedSecret, {
                file: file.relativePath,
                line: i + 1,
                evidence: `${provider} key (${mask(secret)})`,
                message: `Contains what looks like a live ${provider} credential committed into the file.`,
                remediation: "Remove the secret, rotate it immediately, and load credentials from the environment at runtime instead.",
              }),
            );
          }
        }
      }
    }
    return findings;
  },
};
