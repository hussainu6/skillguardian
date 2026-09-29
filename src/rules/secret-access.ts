import type { Finding, Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS002 — Reads secrets or credential stores.
 *
 * A skill that *accesses* `.env`, SSH keys, cloud credential files, or the OS
 * keychain is reaching for material it almost never needs. To avoid flagging
 * benign mentions ("set your OPENAI_API_KEY"), we require a read/transmit verb on
 * the same line as the target — the access, not the name. Combined with an egress
 * path (SS005/SS010) this is how credential theft is staged.
 */
const SECRET_TARGET =
  /(\.env(?:\.[a-z]+)?\b|id_rsa|id_ed25519|\.ssh\/|\.aws\/credentials|\.config\/gcloud|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|security\s+find-generic-password|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|private[_-]?key)/i;

// An access/read/transmit action indicating the secret is being consumed, not just named.
const ACCESS_VERB =
  /\b(read|reads|reading|open|opens|cat|less|load|loads|contents?\s+of|fs\.readfile|readfilesync|require|import|dotenv|source|print|printf|echo|dump|copy|copies|send|sends|post|posts|upload|uploads|exfiltrat|access|parse|parses|grep|find)\b/i;

export const secretAccess: Rule = {
  id: "SS002",
  title: "Reads secrets or credential stores",
  severity: "medium",
  description: "Flags lines that read or transmit .env files, SSH/cloud keys, tokens, or OS keychains (mere mentions are ignored).",
  scan(component) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const t = SECRET_TARGET.exec(line);
        if (!t) continue;
        if (!ACCESS_VERB.test(line)) continue; // a bare mention is not an access
        const key = `${file.relativePath}:${i + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(
          finding(secretAccess, {
            file: file.relativePath,
            line: i + 1,
            evidence: t[0],
            message: "Reads or transmits a secret or credential store that skills rarely need to touch.",
            remediation: "Confirm the skill genuinely needs this. Never have a skill read credentials to pass them elsewhere.",
          }),
        );
      }
    }
    return findings;
  },
};
