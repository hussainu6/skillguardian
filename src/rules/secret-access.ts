import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS002 — References to secret material and credential stores.
 *
 * A skill that asks the agent to read `.env`, SSH keys, cloud credential files,
 * or the OS keychain is reaching for material it almost never needs. On its own
 * this is "medium" — combined with SS003/SS007 (a way to send data out) it is
 * how credential theft is staged.
 */
const SECRET_TARGETS =
  /(\.env(\.[a-z]+)?|id_rsa|id_ed25519|\.ssh\/|\.aws\/credentials|\.config\/gcloud|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|security\s+find-generic-password|secrets\.[a-z]+|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|private[_-]?key)/gi;

export const secretAccess: Rule = {
  id: "SS002",
  title: "Reads secrets or credential stores",
  severity: "medium",
  description: "Flags references to .env files, SSH/cloud keys, tokens, and OS keychains.",
  scan(component) {
    const matches = matchAll(component, SECRET_TARGETS);
    return findingsFromMatches(
      secretAccess,
      matches,
      "References a secret or credential store that skills rarely need to touch.",
      "Confirm the skill genuinely needs this. Never have a skill read credentials to pass them elsewhere.",
    );
  },
};
