import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS018 — Browser / credential-store theft.
 *
 * Browsers keep saved logins and cookies in well-known files. A skill that reads
 * `Login Data`, `key4.db`/`logins.json`, cookie databases, or dumps the OS
 * keychain is after saved passwords and session tokens. We match the specific
 * file names so ordinary mentions of "Chrome" don't trip it.
 */
const BROWSER_SECRETS =
  /\bLogin Data\b|\bkey4\.db\b|\blogins\.json\b|\bcookies\.sqlite\b|\bmoz_cookies\b|\bLocal State\b[^\n]*(?:Chrome|Edge|Brave|Chromium)|(?:Chrome|Edge|Brave|Chromium)[^\n]*\bLocal State\b|security\s+find-generic-password|security\s+dump-keychain|\bColumnMasterKey\b/i;

export const browserTheft: Rule = {
  id: "SS018",
  title: "Reads browser or OS credential stores",
  severity: "high",
  description: "Flags access to saved-password / cookie files (Login Data, key4.db, logins.json, cookies.sqlite) and keychain dumps.",
  scan(component) {
    return findingsFromMatches(
      browserTheft,
      matchAll(component, BROWSER_SECRETS),
      "Reads a browser or OS credential store that holds saved passwords, cookies, or session tokens.",
      "Remove it. A skill has no legitimate need to read saved browser logins, cookie databases, or the keychain.",
    );
  },
};
