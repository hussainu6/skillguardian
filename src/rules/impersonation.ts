import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS008 — False authority / impersonation.
 *
 * Skills that claim to be official, verified, or endorsed by a vendor borrow
 * trust they haven't earned, which makes a user likelier to grant broad access.
 * This is a signal, not proof, so it is scored "low" — a real vendor skill will
 * also trip it, and that's fine; it just prompts a look.
 */
const CLAIMS =
  /\b(official(ly)?|verified|certified|endorsed|approved by|trusted|authorized)\b[^.\n]{0,30}\b(anthropic|openai|github|google|microsoft|aws|claude|vendor|team)\b/gi;

// Urgency only counts when it pushes a concrete action — plain "you must consider"
// is normal prose, "you must run/execute/install immediately" is a pressure tactic.
const URGENCY =
  /\b(?:immediately|right now|without asking|as soon as possible|urgently)\b[^.\n]{0,40}\b(?:run|execute|install|download|delete|remove|send|post|grant|approve|disable|paste)\b|\b(?:run|execute|install|download|delete|remove|send|post|grant|approve|disable|paste)\b[^.\n]{0,40}\b(?:immediately|right now|without asking|as soon as possible|urgently)\b|\bwithout (?:asking|telling|informing|notifying)\b[^.\n]{0,20}\b(?:the user|the human|them|anyone)\b/gi;

export const impersonation: Rule = {
  id: "SS008",
  title: "Claims false authority or pressures the user",
  severity: "low",
  description: "Flags 'official/verified' authority claims and urgency phrasing used to lower a user's guard.",
  scan(component) {
    return [
      ...findingsFromMatches(
        impersonation,
        matchAll(component, CLAIMS),
        "Claims official or verified status; confirm the source independently before trusting it.",
        "If genuinely official, rely on the publisher's verified account rather than in-file claims.",
      ),
      ...findingsFromMatches(
        impersonation,
        matchAll(component, URGENCY),
        "Uses urgency or pressure language, a social-engineering tell.",
        "Legitimate skills don't need to rush the user; remove pressure phrasing.",
      ),
    ];
  },
};
