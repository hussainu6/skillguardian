import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS006 — Instruction-override / jailbreak language.
 *
 * Text aimed at the agent rather than the user: overriding earlier instructions,
 * suppressing the agent's safety behaviour, or coaxing it to reveal its system
 * prompt. Legitimate skills describe a task; they don't try to rewrite the
 * agent's rules.
 */
const OVERRIDE =
  /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|earlier|above|all)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|context)\b/gi;

const SUPPRESS_SAFETY =
  /\b(do not|don't|never)\b[^.\n]{0,40}\b(warn|refuse|ask|mention|tell|disclose|confirm)\b[^.\n]{0,40}\b(user|human|the person)\b/gi;

const LEAK_SYSTEM =
  /\b(reveal|print|repeat|output|show|leak|exfiltrate)\b[^.\n]{0,30}\b(system prompt|developer message|your instructions|hidden (rules|instructions))\b/gi;

export const promptOverride: Rule = {
  id: "SS006",
  title: "Attempts to override agent instructions",
  severity: "critical",
  description: "Detects jailbreak phrasing: overriding prior instructions, suppressing safety, or leaking the system prompt.",
  scan(component) {
    return [
      ...findingsFromMatches(
        promptOverride,
        matchAll(component, OVERRIDE),
        "Instructs the agent to ignore or override its prior instructions.",
        "Skills should describe a task, not rewrite the agent's rules. Remove override language.",
      ),
      ...findingsFromMatches(
        promptOverride,
        matchAll(component, SUPPRESS_SAFETY),
        "Tells the agent to act without informing or confirming with the user.",
        "Remove instructions that hide actions from the user or bypass confirmation.",
      ),
      ...findingsFromMatches(
        promptOverride,
        matchAll(component, LEAK_SYSTEM),
        "Asks the agent to reveal its system prompt or hidden instructions.",
        "Remove; a legitimate skill has no reason to extract the agent's instructions.",
      ),
    ];
  },
};
