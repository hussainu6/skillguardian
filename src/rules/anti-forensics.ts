import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS022 — Anti-forensics / covering tracks.
 *
 * Clearing shell history, disabling history logging, or wiping event logs is how
 * an intruder hides what they did. A legitimate skill never needs to erase the
 * record of its own actions.
 */
const ANTI_FORENSICS =
  /history\s+-c\b|unset\s+HISTFILE\b|HISTFILE=(?:\/dev\/null|)\s*$|export\s+HISTSIZE=0|set\s+\+o\s+history|rm\s+[^\n]*\.(?:bash|zsh)_history|Clear-History\b|Remove-Item[^\n]*ConsoleHost_history|wevtutil\s+cl\b|Clear-EventLog\b/i;

export const antiForensics: Rule = {
  id: "SS022",
  title: "Clears history or covers tracks",
  severity: "medium",
  description: "Flags clearing shell history, disabling history logging, or wiping event logs.",
  scan(component) {
    return findingsFromMatches(
      antiForensics,
      matchAll(component, ANTI_FORENSICS),
      "Erases shell history or logs, which hides what the skill did on the machine.",
      "Remove it. A trustworthy skill has no reason to delete the record of its own actions.",
    );
  },
};
