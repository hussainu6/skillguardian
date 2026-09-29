import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS011 — Clipboard access.
 *
 * The clipboard routinely holds passwords, 2FA codes, and tokens the user just
 * copied. A skill that reads it is positioned to capture exactly those secrets.
 * On its own it's medium-risk; paired with an egress path (SS005/SS010) it's how
 * clipboard contents get stolen.
 */
const CLIPBOARD =
  /(navigator\.clipboard|clipboard\.read(Text)?|pbpaste|xclip\s+-o|xsel\s+-b|Get-Clipboard|pyperclip\.paste|clipboardy(\.read)?|require\(['"]clipboardy['"]\))/gi;

export const clipboardAccess: Rule = {
  id: "SS011",
  title: "Reads the system clipboard",
  severity: "medium",
  description: "Flags clipboard reads, which can capture passwords, 2FA codes, and tokens the user just copied.",
  scan(component) {
    return findingsFromMatches(
      clipboardAccess,
      matchAll(component, CLIPBOARD),
      "Reads the system clipboard, which often holds passwords, one-time codes, or tokens.",
      "Remove clipboard access unless it is the skill's explicit, stated purpose — and never pair it with a network call.",
    );
  },
};
