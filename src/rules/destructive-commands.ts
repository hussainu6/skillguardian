import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS009 — Destructive commands.
 *
 * Irreversible operations a skill should never carry out on its own: recursive
 * force-deletes of broad paths, disk wipes, force-pushes over shared branches,
 * and destructive database statements. These belong to the user, not a skill.
 */
const DESTRUCTIVE =
  /(\brm\s+-rf?\s+(\/|~|\$HOME|\*)|\bdd\s+if=.*of=\/dev\/|mkfs\.|:\(\)\s*\{.*\|.*&\s*\}|\bgit\s+push\s+(--force|-f)\b|\bgit\s+reset\s+--hard\b|\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b|\bDELETE\s+FROM\b[^\n]*(?!where))/gi;

export const destructiveCommands: Rule = {
  id: "SS009",
  title: "Runs destructive or irreversible commands",
  severity: "high",
  description: "Detects recursive force-deletes, disk wipes, force-pushes, and destructive SQL.",
  scan(component) {
    return findingsFromMatches(
      destructiveCommands,
      matchAll(component, DESTRUCTIVE),
      "Contains a destructive, hard-to-reverse command that a skill should not run unattended.",
      "Require explicit user confirmation for destructive actions; never bake them into a skill's steps.",
    );
  },
};
