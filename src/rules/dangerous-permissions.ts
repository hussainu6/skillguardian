import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS007 — Safety switches turned off.
 *
 * Flags flags and config that disable the guardrails an agent runtime ships
 * with: auto-approval of tool calls, skipping permission prompts, disabling the
 * sandbox, or allow-listing every command. Each one removes a human checkpoint.
 */
const DANGER_FLAGS =
  /(--dangerously-skip-permissions|--dangerously-run-mcp-servers|--no-sandbox|--disable-sandbox|--yolo|autoApprove|auto_approve|skip_confirmation|"?permissions"?\s*:\s*"?(bypass|all|full)|allowedCommands?\s*:\s*\[?\s*["'`]?\*)/gi;

export const dangerousPermissions: Rule = {
  id: "SS007",
  title: "Disables safety guardrails",
  severity: "high",
  description: "Detects auto-approval, sandbox-disabling, and wildcard command allow-lists.",
  scan(component) {
    return findingsFromMatches(
      dangerousPermissions,
      matchAll(component, DANGER_FLAGS),
      "Turns off a guardrail (approval prompt, sandbox, or command allow-list) that normally requires a human in the loop.",
      "Remove the flag, or scope permissions to the specific commands the skill needs.",
    );
  },
};
