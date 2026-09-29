import type { Rule } from "../types.js";
import { hiddenUnicode } from "./hidden-unicode.js";
import { secretAccess } from "./secret-access.js";
import { shellExecution } from "./shell-execution.js";
import { obfuscation } from "./obfuscation.js";
import { networkEgress } from "./network-egress.js";
import { promptOverride } from "./prompt-override.js";
import { dangerousPermissions } from "./dangerous-permissions.js";
import { impersonation } from "./impersonation.js";
import { destructiveCommands } from "./destructive-commands.js";
import { exfiltrationCombo } from "./exfiltration-combo.js";

/** All built-in rules, in stable id order. */
export const RULES: Rule[] = [
  hiddenUnicode,
  secretAccess,
  shellExecution,
  obfuscation,
  networkEgress,
  promptOverride,
  dangerousPermissions,
  impersonation,
  destructiveCommands,
  exfiltrationCombo,
];

export {
  hiddenUnicode,
  secretAccess,
  shellExecution,
  obfuscation,
  networkEgress,
  promptOverride,
  dangerousPermissions,
  impersonation,
  destructiveCommands,
  exfiltrationCombo,
};
