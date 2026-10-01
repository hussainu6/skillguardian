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
import { clipboardAccess } from "./clipboard-access.js";
import { typosquatting } from "./typosquatting.js";
import { overbroadAccess } from "./overbroad-access.js";
import { insecureEndpoint } from "./insecure-endpoint.js";
import { hardcodedSecret } from "./hardcoded-secret.js";
import { autorunHooks } from "./autorun-hooks.js";
import { reverseShell } from "./reverse-shell.js";
import { browserTheft } from "./browser-theft.js";
import { walletAccess } from "./wallet-access.js";
import { persistence } from "./persistence.js";
import { maliciousPowershell } from "./malicious-powershell.js";
import { antiForensics } from "./anti-forensics.js";

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
  clipboardAccess,
  typosquatting,
  overbroadAccess,
  insecureEndpoint,
  hardcodedSecret,
  autorunHooks,
  reverseShell,
  browserTheft,
  walletAccess,
  persistence,
  maliciousPowershell,
  antiForensics,
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
  clipboardAccess,
  typosquatting,
  overbroadAccess,
  insecureEndpoint,
  hardcodedSecret,
  autorunHooks,
  reverseShell,
  browserTheft,
  walletAccess,
  persistence,
  maliciousPowershell,
  antiForensics,
};
