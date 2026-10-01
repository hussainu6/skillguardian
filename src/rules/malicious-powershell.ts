import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS021 — Obfuscated / download-and-run PowerShell.
 *
 * The Windows equivalent of `curl | bash`: an encoded command, a hidden window,
 * a bypassed execution policy, or `IEX` on content pulled from the network. Each
 * is a strong attacker tell.
 */
const BAD_POWERSHELL =
  /powershell(?:\.exe)?[^\n]*(?:-e(?:nc|ncodedcommand)?\b|-nop\b|-noni\b|-w(?:indowstyle)?\s+hidden|-ec\b)|IEX\s*\(\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)|(?:New-Object\s+Net\.WebClient)[^\n]*\.DownloadString|\.DownloadString\s*\(|FromBase64String[^\n]*\|\s*IEX|-ExecutionPolicy\s+Bypass/i;

export const maliciousPowershell: Rule = {
  id: "SS021",
  title: "Obfuscated or download-and-run PowerShell",
  severity: "high",
  description: "Detects encoded/hidden PowerShell, execution-policy bypass, and IEX of network-downloaded content.",
  scan(component) {
    return findingsFromMatches(
      maliciousPowershell,
      matchAll(component, BAD_POWERSHELL),
      "Runs PowerShell in an evasive way (encoded/hidden, policy bypass, or executing downloaded content).",
      "Remove it. Ship readable, explicit scripts; never download-and-execute or hide the window and encode the command.",
    );
  },
};
