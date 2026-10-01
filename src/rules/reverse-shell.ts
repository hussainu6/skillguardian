import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS017 — Reverse / bind shell.
 *
 * A reverse shell hands an attacker an interactive prompt on the machine. These
 * patterns are almost never anything else — `/dev/tcp`, `nc -e`, a `socat EXEC`,
 * or a `pty.spawn` wired to a socket are the canonical one-liners, so this is
 * critical.
 */
const REVERSE_SHELL =
  /\/dev\/(?:tcp|udp)\/|bash\s+-i\b[^\n]*(?:>&|\/dev\/tcp)|\bn(?:c|cat)\b[^\n]*\s-[a-z]*e\b|\bsocat\b[^\n]*\bexec\b|mkfifo\b[^\n]*\|\s*(?:nc|ncat|bash|sh)\b|pty\.spawn\s*\(|socket\.socket\([^\n]*\n?[^\n]*(?:subprocess|pty|\/bin\/)|Invoke-PowerShellTcp|System\.Net\.Sockets\.TCPClient/i;

export const reverseShell: Rule = {
  id: "SS017",
  title: "Reverse or bind shell",
  severity: "critical",
  description: "Detects reverse/bind shell one-liners (/dev/tcp, nc -e, socat EXEC, pty.spawn on a socket).",
  scan(component) {
    return findingsFromMatches(
      reverseShell,
      matchAll(component, REVERSE_SHELL),
      "Contains a reverse/bind shell pattern that would hand an attacker interactive access to the machine.",
      "Remove it. There is no legitimate reason for a skill to open a shell back to a remote host.",
    );
  },
};
