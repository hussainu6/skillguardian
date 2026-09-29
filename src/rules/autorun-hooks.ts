import type { Finding, Rule } from "../types.js";
import { defang, finding } from "./util.js";

/**
 * SS016 — Auto-running lifecycle hook.
 *
 * Hooks fire without the user asking: npm install scripts, and agent lifecycle
 * events (session start, pre/post tool use). A hook that runs a shell command —
 * especially one that reaches the network or a shell — executes the moment the
 * component is installed or loaded, before anyone has vetted its behavior.
 */
const HOOK_KEY =
  /("?(?:preinstall|postinstall|install|prepare|SessionStart|PreToolUse|PostToolUse|onStart|onLoad|beforeAll|setup)"?\s*[:=])/i;

const COMMANDISH = /(curl|wget|bash|sh\s+-c|zsh|node\s+-e|python[0-9.]*\s+-c|powershell|iex|Invoke-Expression|eval|npx\s+\S)/i;

export const autorunHooks: Rule = {
  id: "SS016",
  title: "Auto-running hook executes a command",
  severity: "high",
  description: "Flags install scripts and agent lifecycle hooks (SessionStart, PreToolUse…) that run shell or network commands automatically.",
  scan(component) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (!HOOK_KEY.test(line)) continue;
        // Look at the hook line and the two lines after it (value may be on the next line).
        const window = [line, lines[i + 1] ?? "", lines[i + 2] ?? ""].join(" ");
        if (!COMMANDISH.test(window)) continue;
        const key = `${file.relativePath}:${i + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(
          finding(autorunHooks, {
            file: file.relativePath,
            line: i + 1,
            evidence: defang(line),
            message: "A lifecycle hook runs a command automatically when the component is installed or loaded, before it can be vetted.",
            remediation: "Remove auto-running hooks, or make the action explicit and user-initiated. Never fetch-and-run in an install/session hook.",
          }),
        );
      }
    }
    return findings;
  },
};
