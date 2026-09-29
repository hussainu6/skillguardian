import type { Rule } from "../types.js";
import { findingsFromMatches, matchAll } from "./util.js";

/**
 * SS003 — Remote-to-shell execution.
 *
 * The classic supply-chain move: fetch a script from the network and pipe it
 * straight into a shell, so the actual payload is never in the repository and
 * can change after review. Also flags dynamic eval of fetched content.
 */
const PIPE_TO_SHELL =
  /(curl|wget|iwr|Invoke-WebRequest|fetch)\b[^\n|]*\|\s*(sh|bash|zsh|python[0-9.]*|node|pwsh|powershell|iex|Invoke-Expression)\b/gi;

const EVAL_OF_FETCH =
  /\b(eval|exec|Function|child_process|subprocess|os\.system|Invoke-Expression|iex)\b/gi;

export const shellExecution: Rule = {
  id: "SS003",
  title: "Executes remote or dynamic code",
  severity: "critical",
  description: "Detects `curl … | bash` style install lines and dynamic eval/exec of external input.",
  scan(component) {
    const pipe = findingsFromMatches(
      shellExecution,
      matchAll(component, PIPE_TO_SHELL),
      "Downloads a script and pipes it directly into a shell; the real payload is off-repo and can change silently.",
      "Never pipe network content to a shell. Vendor the script, review it, and run it explicitly.",
    );
    const evalHits = findingsFromMatches(
      shellExecution,
      matchAll(component, EVAL_OF_FETCH),
      "Uses dynamic code execution, which can run attacker-controlled input.",
      "Avoid eval/exec on any value that could come from outside the skill.",
    );
    return [...pipe, ...evalHits];
  },
};
