import type { Rule } from "../types.js";
import { finding, findingsFromMatches, matchAll } from "./util.js";

/**
 * SS004 — Obfuscated payloads.
 *
 * Decode-then-run patterns (base64/hex → eval/exec) and large opaque blobs are
 * how a payload evades a text review: the reviewer sees noise, the agent decodes
 * and executes it. We flag decode+exec pairings and long encoded literals.
 */
const DECODE_EXEC =
  /(atob|base64\s*(-d|--decode)|Buffer\.from\([^)]*base64|fromCharCode|b64decode|FromBase64String)/gi;

const LONG_BASE64 = /['"`]([A-Za-z0-9+/]{120,}={0,2})['"`]/g;
const LONG_HEX = /(?:\\x[0-9a-f]{2}){24,}/gi;

export const obfuscation: Rule = {
  id: "SS004",
  title: "Obfuscated or encoded payload",
  severity: "high",
  description: "Detects base64/hex decode-and-run patterns and long opaque encoded literals.",
  scan(component) {
    const decode = findingsFromMatches(
      obfuscation,
      matchAll(component, DECODE_EXEC),
      "Decodes encoded data at runtime, a common way to hide a payload from review.",
      "Ship code in readable form. If encoding is unavoidable, document exactly what the blob is.",
    );

    const blobs = [];
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        LONG_BASE64.lastIndex = 0;
        LONG_HEX.lastIndex = 0;
        if (LONG_BASE64.test(line) || LONG_HEX.test(line)) {
          blobs.push(
            finding(obfuscation, {
              file: file.relativePath,
              line: i + 1,
              evidence: "long encoded literal",
              message: "Contains a long encoded literal whose contents cannot be reviewed as text.",
              remediation: "Replace with readable data, or explain the literal and pin its expected hash.",
            }),
          );
        }
      }
    }
    return [...decode, ...blobs];
  },
};
