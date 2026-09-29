import type { Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS001 — Hidden / non-printing Unicode.
 *
 * Skills are natural-language instructions the agent obeys. Invisible characters
 * let an author hide a second set of instructions a human reviewer will never
 * see. We flag bidirectional overrides, the Unicode "tag" block, and control
 * characters outright. Zero-width characters are only flagged when they sit
 * *inside ASCII text* — the smuggling case — because zero-width joiners are used
 * legitimately in emoji sequences, and a byte-order mark is harmless on its own.
 */
const ZERO_WIDTH_IN_TEXT =
  /[A-Za-z0-9][​-‏⁠-⁤﻿]|[​-‏⁠-⁤﻿][A-Za-z0-9]/;

const CATEGORIES: { test: (line: string) => boolean; kind: string }[] = [
  { test: (l) => ZERO_WIDTH_IN_TEXT.test(l), kind: "zero-width character in text" },
  { test: (l) => /[‪-‮⁦-⁩]/.test(l), kind: "bidirectional override" },
  { test: (l) => /[\u{e0000}-\u{e007f}]/u.test(l), kind: "Unicode tag character" },
  { test: (l) => /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(l), kind: "control character" },
];

export const hiddenUnicode: Rule = {
  id: "SS001",
  title: "Hidden or non-printing Unicode",
  severity: "high",
  description: "Detects invisible characters that can conceal instructions: bidi overrides, tag chars, controls, and zero-width chars embedded in text.",
  scan(component) {
    const findings = [];
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        for (const { test, kind } of CATEGORIES) {
          if (test(line)) {
            findings.push(
              finding(hiddenUnicode, {
                file: file.relativePath,
                line: i + 1,
                evidence: `contains ${kind}(s)`,
                message: `Line contains a ${kind}, which can hide instructions from anyone reading the file.`,
                remediation: "Remove non-printing characters. If the text is legitimately non-Latin, keep only visible glyphs.",
              }),
            );
            break; // one finding per line is enough
          }
        }
      }
    }
    return findings;
  },
};
