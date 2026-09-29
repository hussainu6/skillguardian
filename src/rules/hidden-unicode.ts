import type { Rule } from "../types.js";
import { finding } from "./util.js";

/**
 * SS001 — Hidden / non-printing Unicode.
 *
 * Skills are natural-language instructions the agent obeys. Invisible characters
 * let an author hide a second set of instructions that a human reviewer reading
 * the file will never see: zero-width joiners, bidirectional overrides that
 * reorder text, and the Unicode "tag" block that can smuggle ASCII invisibly.
 */
const SUSPECT = [
  { re: /[​-‏⁠-⁤﻿]/g, kind: "zero-width character" },
  { re: /[‪-‮⁦-⁩]/g, kind: "bidirectional override" },
  { re: /[\u{e0000}-\u{e007f}]/gu, kind: "Unicode tag character" },
  { re: /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, kind: "control character" },
];

export const hiddenUnicode: Rule = {
  id: "SS001",
  title: "Hidden or non-printing Unicode",
  severity: "high",
  description: "Detects invisible characters that can conceal instructions from human reviewers.",
  scan(component) {
    const findings = [];
    for (const file of component.files) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        for (const { re, kind } of SUSPECT) {
          re.lastIndex = 0;
          if (re.test(line)) {
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
