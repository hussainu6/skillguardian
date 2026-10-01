import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, badgeUrl, badgeMarkdown } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");

test("badge url and markdown reflect the grade and color", () => {
  assert.equal(badgeUrl("A"), "https://img.shields.io/badge/skillguardian-A-brightgreen");
  assert.equal(badgeUrl("F"), "https://img.shields.io/badge/skillguardian-F-red");
  const md = badgeMarkdown("A");
  assert.match(md, /^\[!\[skillguardian: A\]/);
  assert.match(md, /github\.com\/hussainu6\/skillguardian\)$/);
});

test("ignore globs skip matching files during discovery", () => {
  const full = scan(join(fixtures, "malicious-skill"));
  assert.ok(full.components.some((c) => c.findings.length > 0), "baseline should have findings");

  const ignored = scan(join(fixtures, "malicious-skill"), { ignore: ["**/SKILL.md"] });
  const total = ignored.components.reduce((n, c) => n + c.findings.length, 0);
  assert.equal(total, 0, "ignoring the only file should yield zero findings");
});

test("ignore with a non-matching glob changes nothing", () => {
  const a = scan(join(fixtures, "malicious-skill"));
  const b = scan(join(fixtures, "malicious-skill"), { ignore: ["*.py"] });
  const countA = a.components.reduce((n, c) => n + c.findings.length, 0);
  const countB = b.components.reduce((n, c) => n + c.findings.length, 0);
  assert.equal(countA, countB);
});
