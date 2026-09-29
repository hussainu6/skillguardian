import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, RULES } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");

function findingsFor(root) {
  const report = scan(root);
  return report.components.flatMap((c) => c.findings);
}

function ruleIds(findings) {
  return new Set(findings.map((f) => f.ruleId));
}

test("clean skill produces no findings and grades A", () => {
  const report = scan(join(fixtures, "clean-skill"));
  const all = report.components.flatMap((c) => c.findings);
  assert.equal(all.length, 0, "expected zero findings for the clean skill");
  assert.equal(report.grade, "A");
  assert.equal(report.score, 100);
});

test("malicious skill trips the core rules", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "malicious-skill")));
  for (const expected of ["SS003", "SS004", "SS005", "SS006", "SS008", "SS009", "SS010"]) {
    assert.ok(ids.has(expected), `expected ${expected} to fire`);
  }
});

test("malicious skill grades F", () => {
  const report = scan(join(fixtures, "malicious-skill"));
  assert.equal(report.grade, "F");
  assert.ok(report.score < 35, `score ${report.score} should be < 35`);
});

test("mcp config flags disabled guardrails and egress", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "mcp-config")));
  assert.ok(ids.has("SS007"), "expected SS007 (disabled guardrails)");
});

test("sneaky skill trips clipboard, typosquat, and overbroad-access rules", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "sneaky-skill")));
  assert.ok(ids.has("SS011"), "expected SS011 (clipboard)");
  assert.ok(ids.has("SS012"), "expected SS012 (typosquatting)");
  assert.ok(ids.has("SS013"), "expected SS013 (overbroad access)");
});

test("risky plugin trips insecure-endpoint, hardcoded-secret, and autorun-hook rules", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "risky-plugin")));
  assert.ok(ids.has("SS014"), "expected SS014 (insecure http endpoint)");
  assert.ok(ids.has("SS015"), "expected SS015 (hardcoded secret)");
  assert.ok(ids.has("SS016"), "expected SS016 (autorun hook)");
});

test("hardcoded-secret skips obvious placeholders", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "placeholder-skill")));
  assert.ok(!ids.has("SS015"), "placeholder keys must not be flagged as SS015");
});

test("hidden-unicode flags zero-width-in-text and bidi overrides (SS001)", () => {
  const ids = ruleIds(findingsFor(join(fixtures, "hidden-skill")));
  assert.ok(ids.has("SS001"), "expected SS001 to fire on genuine hidden Unicode");
});

test("clean skill has no zero-width false positive from plain text", () => {
  // The clean skill is plain ASCII; SS001 must not fire.
  const ids = ruleIds(findingsFor(join(fixtures, "clean-skill")));
  assert.ok(!ids.has("SS001"));
});

test("--only narrows to a single rule", () => {
  const report = scan(join(fixtures, "malicious-skill"), { only: ["SS006"] });
  const ids = ruleIds(report.components.flatMap((c) => c.findings));
  assert.deepEqual([...ids], ["SS006"]);
});

test("--skip removes a rule", () => {
  const report = scan(join(fixtures, "malicious-skill"), { skip: ["SS006"] });
  const ids = ruleIds(report.components.flatMap((c) => c.findings));
  assert.ok(!ids.has("SS006"));
});

test("every rule has a unique id and required metadata", () => {
  const seen = new Set();
  for (const r of RULES) {
    assert.match(r.id, /^SS\d{3}$/, `bad id ${r.id}`);
    assert.ok(!seen.has(r.id), `duplicate id ${r.id}`);
    seen.add(r.id);
    assert.ok(r.title && r.description, `${r.id} missing title/description`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(r.severity));
  }
});
