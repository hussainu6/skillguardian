import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, loadConfig } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");

function ids(report) {
  return new Set(report.components.flatMap((c) => c.findings).map((f) => f.ruleId));
}

test("inline suppression removes the named rule but keeps others", () => {
  const report = scan(join(fixtures, "suppressed-skill"));
  const found = ids(report);
  assert.ok(!found.has("SS003"), "SS003 should be suppressed by inline comment");
  assert.ok(!found.has("SS011"), "SS011 should be suppressed by inline comment");
});

test("--no-suppress (suppressions:false) restores suppressed findings", () => {
  const report = scan(join(fixtures, "suppressed-skill"), { suppressions: false });
  const found = ids(report);
  assert.ok(found.has("SS003"), "SS003 should reappear when suppressions are off");
});

test("minSeverity drops findings below the threshold", () => {
  const all = scan(join(fixtures, "malicious-skill"));
  const highOnly = scan(join(fixtures, "malicious-skill"), { minSeverity: "high" });
  const lows = all.components.flatMap((c) => c.findings).filter((f) => f.severity === "low");
  assert.ok(lows.length > 0, "fixture should have low findings to filter");
  const remainingLows = highOnly.components
    .flatMap((c) => c.findings)
    .filter((f) => f.severity === "low" || f.severity === "info");
  assert.equal(remainingLows.length, 0, "no low/info findings should remain at minSeverity=high");
});

test("skip via options removes a rule (config.disable path)", () => {
  const report = scan(join(fixtures, "malicious-skill"), { skip: ["SS006"] });
  assert.ok(!ids(report).has("SS006"));
});

test("loadConfig returns empty object when no config file is present", () => {
  const cfg = loadConfig(join(fixtures, "clean-skill"));
  assert.deepEqual(cfg, {});
});
