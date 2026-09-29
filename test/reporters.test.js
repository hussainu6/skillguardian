import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, renderJson, renderSarif, renderMarkdown, renderTerminal } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const malicious = join(here, "fixtures", "malicious-skill");

test("JSON report parses and carries findings", () => {
  const report = scan(malicious);
  const parsed = JSON.parse(renderJson(report));
  assert.equal(parsed.version, report.version);
  assert.ok(parsed.components.length >= 1);
});

test("SARIF is valid 2.1.0 with rules and results", () => {
  const sarif = JSON.parse(renderSarif(scan(malicious)));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "skillguardian");
  assert.ok(run.tool.driver.rules.length >= 10);
  assert.ok(run.results.length >= 1);
  for (const r of run.results) {
    assert.ok(r.ruleId);
    assert.ok(["error", "warning", "note"].includes(r.level));
    assert.ok(r.locations[0].physicalLocation.artifactLocation.uri);
  }
});

test("markdown report includes a grade and table", () => {
  const md = renderMarkdown(scan(malicious));
  assert.match(md, /skillguardian report/);
  assert.match(md, /Overall grade/);
  assert.match(md, /\| Grade \|/);
});

test("terminal report renders without throwing", () => {
  const txt = renderTerminal(scan(malicious));
  assert.ok(txt.includes("skillguardian"));
  assert.ok(txt.includes("Overall"));
});

test("evidence is defanged: no raw control characters leak", () => {
  const report = scan(malicious);
  for (const c of report.components) {
    for (const f of c.findings) {
      if (f.evidence) assert.doesNotMatch(f.evidence, /[\u0000-\u0008\u000e-\u001f]/);
    }
  }
});
