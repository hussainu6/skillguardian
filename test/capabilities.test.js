import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scan, capabilitiesFor, RULE_CAPABILITIES } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures");

test("each component reports the capabilities implied by its findings", () => {
  const report = scan(join(fixtures, "malicious-skill"));
  const comp = report.components.find((c) => c.findings.length > 0);
  assert.ok(comp, "expected a component with findings");
  // malicious-skill reads secrets, has network egress, and executes code.
  for (const cap of ["secrets", "network", "exec"]) {
    assert.ok(comp.capabilities.includes(cap), `expected capability ${cap}`);
  }
});

test("clean skill has no capabilities and no composed risks", () => {
  const report = scan(join(fixtures, "clean-skill"));
  assert.deepEqual(report.composedRisks, []);
  assert.ok(report.components.every((c) => c.capabilities.length === 0));
});

test("composed risk fires when secrets and network live in different components", () => {
  const report = scan(join(fixtures, "composed-demo"));
  assert.ok(report.composedRisks.length >= 1, "expected at least one composed risk");
  const exfil = report.composedRisks.find((r) => r.id === "SX01");
  assert.ok(exfil, "expected SX01 composed exfiltration risk");
  const caps = exfil.legs.map((l) => l.capability);
  assert.ok(caps.includes("secrets") && caps.includes("network"));
  // The two legs must be in different components.
  assert.notEqual(exfil.legs[0].component, exfil.legs[1].component);
});

test("a single component doing both halves is NOT a composed risk (that's SS010)", () => {
  // malicious-skill is one component with both secrets + network: SS010 covers it,
  // so there is no cross-component composed risk.
  const report = scan(join(fixtures, "malicious-skill"));
  assert.deepEqual(report.composedRisks, []);
});

test("capabilitiesFor maps rule ids and every rule has a capability", () => {
  assert.deepEqual(capabilitiesFor([{ ruleId: "SS002" }, { ruleId: "SS005" }]).sort(), ["network", "secrets"]);
  // Every SSNNN rule id should have a capability mapping.
  for (let n = 1; n <= 22; n++) {
    const id = "SS" + String(n).padStart(3, "0");
    assert.ok(Array.isArray(RULE_CAPABILITIES[id]) && RULE_CAPABILITIES[id].length > 0, `${id} missing capability`);
  }
});
