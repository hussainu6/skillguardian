import type { Capability, ComponentResult, ComposedRisk, Finding } from "./types.js";

/**
 * Which capability each rule implies. A finding says "this pattern is here"; the
 * capability says "this is the authority it grants the agent", which is what lets
 * us reason about dangerous *combinations* rather than isolated strings.
 */
export const RULE_CAPABILITIES: Record<string, Capability[]> = {
  SS001: ["evasion"],
  SS002: ["secrets"],
  SS003: ["exec"],
  SS004: ["evasion"],
  SS005: ["network"],
  SS006: ["control"],
  SS007: ["control"],
  SS008: ["control"],
  SS009: ["filesystem"],
  SS010: ["secrets", "network"],
  SS011: ["secrets"],
  SS012: ["exec"],
  SS013: ["filesystem"],
  SS014: ["network"],
  SS015: ["secrets"],
  SS016: ["exec", "persistence"],
  SS017: ["network", "exec"],
  SS018: ["secrets"],
  SS019: ["secrets"],
  SS020: ["persistence", "filesystem"],
  SS021: ["exec", "network"],
  SS022: ["evasion"],
};

const CAPABILITY_ORDER: Capability[] = [
  "secrets",
  "filesystem",
  "network",
  "exec",
  "persistence",
  "control",
  "evasion",
];

function sortCaps(caps: Iterable<Capability>): Capability[] {
  return [...new Set(caps)].sort((a, b) => CAPABILITY_ORDER.indexOf(a) - CAPABILITY_ORDER.indexOf(b));
}

/** Capabilities implied by a set of findings. */
export function capabilitiesFor(findings: Finding[]): Capability[] {
  const caps: Capability[] = [];
  for (const f of findings) for (const c of RULE_CAPABILITIES[f.ruleId] ?? []) caps.push(c);
  return sortCaps(caps);
}

/** First finding in a component whose rule contributes `cap`, for a location hint. */
function legFor(result: ComponentResult, cap: Capability): ComposedRisk["legs"][number] | undefined {
  const f = result.findings.find((x) => (RULE_CAPABILITIES[x.ruleId] ?? []).includes(cap));
  if (!f) return undefined;
  return { capability: cap, component: result.component.name, ruleId: f.ruleId, file: f.file, line: f.line };
}

/** The cross-component chains we warn about: a "source" of data plus a way out. */
const CHAINS: { id: string; title: string; source: Capability; message: string }[] = [
  {
    id: "SX01",
    title: "Composed exfiltration risk (secrets + network across skills)",
    source: "secrets",
    message:
      "One skill reads secrets and a different skill can reach the network. Installed together they form an exfiltration chain that neither looks like on its own.",
  },
  {
    id: "SX02",
    title: "Composed data-staging risk (filesystem + network across skills)",
    source: "filesystem",
    message:
      "One skill reads or writes broad filesystem paths and a different skill can reach the network — a stage-then-upload chain spread across skills.",
  },
];

/**
 * Detect risks that only appear when capabilities combine across *different*
 * components. A single component that does both halves is already covered by
 * SS010 at the finding level, so here we require two distinct components.
 */
export function detectComposedRisks(results: ComponentResult[]): ComposedRisk[] {
  if (results.length < 2) return [];
  const risks: ComposedRisk[] = [];
  const netComponents = results.filter((r) => r.capabilities.includes("network"));
  if (netComponents.length === 0) return [];

  for (const chain of CHAINS) {
    const sourceComponents = results.filter((r) => r.capabilities.includes(chain.source));
    // Need a source and a network leg in two *different* components.
    const pair = findDistinctPair(sourceComponents, netComponents);
    if (!pair) continue;
    const sourceLeg = legFor(pair.source, chain.source);
    const netLeg = legFor(pair.net, "network");
    if (!sourceLeg || !netLeg) continue;
    risks.push({
      id: chain.id,
      title: chain.title,
      severity: "high",
      message: chain.message,
      remediation:
        "Don't grant one agent both capabilities at once. Scope network egress and filesystem access per tool, and review these skills together, not separately.",
      legs: [sourceLeg, netLeg],
    });
  }
  return risks;
}

function findDistinctPair(
  sources: ComponentResult[],
  nets: ComponentResult[],
): { source: ComponentResult; net: ComponentResult } | undefined {
  for (const s of sources) {
    const n = nets.find((x) => x.component.root !== s.component.root);
    if (n) return { source: s, net: n };
  }
  return undefined;
}

/** Union of capabilities across all components, in display order. */
export function unionCapabilities(results: ComponentResult[]): Capability[] {
  return sortCaps(results.flatMap((r) => r.capabilities));
}

/** Short emoji + label for a capability, for reports. */
export const CAPABILITY_LABEL: Record<Capability, string> = {
  secrets: "🔑 secrets",
  filesystem: "📁 filesystem",
  network: "🌐 network",
  exec: "⚙️ exec",
  persistence: "📌 persistence",
  control: "🎛️ control",
  evasion: "🫥 evasion",
};
