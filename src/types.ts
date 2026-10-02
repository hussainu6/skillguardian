/**
 * Core types for skillguardian.
 *
 * A "component" is one thing we scan: an agent skill, a plugin manifest, or an
 * MCP server config. A "rule" inspects a component's text and emits findings.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Weight each severity contributes to the risk score (higher = worse). */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

/** The kind of artifact a component represents. */
export type ComponentKind = "skill" | "plugin" | "mcp" | "unknown";

/** A single file pulled in for scanning. */
export interface ScannedFile {
  /** Absolute path on disk. */
  path: string;
  /** Path relative to the scan root, used in reports. */
  relativePath: string;
  /** Raw UTF-8 contents. */
  content: string;
}

/** A logical component (a skill dir, a plugin, an MCP entry) with its files. */
export interface Component {
  kind: ComponentKind;
  /** Human-friendly name (skill name, server key, dir name). */
  name: string;
  /** The component's root path relative to the scan root. */
  root: string;
  files: ScannedFile[];
  /** Parsed metadata when available (frontmatter, manifest fields). */
  metadata?: Record<string, unknown>;
}

/** One problem found in a component. */
export interface Finding {
  /** Stable machine id, e.g. "SS001". */
  ruleId: string;
  /** Short human title. */
  title: string;
  severity: Severity;
  /** File the finding is anchored to (relative path). */
  file: string;
  /** 1-indexed line, when known. */
  line?: number;
  /** The offending snippet, trimmed and defanged for display. */
  evidence?: string;
  /** Why this matters, in one sentence. */
  message: string;
  /** What the author/consumer should do. */
  remediation: string;
}

/** A rule inspects a component and returns zero or more findings. */
export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** One-line description shown in `skillguardian rules`. */
  description: string;
  scan(component: Component): Finding[];
}

/**
 * The authority a component exercises. A finding tells you a pattern is present;
 * a capability tells you what power installing the component grants the agent.
 */
export type Capability =
  | "secrets"
  | "filesystem"
  | "network"
  | "exec"
  | "evasion"
  | "control"
  | "persistence";

/** Result of scanning one component. */
export interface ComponentResult {
  component: Pick<Component, "kind" | "name" | "root">;
  findings: Finding[];
  /** Capabilities this component exercises, derived from its findings. */
  capabilities: Capability[];
  score: number;
  grade: Grade;
}

/**
 * A risk that emerges from combining capabilities across *separate* components —
 * e.g. one skill reads secrets and a different skill can reach the network, which
 * together form an exfiltration chain neither looks like alone.
 */
export interface ComposedRisk {
  id: string;
  title: string;
  severity: Severity;
  message: string;
  remediation: string;
  /** The capability legs of the chain and where each was observed. */
  legs: { capability: Capability; component: string; ruleId: string; file: string; line?: number }[];
}

/** Aggregate result for a whole scan. */
export interface ScanReport {
  version: string;
  scannedAt: string;
  root: string;
  components: ComponentResult[];
  totals: Record<Severity, number>;
  score: number;
  grade: Grade;
  /** Capabilities present anywhere in the scan. */
  capabilities: Capability[];
  /** Cross-component capability-composition risks. */
  composedRisks: ComposedRisk[];
}

export type Grade = "A" | "B" | "C" | "D" | "F";
