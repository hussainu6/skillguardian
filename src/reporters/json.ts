import type { ScanReport } from "../types.js";

/** Stable, machine-readable JSON. Field names are part of the public contract. */
export function renderJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
