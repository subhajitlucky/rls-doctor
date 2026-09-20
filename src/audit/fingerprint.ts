import { createHash } from "node:crypto";
import type { AuditReport, Finding, ProbeFinding, SchemaFinding } from "./types.js";

export type AuditableFinding = Finding | SchemaFinding | ProbeFinding;

export interface BaselineComparison {
  new: string[];
  unchanged: string[];
  resolved: string[];
}

export function findingFingerprint(finding: AuditableFinding): string {
  const table = "table" in finding && finding.table ? finding.table : "";
  return createHash("sha256")
    .update([finding.id, finding.schema ?? "", table, finding.detail].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

export function collectReportFindings(report: AuditReport): AuditableFinding[] {
  return [...report.schemaFindings, ...report.tables.flatMap((table) => table.findings)];
}

export function reportFindingFingerprints(report: AuditReport): string[] {
  return [...new Set(collectReportFindings(report).map(findingFingerprint))].sort();
}

export function compareWithBaseline(
  baselineFingerprints: readonly string[],
  report: AuditReport
): BaselineComparison {
  const baseline = new Set(baselineFingerprints);
  const current = new Set(reportFindingFingerprints(report));

  return {
    new: [...current].filter((fingerprint) => !baseline.has(fingerprint)).sort(),
    unchanged: [...current].filter((fingerprint) => baseline.has(fingerprint)).sort(),
    resolved: [...baseline].filter((fingerprint) => !current.has(fingerprint)).sort()
  };
}
