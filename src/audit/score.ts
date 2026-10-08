import type {
  AuditScore,
  SchemaFinding,
  ScoreBand,
  Severity,
  TableAudit
} from "./types.js";

export const SEVERITY_PENALTIES: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 4,
  high: 10,
  critical: 25
};

export const INCOMPLETE_COVERAGE_PENALTY = 10;
export const GREEN_MINIMUM = 80;
export const YELLOW_MINIMUM = 50;

export function bandForScore(value: number): ScoreBand {
  if (value >= GREEN_MINIMUM) return "green";
  if (value >= YELLOW_MINIMUM) return "yellow";
  return "red";
}

/**
 * Deterministic RLS Score: 100 minus weighted findings. Catalog analysis
 * covers every requested schema, so the coverage penalty is reserved at 0 for
 * shape parity with Codebase Doctor reports.
 */
export function scoreAudit(
  schemaFindings: readonly SchemaFinding[],
  tables: readonly TableAudit[]
): AuditScore {
  const findingPenalty = [...schemaFindings, ...tables.flatMap((table) => table.findings)]
    .reduce((total, finding) => total + SEVERITY_PENALTIES[finding.severity], 0);
  const coveragePenalty = 0;
  const value = Math.max(0, Math.min(100, 100 - findingPenalty - coveragePenalty));
  return { value, band: bandForScore(value), findingPenalty, coveragePenalty };
}
