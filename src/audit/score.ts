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
 * Deterministic RLS Score: 100 minus weighted findings, minus a fixed penalty
 * when offline analysis could not evaluate every statement. Live catalog
 * audits always complete their selected scope, so the penalty is 0 there.
 */
export function scoreAudit(
  schemaFindings: readonly SchemaFinding[],
  tables: readonly TableAudit[],
  coverageComplete = true
): AuditScore {
  const findingPenalty = [...schemaFindings, ...tables.flatMap((table) => table.findings)]
    .reduce((total, finding) => total + SEVERITY_PENALTIES[finding.severity], 0);
  const coveragePenalty = coverageComplete ? 0 : INCOMPLETE_COVERAGE_PENALTY;
  const value = Math.max(0, Math.min(100, 100 - findingPenalty - coveragePenalty));
  return { value, band: bandForScore(value), findingPenalty, coveragePenalty };
}
