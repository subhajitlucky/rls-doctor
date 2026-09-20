import { readFile } from "node:fs/promises";
import { collectReportFindings, findingFingerprint } from "./fingerprint.js";
import type { AuditReport } from "./types.js";

export interface AuditBaseline {
  generatedAt: string | null;
  fingerprints: string[];
}

export async function loadBaseline(path: string): Promise<AuditBaseline> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read baseline "${path}": ${message}`);
  }

  if (!isAuditReport(parsed)) {
    throw new Error(`Baseline "${path}" is not an rls-doctor JSON report (schemaVersion "1.0").`);
  }

  const fingerprints = [
    ...new Set(collectReportFindings(parsed).map(findingFingerprint))
  ].sort();

  return {
    generatedAt: typeof parsed.generatedAt === "string" ? parsed.generatedAt : null,
    fingerprints
  };
}

export function isAuditReport(value: unknown): value is AuditReport {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  const candidate = value as Partial<AuditReport>;
  return (
    candidate.schemaVersion === "1.0" &&
    Array.isArray(candidate.schemaFindings) &&
    Array.isArray(candidate.tables) &&
    candidate.tables.every((table) => Array.isArray(table?.findings))
  );
}
