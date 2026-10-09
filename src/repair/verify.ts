import { createHash } from "node:crypto";
import pg from "pg";
import { analyzeCatalog } from "../audit/analyzer.js";
import { parseSchemaSql } from "../audit/schema-file.js";
import type { CatalogSnapshot, Severity, TableAudit } from "../audit/types.js";
import { loadCatalog } from "../db/catalog.js";
import { buildProofClaims, type ProofClaim } from "../proof/runner.js";
import { canonicalJson } from "../receipts/receipt.js";
import { dockerAvailable, withDisposablePostgres } from "../shadow/postgres.js";
import type { RepairPlan } from "./repair.js";

export type RepairVerificationMode = "static+live" | "static";

export interface RepairVerification {
  status: "verified" | "failed";
  mode: RepairVerificationMode;
  beforeWitnesses: string[];
  afterWitnesses: string[];
  resolved: string[];
  newFindings: string[];
  advisoryFindings: string[];
  reasons: string[];
  limitations: string[];
}

interface FindingKey {
  key: string;
  severity: Severity;
}

function claimKey(claim: ProofClaim): string {
  return `${claim.schema}.${claim.table} ${claim.command} ${claim.role}`;
}

function tableClaims(snapshot: CatalogSnapshot, schema: string, table: string, roles: readonly string[]): ProofClaim[] {
  const tables = snapshot.tables.filter((entry) => entry.schema === schema && entry.name === table);
  return buildProofClaims(tables, snapshot.policies, roles);
}

function findingKeys(tables: readonly TableAudit[]): FindingKey[] {
  return tables
    .flatMap((table) => table.findings.map((finding) => ({
      key: `${finding.id} ${table.schema}.${table.table}`,
      severity: finding.severity,
    })))
    .sort((left, right) => left.key.localeCompare(right.key));
}

export interface StaticAnalysis {
  snapshot: CatalogSnapshot;
  claims: ProofClaim[];
  findings: FindingKey[];
}

export function analyzeSql(sql: string, schema: string, table: string, roles: readonly string[]): StaticAnalysis {
  const parsed = parseSchemaSql(sql);
  const report = analyzeCatalog(parsed.snapshot, {
    schemas: parsed.schemas,
    limitations: parsed.limitations,
  });
  return {
    snapshot: parsed.snapshot,
    claims: tableClaims(parsed.snapshot, schema, table, roles),
    findings: findingKeys(report.tables),
  };
}

function compare(before: StaticAnalysis, after: StaticAnalysis): Omit<RepairVerification, "status" | "mode" | "limitations"> {
  const beforeWitnesses = before.claims.filter((claim) => claim.status === "witness").map(claimKey).sort();
  const afterWitnesses = after.claims.filter((claim) => claim.status === "witness").map(claimKey).sort();
  const resolved = beforeWitnesses.filter((key) => !afterWitnesses.includes(key));
  const beforeKeys = new Set(before.findings.map((finding) => finding.key));
  const introduced = after.findings.filter((finding) => !beforeKeys.has(finding.key));
  const blocking = introduced.filter((finding) => finding.severity !== "info" && finding.severity !== "low");
  const advisory = introduced.filter((finding) => finding.severity === "info" || finding.severity === "low");
  const reasons: string[] = [];
  if (resolved.length === 0) {
    reasons.push("the patch did not resolve any witness");
  }
  if (afterWitnesses.length > 0) {
    reasons.push(`${afterWitnesses.length} witness(es) remain after the patch`);
  }
  if (blocking.length > 0) {
    reasons.push(`${blocking.length} new medium+ finding(s) were introduced by the patch`);
  }
  return {
    beforeWitnesses,
    afterWitnesses,
    resolved,
    newFindings: blocking.map((finding) => finding.key),
    advisoryFindings: advisory.map((finding) => `${finding.severity} ${finding.key}`),
    reasons,
  };
}

/**
 * Static verification: re-parse the original SQL with the patch appended and
 * re-prove the target table. Always available, no database required.
 */
export function verifyRepairStatic(
  originalSql: string,
  plan: RepairPlan,
  roles: readonly string[],
): RepairVerification {
  const before = analyzeSql(originalSql, plan.schema, plan.table, roles);
  const after = analyzeSql(`${originalSql}\n${plan.statements.join("\n")}\n`, plan.schema, plan.table, roles);
  const comparison = compare(before, after);
  return {
    status: comparison.reasons.length === 0 ? "verified" : "failed",
    mode: "static",
    ...comparison,
    limitations: [],
  };
}

/**
 * Live verification: apply the original SQL and the patch in a disposable
 * PostgreSQL container and compare catalog-derived proofs. Stronger than the
 * static pass; skipped (with a limitation) when Docker is unavailable.
 */
export async function verifyRepairLive(
  originalSql: string,
  plan: RepairPlan,
  roles: readonly string[],
): Promise<RepairVerification | undefined> {
  if (!(await dockerAvailable())) return undefined;

  return withDisposablePostgres(async (connectionString) => {
    const admin = new pg.Client({ connectionString });
    await admin.connect();
    try {
      await admin.query(originalSql);
      const schemas = parseSchemaSql(originalSql).schemas;
      const beforeSnapshot = await loadCatalog({ connectionString, schemas });
      const beforeReport = analyzeCatalog(beforeSnapshot, { schemas });
      const beforeClaims = tableClaims(beforeSnapshot, plan.schema, plan.table, roles);

      await admin.query(plan.statements.join("\n"));
      const afterSnapshot = await loadCatalog({ connectionString, schemas });
      const afterReport = analyzeCatalog(afterSnapshot, { schemas });
      const afterClaims = tableClaims(afterSnapshot, plan.schema, plan.table, roles);

      const before: StaticAnalysis = {
        snapshot: beforeSnapshot,
        claims: beforeClaims,
        findings: findingKeys(beforeReport.tables),
      };
      const after: StaticAnalysis = {
        snapshot: afterSnapshot,
        claims: afterClaims,
        findings: findingKeys(afterReport.tables),
      };
      const comparison = compare(before, after);
      return {
        status: comparison.reasons.length === 0 ? "verified" : "failed",
        mode: "static+live",
        ...comparison,
        limitations: [],
      };
    } finally {
      await admin.end().catch(() => undefined);
    }
  });
}

export interface RepairReceipt {
  repairVersion: "1";
  tool: { name: "rls-doctor"; version: string };
  generatedAt: string;
  subject: { schemaFiles: string[]; table: string; roles: string[] };
  targets: string[];
  patch: { sql: string; sha256: string };
  verification: RepairVerification;
  digest: { algorithm: "sha256"; value: string };
}

export function buildRepairReceipt(
  plan: RepairPlan,
  patch: string,
  verification: RepairVerification,
  subject: RepairReceipt["subject"],
  toolVersion: string,
  generatedAt: Date = new Date(),
): RepairReceipt {
  const body = {
    repairVersion: "1" as const,
    tool: { name: "rls-doctor" as const, version: toolVersion },
    generatedAt: generatedAt.toISOString(),
    subject,
    targets: [...plan.targets],
    patch: {
      sql: patch,
      sha256: createHash("sha256").update(patch, "utf8").digest("hex"),
    },
    verification,
  };
  return {
    ...body,
    digest: {
      algorithm: "sha256",
      value: createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"),
    },
  };
}

export function renderRepairText(receipt: RepairReceipt): string {
  const lines = [
    "RLS Doctor Verified Repair",
    "==========================",
    "",
    `Table: ${receipt.subject.table} · roles: ${receipt.subject.roles.join(", ")}`,
    `Patch: ${receipt.patch.sha256.slice(0, 16)}… (${receipt.patch.sql.split("\n").length} lines)`,
    `Verification: ${receipt.verification.status} (${receipt.verification.mode})`,
    "",
    `Witnesses before: ${receipt.verification.beforeWitnesses.length}`,
    `Witnesses after:  ${receipt.verification.afterWitnesses.length}`,
    `Resolved:         ${receipt.verification.resolved.length}`,
  ];
  for (const key of receipt.verification.resolved) lines.push(`  + ${key}`);
  if (receipt.verification.newFindings.length > 0) {
    lines.push(`New findings introduced: ${receipt.verification.newFindings.length}`);
    for (const key of receipt.verification.newFindings) lines.push(`  ! ${key}`);
  }
  if (receipt.verification.advisoryFindings.length > 0) {
    lines.push(`Advisory (non-blocking): ${receipt.verification.advisoryFindings.length}`);
    for (const key of receipt.verification.advisoryFindings) lines.push(`  ~ ${key}`);
  }
  for (const reason of receipt.verification.reasons) lines.push(`Reason: ${reason}`);
  for (const limitation of receipt.verification.limitations) lines.push(`Limitation: ${limitation}`);
  lines.push(
    "",
    receipt.verification.status === "verified"
      ? "The patch is verified: apply it, then rerun `rls-doctor check` and `prove` to confirm the same scope."
      : "The patch is NOT verified and was not written. Nothing was applied.",
    "Read-only: the tool never modified any file or database.",
  );
  return `${lines.join("\n")}\n`;
}
