import { createHash } from "node:crypto";
import type { PolicyCommand, PolicySnapshot, TableSnapshot } from "../audit/types.js";
import { canonicalJson } from "../receipts/receipt.js";
import { decidePredicate, type Decision } from "./predicate.js";

export type ProofCommand = Exclude<PolicyCommand, "ALL">;
export type ClaimStatus = "proved" | "witness" | "undecided";

export interface ProofClaim {
  schema: string;
  table: string;
  command: ProofCommand;
  role: string;
  status: ClaimStatus;
  column?: string;
  reason: string;
  policies: string[];
}

export interface ProofArtifact {
  proofVersion: "1";
  tool: { name: "rls-doctor"; version: string };
  generatedAt: string;
  subject: { schemaFiles: string[]; schemas: string[]; roles: string[] };
  limitations: string[];
  claims: ProofClaim[];
  digest: { algorithm: "sha256"; value: string };
}

const COMMANDS: ProofCommand[] = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const PUBLIC_LIKE = new Set(["public"]);
const ANON_LIKE = new Set(["anon", "anonymous"]);

function roleApplies(policyRoles: readonly string[], role: string): boolean {
  if (policyRoles.includes(role)) return true;
  if (policyRoles.some((entry) => PUBLIC_LIKE.has(entry))) return true;
  return ANON_LIKE.has(role) && policyRoles.some((entry) => ANON_LIKE.has(entry));
}

function predicateFor(policy: PolicySnapshot, command: ProofCommand): string | null {
  if (command === "SELECT" || command === "DELETE") {
    return policy.usingExpression;
  }
  return policy.checkExpression ?? policy.usingExpression;
}

function combinePredicates(policies: readonly PolicySnapshot[], command: ProofCommand): string {
  const permissive = policies.filter((policy) => policy.permissive);
  const restrictive = policies.filter((policy) => !policy.permissive);
  const permissiveExpression = permissive.length === 0
    ? "false"
    : permissive
        .map((policy) => `(${predicateFor(policy, command) ?? "false"})`)
        .join(" OR ");
  const restrictiveExpressions = restrictive.map(
    (policy) => `(${predicateFor(policy, command) ?? "false"})`,
  );
  return restrictiveExpressions.length === 0
    ? permissiveExpression
    : [permissiveExpression, ...restrictiveExpressions].map((part) => `(${part})`).join(" AND ");
}

function claimFromDecision(
  table: TableSnapshot,
  command: ProofCommand,
  role: string,
  policies: readonly PolicySnapshot[],
  decision: Decision,
): ProofClaim {
  const names = policies.map((policy) => policy.name).sort();
  const base = {
    schema: table.schema,
    table: table.name,
    command,
    role,
    policies: names,
  };
  if (decision.status === "proved") {
    return {
      ...base,
      status: "proved",
      ...(decision.column === null ? {} : { column: decision.column }),
      reason: decision.column === null
        ? "no applicable policy admits rows (default deny)"
        : `every admitted row satisfies ${decision.column} = auth.uid()`,
    };
  }
  return { ...base, status: decision.status, reason: decision.reason };
}

/**
 * Prove row-isolation claims for each table, command, and role from parsed
 * policy state. Uses the decidable fragment in ./predicate.ts; anything
 * outside it is reported as undecided with a reason — never guessed.
 */
export function buildProofClaims(
  tables: readonly TableSnapshot[],
  policies: readonly PolicySnapshot[],
  roles: readonly string[],
): ProofClaim[] {
  const claims: ProofClaim[] = [];
  for (const table of [...tables].sort((left, right) =>
    `${left.schema}.${left.name}`.localeCompare(`${right.schema}.${right.name}`)
  )) {
    for (const command of COMMANDS) {
      for (const role of roles) {
        if (!table.rlsEnabled) {
          claims.push({
            schema: table.schema,
            table: table.name,
            command,
            role,
            status: "witness",
            reason: "RLS is disabled; policies are not enforced",
            policies: [],
          });
          continue;
        }
        const applicable = policies.filter((policy) =>
          policy.schema === table.schema &&
          policy.table === table.name &&
          (policy.command === "ALL" || policy.command === command) &&
          roleApplies(policy.roles, role)
        );
        if (applicable.length === 0) {
          claims.push(claimFromDecision(table, command, role, applicable, {
            status: "proved",
            column: null,
          }));
          continue;
        }
        const decision = decidePredicate(combinePredicates(applicable, command));
        claims.push(claimFromDecision(table, command, role, applicable, decision));
      }
    }
  }
  return claims;
}

export interface ProofReport {
  artifact: ProofArtifact;
  output: string;
  exitCode: 0 | 1;
}

export function buildProofArtifact(
  claims: readonly ProofClaim[],
  subject: ProofArtifact["subject"],
  limitations: readonly string[],
  toolVersion: string,
  generatedAt: Date = new Date(),
): ProofArtifact {
  const body = {
    proofVersion: "1" as const,
    tool: { name: "rls-doctor" as const, version: toolVersion },
    generatedAt: generatedAt.toISOString(),
    subject,
    limitations: [...limitations],
    claims: [...claims],
  };
  return {
    ...body,
    digest: {
      algorithm: "sha256",
      value: createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"),
    },
  };
}

export function renderProofText(artifact: ProofArtifact): string {
  const lines = [
    "RLS Doctor Proof Mode",
    "=====================",
    "",
    `Schema file(s): ${artifact.subject.schemaFiles.join(", ")} · roles: ${artifact.subject.roles.join(", ")}`,
    "",
  ];

  const width = Math.max(0, ...artifact.claims.map((claim) =>
    `${claim.schema}.${claim.table}`.length
  ));
  for (const claim of artifact.claims) {
    const location = `${claim.schema}.${claim.table}`.padEnd(width);
    const status = claim.status.toUpperCase().padEnd(9);
    const detail = claim.column === undefined
      ? claim.reason
      : `${claim.reason}${claim.policies.length === 0 ? "" : ` (policy ${claim.policies.join(", ")})`}`;
    lines.push(`${location}  ${claim.command.padEnd(6)}  ${claim.role.padEnd(14)}  ${status}  ${detail}`);
  }

  const counts = {
    proved: artifact.claims.filter((claim) => claim.status === "proved").length,
    witness: artifact.claims.filter((claim) => claim.status === "witness").length,
    undecided: artifact.claims.filter((claim) => claim.status === "undecided").length,
  };
  lines.push(
    "",
    `Summary: ${counts.proved} proved, ${counts.witness} witness, ${counts.undecided} undecided.`,
    counts.witness > 0
      ? "Exit code 1: at least one claim has a witness — a role can reach rows outside the ownership boundary."
      : counts.undecided > 0
        ? "Exit code 0: no witness found; undecided claims are listed and never counted as proofs."
        : "Exit code 0: every claim is proved within the decidable fragment.",
  );
  if (artifact.limitations.length > 0) {
    lines.push("", "Coverage limitations (offline parsing):");
    for (const limitation of artifact.limitations) lines.push(`- ${limitation}`);
  }
  return `${lines.join("\n")}\n`;
}
