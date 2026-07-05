import type {
  AuditOptions,
  AuditReport,
  AuditSummary,
  CatalogSnapshot,
  Finding,
  PolicySnapshot,
  Severity,
  TableAudit,
  TableSnapshot
} from "./types.js";

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const severityOrder: Severity[] = ["info", "low", "medium", "high", "critical"];
const publicLikeRoles = new Set(["public", "anon", "anonymous"]);
const writeCommands = new Set(["ALL", "INSERT", "UPDATE"]);

export function analyzeCatalog(snapshot: CatalogSnapshot, options: AuditOptions): AuditReport {
  const generatedAt = options.generatedAt ?? new Date();
  const policiesByTable = groupPoliciesByTable(snapshot.policies);
  const tables = snapshot.tables
    .map((table) => auditTable(table, policiesByTable.get(tableKey(table.schema, table.name)) ?? []))
    .sort((a, b) => `${a.schema}.${a.table}`.localeCompare(`${b.schema}.${b.table}`));

  return {
    generatedAt: generatedAt.toISOString(),
    schemas: options.schemas,
    summary: summarize(tables, snapshot.policies.length),
    tables
  };
}

export function shouldFail(report: AuditReport, failOn: Severity | "none"): boolean {
  if (failOn === "none") {
    return false;
  }

  return severityRank[report.summary.highestSeverity] >= severityRank[failOn];
}

function auditTable(table: TableSnapshot, policies: PolicySnapshot[]): TableAudit {
  const findings: Finding[] = [];

  if (!table.rlsEnabled) {
    findings.push({
      id: "rls-disabled",
      severity: "high",
      schema: table.schema,
      table: table.name,
      title: "Row Level Security is disabled",
      detail: `${qualifiedName(table)} can be read or changed according to table privileges without row-level policy checks.`,
      recommendation: "Enable RLS and add least-privilege policies for each application role."
    });

    return tableAudit(table, policies, findings);
  }

  if (policies.length === 0) {
    findings.push({
      id: "rls-enabled-no-policies",
      severity: "medium",
      schema: table.schema,
      table: table.name,
      title: "RLS is enabled but no policies exist",
      detail: `${qualifiedName(table)} will default-deny access for non-owner roles, which may break application reads or writes.`,
      recommendation: "Add explicit policies for the roles and commands the application needs."
    });
  }

  if (!table.forceRls) {
    findings.push({
      id: "force-rls-disabled",
      severity: "info",
      schema: table.schema,
      table: table.name,
      title: "FORCE ROW LEVEL SECURITY is disabled",
      detail: "Table owners and privileged sessions can bypass RLS unless FORCE RLS is enabled.",
      recommendation: "Enable FORCE RLS for sensitive multi-tenant tables after confirming owner-side maintenance workflows."
    });
  }

  for (const policy of policies) {
    findings.push(...auditPolicy(table, policy));
  }

  return tableAudit(table, policies, findings);
}

function auditPolicy(table: TableSnapshot, policy: PolicySnapshot): Finding[] {
  const findings: Finding[] = [];
  const grantsPublicLikeRole = policy.roles.some((role) => publicLikeRoles.has(role.toLowerCase()));
  const unconditionalUsing = isUnconditionalExpression(policy.usingExpression);
  const unconditionalCheck = isUnconditionalExpression(policy.checkExpression);

  if (grantsPublicLikeRole && (policy.command === "ALL" || policy.command === "SELECT") && unconditionalUsing) {
    findings.push({
      id: "public-unconditional-read",
      severity: "high",
      schema: table.schema,
      table: table.name,
      title: "Anonymous-style role can read rows unconditionally",
      detail: `Policy "${policy.name}" grants ${policy.command} to ${policy.roles.join(", ")} with no row predicate.`,
      recommendation: "Restrict the policy with tenant, owner, or explicit public-content predicates."
    });
  }

  if (grantsPublicLikeRole && writeCommands.has(policy.command) && (unconditionalUsing || unconditionalCheck)) {
    findings.push({
      id: "public-unconditional-write",
      severity: "critical",
      schema: table.schema,
      table: table.name,
      title: "Anonymous-style role can write rows too broadly",
      detail: `Policy "${policy.name}" allows ${policy.command} for ${policy.roles.join(", ")} with an unconditional predicate.`,
      recommendation: "Require authenticated ownership checks and explicit WITH CHECK constraints for writes."
    });
  }

  if (writeCommands.has(policy.command) && policy.checkExpression === null) {
    findings.push({
      id: "write-policy-missing-check",
      severity: "medium",
      schema: table.schema,
      table: table.name,
      title: "Write policy has no explicit WITH CHECK expression",
      detail: `Policy "${policy.name}" handles ${policy.command} without an explicit insert/update constraint.`,
      recommendation: "Add WITH CHECK so new or changed rows must satisfy the same ownership and tenant boundaries."
    });
  }

  if (policy.permissive && grantsPublicLikeRole) {
    findings.push({
      id: "public-permissive-policy",
      severity: "low",
      schema: table.schema,
      table: table.name,
      title: "Public-like role uses a permissive policy",
      detail: `Policy "${policy.name}" is permissive, so it is OR-combined with other permissive policies.`,
      recommendation: "Review whether the policy should be restrictive or scoped to authenticated application roles."
    });
  }

  return findings;
}

function summarize(tables: TableAudit[], policyCount: number): AuditSummary {
  const findings: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  for (const table of tables) {
    for (const finding of table.findings) {
      findings[finding.severity] += 1;
    }
  }

  const highestSeverity = [...severityOrder]
    .reverse()
    .find((severity) => findings[severity] > 0) ?? "info";

  return {
    tables: tables.length,
    policies: policyCount,
    findings,
    highestSeverity
  };
}

function groupPoliciesByTable(policies: PolicySnapshot[]): Map<string, PolicySnapshot[]> {
  const grouped = new Map<string, PolicySnapshot[]>();

  for (const policy of policies) {
    const key = tableKey(policy.schema, policy.table);
    const existing = grouped.get(key) ?? [];
    existing.push(policy);
    grouped.set(key, existing);
  }

  return grouped;
}

function tableAudit(table: TableSnapshot, policies: PolicySnapshot[], findings: Finding[]): TableAudit {
  return {
    schema: table.schema,
    table: table.name,
    rlsEnabled: table.rlsEnabled,
    forceRls: table.forceRls,
    policies: [...policies].sort((a, b) => a.name.localeCompare(b.name)),
    findings
  };
}

function isUnconditionalExpression(expression: string | null): boolean {
  if (expression === null) {
    return true;
  }

  const normalized = expression.replace(/[()]/g, "").trim().toLowerCase();
  return normalized === "" || normalized === "true" || normalized === "1 = 1" || normalized === "1=1";
}

function tableKey(schema: string, table: string): string {
  return `${schema}.${table}`;
}

function qualifiedName(table: TableSnapshot): string {
  return `${table.schema}.${table.name}`;
}
