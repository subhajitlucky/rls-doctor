import type {
  AuditOptions,
  AuditReport,
  AuditSummary,
  CatalogSnapshot,
  Finding,
  PolicyCommand,
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

export function analyzeCatalog(snapshot: CatalogSnapshot, options: AuditOptions): AuditReport {
  const generatedAt = options.generatedAt ?? new Date();
  const policiesByTable = groupPoliciesByTable(snapshot.policies);
  const tables = snapshot.tables
    .map((table) => auditTable(table, policiesByTable.get(tableKey(table.schema, table.name)) ?? []))
    .sort((a, b) => `${a.schema}.${a.table}`.localeCompare(`${b.schema}.${b.table}`));

  return {
    schemaVersion: "1.0",
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

  return severityOrder.some(
    (severity) => severityRank[severity] >= severityRank[failOn] && report.summary.findings[severity] > 0
  );
}

export function getTableAudit(report: AuditReport, tableRef: string): TableAudit | undefined {
  const [schemaPart, tablePart] = tableRef.includes(".") ? tableRef.split(".", 2) : ["public", tableRef];
  const schema = schemaPart?.trim();
  const table = tablePart?.trim();

  if (!schema || !table) {
    return undefined;
  }

  return report.tables.find((audit) => audit.schema === schema && audit.table === table);
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
      recommendation: "Enable RLS and add least-privilege policies for each application role.",
      suggestedSql: [
        `alter table ${quoteQualifiedName(table)} enable row level security;`,
        `-- Then add policies that match your access model before exposing this table to client roles.`
      ]
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
      recommendation: "Add explicit policies for the roles and commands the application needs.",
      suggestedSql: [
        `create policy "users can read own ${table.name}"`,
        `  on ${quoteQualifiedName(table)}`,
        `  for select`,
        `  to authenticated`,
        `  using ((select auth.uid()) = owner_id);`
      ]
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
      recommendation: "Enable FORCE RLS for sensitive multi-tenant tables after confirming owner-side maintenance workflows.",
      suggestedSql: [`alter table ${quoteQualifiedName(table)} force row level security;`]
    });
  }

  for (const policy of policies) {
    findings.push(...auditPolicy(table, policy));
  }

  findings.push(...auditPolicyComposition(table, policies));

  return tableAudit(table, policies, findings);
}

const concreteCommands: Exclude<PolicyCommand, "ALL">[] = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE"
];

interface PolicyCompositionGroup {
  role: string;
  command: Exclude<PolicyCommand, "ALL">;
  permissive: Map<string, PolicySnapshot>;
  restrictive: Map<string, PolicySnapshot>;
}

function auditPolicyComposition(table: TableSnapshot, policies: PolicySnapshot[]): Finding[] {
  const groups = new Map<string, PolicyCompositionGroup>();

  for (const policy of policies) {
    const commands = policy.command === "ALL" ? concreteCommands : [policy.command];

    for (const role of new Set(policy.roles.map((policyRole) => policyRole.toLowerCase()))) {
      for (const command of commands) {
        const key = `${role}\u0000${command}`;
        const group = groups.get(key) ?? {
          role,
          command,
          permissive: new Map<string, PolicySnapshot>(),
          restrictive: new Map<string, PolicySnapshot>()
        };
        const policiesByKind = policy.permissive ? group.permissive : group.restrictive;
        policiesByKind.set(policy.name, policy);
        groups.set(key, group);
      }
    }
  }

  return [...groups.values()]
    .filter((group) => group.permissive.size > 1)
    .sort(compareCompositionGroups)
    .map((group) => compositionFinding(table, group));
}

function compareCompositionGroups(left: PolicyCompositionGroup, right: PolicyCompositionGroup): number {
  const roleComparison = left.role.localeCompare(right.role);
  if (roleComparison !== 0) {
    return roleComparison;
  }

  return concreteCommands.indexOf(left.command) - concreteCommands.indexOf(right.command);
}

function compositionFinding(table: TableSnapshot, group: PolicyCompositionGroup): Finding {
  const permissiveNames = [...group.permissive.keys()].sort((a, b) => a.localeCompare(b));
  const restrictiveNames = [...group.restrictive.keys()].sort((a, b) => a.localeCompare(b));
  const restrictiveContext = restrictivePolicyContext(restrictiveNames);

  return {
    id: "multiple-permissive-policies",
    severity: publicLikeRoles.has(group.role) ? "medium" : "low",
    schema: table.schema,
    table: table.name,
    title: "Multiple permissive policies combine for one role and command",
    detail: `Role ${group.role} has ${permissiveNames.length} permissive policies for ${group.command}: ${formatPolicyNames(permissiveNames)}. Their predicates are OR-combined.${restrictiveContext}`,
    recommendation:
      "Review the policies together and confirm that access allowed by any permissive policy is intended."
  };
}

function restrictivePolicyContext(policyNames: string[]): string {
  if (policyNames.length === 0) {
    return "";
  }

  if (policyNames.length === 1) {
    return ` Restrictive policy ${formatPolicyNames(policyNames)} is AND-combined with the permissive result.`;
  }

  return ` Restrictive policies ${formatPolicyNames(policyNames)} are AND-combined with the permissive result.`;
}

function formatPolicyNames(policyNames: string[]): string {
  return policyNames.map((name) => `"${name}"`).join(", ");
}

function auditPolicy(table: TableSnapshot, policy: PolicySnapshot): Finding[] {
  const findings: Finding[] = [];
  const grantsPublicLikeRole = policy.roles.some((role) => publicLikeRoles.has(role.toLowerCase()));
  const evaluatesUsingForRead = policy.command === "SELECT" || policy.command === "ALL";
  const unconditionalRead = evaluatesUsingForRead && isUnconditionalExpression(policy.usingExpression);
  const unconditionalWrite = hasUnconditionalWriteBehavior(policy);

  if (grantsPublicLikeRole && unconditionalRead) {
    findings.push({
      id: "public-unconditional-read",
      severity: "high",
      schema: table.schema,
      table: table.name,
      title: "Anonymous-style role can read rows unconditionally",
      detail: `Policy "${policy.name}" grants ${policy.command} to ${policy.roles.join(", ")} with no row predicate.`,
      recommendation: "Restrict the policy with tenant, owner, or explicit public-content predicates.",
      suggestedSql: [
        `-- Adapt this suggested SQL to your schema and access model before executing it.`,
        `alter policy ${quoteIdentifier(policy.name)}`,
        `  on ${quoteQualifiedName(table)}`,
        `  using (<public_read_predicate>);`
      ]
    });
  }

  if (grantsPublicLikeRole && unconditionalWrite) {
    findings.push({
      id: "public-unconditional-write",
      severity: "critical",
      schema: table.schema,
      table: table.name,
      title: "Anonymous-style role can write rows too broadly",
      detail: `Policy "${policy.name}" allows ${policy.command} for ${policy.roles.join(", ")} with an unconditional predicate.`,
      recommendation: writePolicyRecommendation(policy),
      suggestedSql: suggestedWritePolicySql(table, policy)
    });
  }

  if (missingCheckCreatesUnconstrainedWrite(policy)) {
    findings.push({
      id: "write-policy-missing-check",
      severity: "medium",
      schema: table.schema,
      table: table.name,
      title: "Write policy has no explicit WITH CHECK expression",
      detail: `Policy "${policy.name}" handles ${policy.command} without an explicit insert/update constraint.`,
      recommendation: "Add WITH CHECK so new or changed rows must satisfy the same ownership and tenant boundaries.",
      suggestedSql: [
        `-- Adapt this suggested SQL to your schema and access model before executing it.`,
        `alter policy ${quoteIdentifier(policy.name)}`,
        `  on ${quoteQualifiedName(table)}`,
        `  with check ((select auth.uid()) = <owner_column>);`
      ]
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

function effectiveCheckExpression(policy: PolicySnapshot): string | null {
  if (policy.checkExpression !== null) {
    return policy.checkExpression;
  }

  if (policy.command === "UPDATE" || policy.command === "ALL") {
    return policy.usingExpression;
  }

  return null;
}

function hasUnconditionalWriteBehavior(policy: PolicySnapshot): boolean {
  switch (policy.command) {
    case "SELECT":
      return false;
    case "INSERT":
      return isUnconditionalExpression(effectiveCheckExpression(policy));
    case "UPDATE":
    case "ALL":
      return (
        isUnconditionalExpression(policy.usingExpression) ||
        isUnconditionalExpression(effectiveCheckExpression(policy))
      );
    case "DELETE":
      return isUnconditionalExpression(policy.usingExpression);
  }
}

function missingCheckCreatesUnconstrainedWrite(policy: PolicySnapshot): boolean {
  if (policy.checkExpression !== null || policy.command === "SELECT" || policy.command === "DELETE") {
    return false;
  }

  return isUnconditionalExpression(effectiveCheckExpression(policy));
}

function writePolicyRecommendation(policy: PolicySnapshot): string {
  if (policy.command === "INSERT") {
    return "Require an authenticated ownership constraint in WITH CHECK for inserted rows.";
  }

  if (policy.command === "DELETE") {
    return "Require an authenticated ownership constraint in USING for deleted rows.";
  }

  return "Require authenticated ownership constraints in USING and WITH CHECK for writes.";
}

function suggestedWritePolicySql(table: TableSnapshot, policy: PolicySnapshot): string[] {
  const sql = [
    `-- Adapt this suggested SQL to your schema and access model before executing it.`,
    `alter policy ${quoteIdentifier(policy.name)}`,
    `  on ${quoteQualifiedName(table)}`,
    `  to authenticated`
  ];

  if (policy.command === "ALL" || policy.command === "UPDATE" || policy.command === "DELETE") {
    sql.push(`  using ((select auth.uid()) = <owner_column>)`);
  }

  if (policy.command === "ALL" || policy.command === "INSERT" || policy.command === "UPDATE") {
    sql.push(`  with check ((select auth.uid()) = <owner_column>)`);
  }

  sql[sql.length - 1] += ";";
  return sql;
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
    .find((severity) => findings[severity] > 0) ?? "none";

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

function quoteQualifiedName(table: TableSnapshot): string {
  return `${quoteIdentifier(table.schema)}.${quoteIdentifier(table.name)}`;
}

function quoteIdentifier(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}
