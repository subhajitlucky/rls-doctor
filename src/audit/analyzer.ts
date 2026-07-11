import type {
  AuditOptions,
  AuditReport,
  AuditSummary,
  CatalogSnapshot,
  DefaultPrivilegeSnapshot,
  Finding,
  PolicyCommand,
  PolicySnapshot,
  RelationPrivilegeSnapshot,
  RoleMembershipSnapshot,
  RoleSnapshot,
  SchemaFinding,
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
const applicationRoleNames = new Set(["public", "anon", "anonymous", "authenticated"]);
const rowAccessPrivileges = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"]);

type AccessMode = "direct" | "inherited" | "set-role";

interface RoleAccess {
  applicationRole: string;
  targetRole: string;
  mode: AccessMode;
}

interface RoleGraph {
  applicationRoles: string[];
  rolesByName: Map<string, RoleSnapshot>;
  membershipsByMember: Map<string, RoleMembershipSnapshot[]>;
}

export function analyzeCatalog(snapshot: CatalogSnapshot, options: AuditOptions): AuditReport {
  const generatedAt = options.generatedAt ?? new Date();
  const policiesByTable = groupPoliciesByTable(snapshot.policies);
  const relationPrivileges = snapshot.relationPrivileges ?? [];
  const defaultPrivileges = snapshot.defaultPrivileges ?? [];
  const roles = snapshot.roles ?? [];
  const roleMemberships = snapshot.roleMemberships ?? [];
  const roleGraph = buildRoleGraph(snapshot, roles, roleMemberships);
  const privilegesByTable = groupPrivilegesByTable(relationPrivileges);
  const schemaFindings = [
    ...auditDefaultPrivileges(defaultPrivileges, roleGraph),
    ...auditBypassRoles(roles, roleGraph)
  ].sort(compareSchemaFindings);
  const tables = snapshot.tables
    .map((table) =>
      auditTable(
        table,
        policiesByTable.get(tableKey(table.schema, table.name)) ?? [],
        privilegesByTable.get(tableKey(table.schema, table.name)) ?? [],
        roleGraph
      )
    )
    .sort((a, b) => `${a.schema}.${a.table}`.localeCompare(`${b.schema}.${b.table}`));

  return {
    schemaVersion: "1.0",
    generatedAt: generatedAt.toISOString(),
    schemas: options.schemas,
    summary: summarize(tables, schemaFindings, snapshot.policies.length),
    schemaFindings,
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

function auditTable(
  table: TableSnapshot,
  policies: PolicySnapshot[],
  privileges: RelationPrivilegeSnapshot[],
  roleGraph: RoleGraph
): TableAudit {
  const findings: Finding[] = [];

  if (!table.rlsEnabled) {
    const exposure = findTableExposure(table, privileges, roleGraph);
    findings.push(
      exposure
        ? {
            id: "rls-disabled-exposed",
            severity: "high",
            schema: table.schema,
            table: table.name,
            title: "RLS-disabled table is reachable by an application role",
            detail: `${qualifiedName(table)} has no row-level checks; ${exposure}.`,
            recommendation: "Enable RLS and add least-privilege policies for each application role.",
            suggestedSql: enableRlsSql(table)
          }
        : {
            id: "rls-disabled",
            severity: "medium",
            schema: table.schema,
            table: table.name,
            title: "Row Level Security is disabled",
            detail: `${qualifiedName(table)} has no row-level policy enforcement. No reachable application table privilege was found in this catalog snapshot.`,
            recommendation: "Enable RLS before granting this table to an application-facing role.",
            suggestedSql: enableRlsSql(table)
          }
    );

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
      detail: "The table owner bypasses RLS while FORCE RLS is disabled. Superusers and BYPASSRLS roles bypass RLS regardless of FORCE RLS.",
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
  const tableRoles = new Set(policies.flatMap((policy) => policy.roles));

  for (const policy of policies) {
    const commands = policy.command === "ALL" ? concreteCommands : [policy.command];
    const declaredRoles = new Set(policy.roles);
    // Preserve catalog role identity; only literal `public` has PUBLIC applicability,
    // while case-folding is reserved for public-like risk classification.
    const applicableRoles = declaredRoles.has("public") ? tableRoles : declaredRoles;

    for (const role of applicableRoles) {
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
    severity: publicLikeRoles.has(group.role.toLowerCase()) ? "medium" : "low",
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

function buildRoleGraph(
  snapshot: CatalogSnapshot,
  roles: RoleSnapshot[],
  memberships: RoleMembershipSnapshot[]
): RoleGraph {
  const identityNames = new Set<string>(["anon", "anonymous", "authenticated"]);
  for (const role of roles) identityNames.add(role.name);
  for (const membership of memberships) {
    identityNames.add(membership.role);
    identityNames.add(membership.member);
  }
  for (const privilege of snapshot.relationPrivileges ?? []) identityNames.add(privilege.grantee);
  for (const privilege of snapshot.defaultPrivileges ?? []) identityNames.add(privilege.grantee);
  for (const table of snapshot.tables) if (table.owner) identityNames.add(table.owner);

  const membershipsByMember = new Map<string, RoleMembershipSnapshot[]>();
  for (const membership of memberships) {
    const existing = membershipsByMember.get(membership.member) ?? [];
    existing.push(membership);
    membershipsByMember.set(membership.member, existing);
  }
  for (const edges of membershipsByMember.values()) {
    edges.sort((left, right) =>
      left.role.localeCompare(right.role) || left.member.localeCompare(right.member)
    );
  }

  return {
    applicationRoles: [...identityNames]
      .filter((name) => name !== "PUBLIC" && isApplicationRole(name))
      .sort((left, right) => left.localeCompare(right)),
    rolesByName: new Map(roles.map((role) => [role.name, role])),
    membershipsByMember
  };
}

function isApplicationRole(role: string): boolean {
  return applicationRoleNames.has(role.toLowerCase());
}

function findBestAccess(graph: RoleGraph, targetRole: string): RoleAccess | undefined {
  const accesses: RoleAccess[] = [];
  for (const applicationRole of graph.applicationRoles) {
    if (applicationRole === targetRole) {
      accesses.push({ applicationRole, targetRole, mode: "direct" });
      continue;
    }
    if (canReachRole(graph, applicationRole, targetRole, "inherited")) {
      accesses.push({ applicationRole, targetRole, mode: "inherited" });
    } else if (canReachRole(graph, applicationRole, targetRole, "set-role")) {
      accesses.push({ applicationRole, targetRole, mode: "set-role" });
    }
  }

  return accesses.sort(compareRoleAccess)[0];
}

function findBypassAccess(graph: RoleGraph, targetRole: string): RoleAccess | undefined {
  const accesses: RoleAccess[] = [];
  for (const applicationRole of graph.applicationRoles) {
    if (applicationRole === targetRole) {
      accesses.push({ applicationRole, targetRole, mode: "direct" });
    } else if (canReachRole(graph, applicationRole, targetRole, "set-role")) {
      accesses.push({ applicationRole, targetRole, mode: "set-role" });
    }
  }
  return accesses.sort(compareRoleAccess)[0];
}

function canReachRole(
  graph: RoleGraph,
  sourceRole: string,
  targetRole: string,
  mode: Exclude<AccessMode, "direct">
): boolean {
  const queue = [sourceRole];
  const visited = new Set<string>(queue);

  for (let index = 0; index < queue.length; index += 1) {
    const member = queue[index]!;
    const memberCanInherit = graph.rolesByName.get(member)?.inherits !== false;
    for (const membership of graph.membershipsByMember.get(member) ?? []) {
      const enabled =
        mode === "inherited"
          ? membership.inheritOption && memberCanInherit
          : membership.setOption;
      if (!enabled) continue;
      if (membership.role === targetRole) return true;
      if (!visited.has(membership.role)) {
        visited.add(membership.role);
        queue.push(membership.role);
      }
    }
  }

  return false;
}

function compareRoleAccess(left: RoleAccess, right: RoleAccess): number {
  const modeRank: Record<AccessMode, number> = { direct: 0, inherited: 1, "set-role": 2 };
  return (
    modeRank[left.mode] - modeRank[right.mode] ||
    left.applicationRole.localeCompare(right.applicationRole) ||
    left.targetRole.localeCompare(right.targetRole)
  );
}

function formatAccess(access: RoleAccess): string {
  if (access.mode === "direct") return `Application role ${access.applicationRole}`;
  if (access.mode === "inherited") {
    return `Application role ${access.applicationRole} reaches ${access.targetRole} through inherited membership`;
  }
  return `Application role ${access.applicationRole} reaches ${access.targetRole} through SET ROLE`;
}

function findTableExposure(
  table: TableSnapshot,
  privileges: RelationPrivilegeSnapshot[],
  roleGraph: RoleGraph
): string | undefined {
  const candidates: Array<{ privilege: string; grantee: string; access?: RoleAccess }> = [];
  for (const privilege of privileges) {
    if (!rowAccessPrivileges.has(privilege.privilege)) continue;
    if (privilege.grantee === "PUBLIC") {
      candidates.push({ privilege: privilege.privilege, grantee: privilege.grantee });
      continue;
    }
    const access = findBestAccess(roleGraph, privilege.grantee);
    if (access) candidates.push({ privilege: privilege.privilege, grantee: privilege.grantee, access });
  }

  if (table.owner) {
    const access = findBestAccess(roleGraph, table.owner);
    if (access) candidates.push({ privilege: "owner privileges", grantee: table.owner, access });
  }

  const candidate = candidates.sort((left, right) =>
    left.grantee.localeCompare(right.grantee) || left.privilege.localeCompare(right.privilege)
  )[0];
  if (!candidate) return undefined;
  if (!candidate.access) return `PUBLIC has ${candidate.privilege}`;
  return `${formatAccess(candidate.access)} and can exercise ${candidate.privilege} granted to ${candidate.grantee}`;
}

function enableRlsSql(table: TableSnapshot): string[] {
  return [
    `alter table ${quoteQualifiedName(table)} enable row level security;`,
    "-- Then add policies that match your access model before exposing this table to client roles."
  ];
}

function auditDefaultPrivileges(
  privileges: DefaultPrivilegeSnapshot[],
  roleGraph: RoleGraph
): SchemaFinding[] {
  const findings = new Map<string, SchemaFinding>();
  for (const privilege of privileges) {
    const isPublic = privilege.grantee === "PUBLIC";
    const access = isPublic ? undefined : findBestAccess(roleGraph, privilege.grantee);
    if (!isPublic && !access) continue;

    const routeContext = isPublic ? "applies to every role" : formatAccess(access!);
    const defaultContext = privilege.schema
      ? `Defaults for owner ${privilege.owner} in schema ${privilege.schema}`
      : `Database-wide defaults for owner ${privilege.owner}`;
    const finding: SchemaFinding = {
      id: "broad-default-table-privilege",
      severity: defaultPrivilegeSeverity(privilege.privilege),
      schema: privilege.schema,
      title: "Broad default table privilege",
      detail: `${defaultContext} grant grantee ${privilege.grantee} privilege ${privilege.privilege}; ${routeContext}. Future tables created by ${privilege.owner} can become application-accessible without an explicit table grant.`,
      recommendation: "Revoke the broad default privilege and grant only the table privileges required by each application role."
    };
    const key = [
      privilege.schema ?? "",
      privilege.owner,
      privilege.grantee,
      privilege.privilege,
      finding.id
    ].join("\u0000");
    findings.set(key, finding);
  }
  return [...findings.values()];
}

function defaultPrivilegeSeverity(privilege: string): Severity {
  if (["INSERT", "UPDATE", "DELETE", "TRUNCATE"].includes(privilege)) return "high";
  if (privilege === "SELECT") return "medium";
  return "low";
}

function auditBypassRoles(roles: RoleSnapshot[], roleGraph: RoleGraph): SchemaFinding[] {
  const findings: SchemaFinding[] = [];
  for (const role of roles) {
    if (!role.superuser && !role.bypassRls) continue;
    const access = findBypassAccess(roleGraph, role.name);
    if (!access) continue;
    const attributes = [role.superuser ? "SUPERUSER" : "", role.bypassRls ? "BYPASSRLS" : ""]
      .filter(Boolean)
      .join(" and ");
    findings.push({
      id: "rls-bypass-role",
      severity: "high",
      schema: null,
      title: "Application role can reach an RLS-bypass role",
      detail: `${formatAccess(access)}. Role ${role.name} has ${attributes} and bypasses row-level security even when FORCE RLS is enabled.`,
      recommendation: "Remove application membership paths to privileged roles and use isolated server-side credentials for administrative work."
    });
  }
  return findings;
}

function compareSchemaFindings(left: SchemaFinding, right: SchemaFinding): number {
  return (
    severityRank[right.severity] - severityRank[left.severity] ||
    (left.schema ?? "").localeCompare(right.schema ?? "") ||
    left.detail.localeCompare(right.detail) ||
    left.id.localeCompare(right.id)
  );
}

function summarize(
  tables: TableAudit[],
  schemaFindings: SchemaFinding[],
  policyCount: number
): AuditSummary {
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

  for (const finding of schemaFindings) {
    findings[finding.severity] += 1;
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

function groupPrivilegesByTable(
  privileges: RelationPrivilegeSnapshot[]
): Map<string, RelationPrivilegeSnapshot[]> {
  const grouped = new Map<string, RelationPrivilegeSnapshot[]>();
  for (const privilege of privileges) {
    const key = tableKey(privilege.schema, privilege.table);
    const existing = grouped.get(key) ?? [];
    existing.push(privilege);
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
