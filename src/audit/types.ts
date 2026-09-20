export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type HighestSeverity = Severity | "none";

export type PolicyCommand = "ALL" | "SELECT" | "INSERT" | "UPDATE" | "DELETE";

export type RelationPrivilege =
  | "SELECT"
  | "INSERT"
  | "UPDATE"
  | "DELETE"
  | "TRUNCATE"
  | "REFERENCES"
  | "TRIGGER";

export interface TableSnapshot {
  schema: string;
  name: string;
  owner?: string;
  rlsEnabled: boolean;
  forceRls: boolean;
  isPartitioned: boolean;
  estimatedRows: number | null;
}

export interface RelationPrivilegeSnapshot {
  schema: string;
  table: string;
  grantor: string;
  grantee: string;
  privilege: RelationPrivilege;
  grantable: boolean;
}

export interface DefaultPrivilegeSnapshot {
  schema: string | null;
  owner: string;
  grantee: string;
  objectType: "TABLE";
  privilege: string;
  grantable: boolean;
}

export interface SchemaPrivilegeSnapshot {
  schema: string;
  grantor: string;
  grantee: string;
  privilege: "USAGE" | "CREATE";
  grantable: boolean;
}

export interface RoleSnapshot {
  name: string;
  superuser: boolean;
  bypassRls: boolean;
  inherits: boolean;
}

export interface RoleMembershipSnapshot {
  role: string;
  member: string;
  inheritOption: boolean;
  setOption: boolean;
}

export interface PolicySnapshot {
  schema: string;
  table: string;
  name: string;
  command: PolicyCommand;
  permissive: boolean;
  roles: string[];
  usingExpression: string | null;
  checkExpression: string | null;
}

export interface CatalogSnapshot {
  tables: TableSnapshot[];
  policies: PolicySnapshot[];
  relationPrivileges?: RelationPrivilegeSnapshot[];
  defaultPrivileges?: DefaultPrivilegeSnapshot[];
  schemaPrivileges?: SchemaPrivilegeSnapshot[];
  roles?: RoleSnapshot[];
  roleMemberships?: RoleMembershipSnapshot[];
}

export interface Finding {
  id: string;
  severity: Severity;
  schema: string;
  table: string;
  title: string;
  detail: string;
  recommendation: string;
  suggestedSql?: string[];
}

export interface SchemaFinding {
  id: string;
  severity: Severity;
  schema: string | null;
  title: string;
  detail: string;
  recommendation: string;
  suggestedSql?: string[];
}

export interface TableAudit {
  schema: string;
  table: string;
  rlsEnabled: boolean;
  forceRls: boolean;
  policies: PolicySnapshot[];
  findings: Finding[];
}

export interface AuditSummary {
  tables: number;
  policies: number;
  findings: Record<Severity, number>;
  highestSeverity: HighestSeverity;
}

export interface BaselineSummary {
  new: number;
  unchanged: number;
  resolved: number;
}

export interface AuditReport {
  schemaVersion: "1.0";
  generatedAt: string;
  schemas: string[];
  summary: AuditSummary;
  schemaFindings: SchemaFinding[];
  tables: TableAudit[];
  baseline?: BaselineSummary;
}

export interface AuditOptions {
  schemas: string[];
  generatedAt?: Date;
  appRoles?: readonly string[];
}

export type ProbeStatus = "rows" | "none" | "denied" | "error";

export interface ProbeTarget {
  schema: string;
  table: string;
  ownerColumn: string | null;
}

export interface ProbeExecutionResult {
  role: string;
  schema: string;
  table: string;
  status: ProbeStatus;
  sampledRows: number;
  ownerColumn: string | null;
  distinctOwners: number | null;
  error: string | null;
}

export interface ProbeRoleError {
  role: string;
  message: string;
}

export interface ProbeRunResult {
  probes: ProbeExecutionResult[];
  roleErrors: ProbeRoleError[];
}

export interface ProbeFinding {
  id: string;
  severity: Severity;
  schema: string | null;
  table: string | null;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ProbeReport {
  schemaVersion: "1.0";
  generatedAt: string;
  schemas: string[];
  roles: string[];
  summary: {
    probes: number;
    byStatus: Record<ProbeStatus, number>;
    findings: Record<Severity, number>;
    highestSeverity: HighestSeverity;
  };
  probes: ProbeExecutionResult[];
  findings: ProbeFinding[];
}
