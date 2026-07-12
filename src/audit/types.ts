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

export interface AuditReport {
  schemaVersion: "1.0";
  generatedAt: string;
  schemas: string[];
  summary: AuditSummary;
  schemaFindings: SchemaFinding[];
  tables: TableAudit[];
}

export interface AuditOptions {
  schemas: string[];
  generatedAt?: Date;
}
