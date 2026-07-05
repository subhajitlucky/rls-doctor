export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type PolicyCommand = "ALL" | "SELECT" | "INSERT" | "UPDATE" | "DELETE";

export interface TableSnapshot {
  schema: string;
  name: string;
  rlsEnabled: boolean;
  forceRls: boolean;
  isPartitioned: boolean;
  estimatedRows: number | null;
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
  highestSeverity: Severity;
}

export interface AuditReport {
  generatedAt: string;
  schemas: string[];
  summary: AuditSummary;
  tables: TableAudit[];
}

export interface AuditOptions {
  schemas: string[];
  generatedAt?: Date;
}
