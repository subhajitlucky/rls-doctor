export { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
export { analyzeProbeResults, shouldFailProbe } from "./audit/probe.js";
export type { ProbeAnalysisOptions } from "./audit/probe.js";
export { loadCatalog } from "./db/catalog.js";
export { runProbes } from "./db/probe.js";
export type { ProbeOptions } from "./db/probe.js";
export { renderJsonReport } from "./reporters/json.js";
export { renderProbeJsonReport, renderProbeTextReport } from "./reporters/probe.js";
export { renderExplainReport, renderTextReport } from "./reporters/text.js";
export type {
  AuditOptions,
  AuditReport,
  CatalogSnapshot,
  DefaultPrivilegeSnapshot,
  Finding,
  PolicySnapshot,
  ProbeExecutionResult,
  ProbeFinding,
  ProbeReport,
  ProbeRoleError,
  ProbeRunResult,
  ProbeStatus,
  ProbeTarget,
  RelationPrivilege,
  RelationPrivilegeSnapshot,
  RoleMembershipSnapshot,
  RoleSnapshot,
  SchemaPrivilegeSnapshot,
  SchemaFinding,
  Severity,
  TableAudit,
  TableSnapshot
} from "./audit/types.js";
