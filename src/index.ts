export { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
export type { FailOptions } from "./audit/analyzer.js";
export { isAuditReport, loadBaseline } from "./audit/baseline.js";
export type { AuditBaseline } from "./audit/baseline.js";
export {
  collectReportFindings,
  compareWithBaseline,
  findingFingerprint,
  reportFindingFingerprints
} from "./audit/fingerprint.js";
export type { AuditableFinding, BaselineComparison } from "./audit/fingerprint.js";
export { analyzeProbeResults, shouldFailProbe } from "./audit/probe.js";
export type { ProbeAnalysisOptions } from "./audit/probe.js";
export { loadCatalog } from "./db/catalog.js";
export { runProbes } from "./db/probe.js";
export type { ProbeOptions } from "./db/probe.js";
export { renderJsonReport } from "./reporters/json.js";
export { renderProbeJsonReport, renderProbeTextReport } from "./reporters/probe.js";
export { renderSarifReport } from "./reporters/sarif.js";
export type { SarifRenderOptions } from "./reporters/sarif.js";
export { renderExplainReport, renderTextReport } from "./reporters/text.js";
export type {
  AuditOptions,
  AuditReport,
  BaselineSummary,
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
