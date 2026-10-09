export { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
export type { FailOptions } from "./audit/analyzer.js";
export { bandForScore, scoreAudit, SEVERITY_PENALTIES } from "./audit/score.js";
export { parseSchemaSql } from "./audit/schema-file.js";
export type { ParsedSchemaFile } from "./audit/schema-file.js";
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
export { renderScoreLine, scoreBadgeUrl } from "./reporters/score.js";
export type { ScoreRenderOptions } from "./reporters/score.js";
export {
  buildReceipt,
  canonicalJson,
  receiptDigest,
  RECEIPT_VERSION,
  serializeReceipt,
  verifyReceipt
} from "./receipts/receipt.js";
export type {
  BuildReceiptOptions,
  CoverageReceipt,
  ReceiptVerification
} from "./receipts/receipt.js";
export { compareShadowFindings, runShadow } from "./shadow/runner.js";
export type { ShadowComparison, ShadowOptions, ShadowOutcome } from "./shadow/runner.js";
export { buildProofArtifact, buildProofClaims, renderProofText } from "./proof/runner.js";
export type { ClaimStatus, ProofArtifact, ProofClaim, ProofCommand, ProofReport } from "./proof/runner.js";
export { decidePredicate } from "./proof/predicate.js";
export type { Decision } from "./proof/predicate.js";
export { renderExplainReport, renderTextReport } from "./reporters/text.js";
export type {
  AuditOptions,
  AuditReport,
  AuditScore,
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
  ScoreBand,
  Severity,
  TableAudit,
  TableSnapshot
} from "./audit/types.js";

export { createMcpServer, startMcpStdioServer, MCP_SERVER_NAME } from "./mcp/index.js";
