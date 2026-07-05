export { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
export { loadCatalog } from "./db/catalog.js";
export { renderJsonReport } from "./reporters/json.js";
export { renderExplainReport, renderTextReport } from "./reporters/text.js";
export type {
  AuditOptions,
  AuditReport,
  CatalogSnapshot,
  Finding,
  PolicySnapshot,
  Severity,
  TableAudit,
  TableSnapshot
} from "./audit/types.js";
