import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { analyzeCatalog, getTableAudit } from "../audit/analyzer.js";
import { analyzeProbeResults } from "../audit/probe.js";
import { formatCliError, resolveConnectionString } from "../cli-support.js";
import { loadCatalog } from "../db/catalog.js";
import { runProbes } from "../db/probe.js";
import {
  renderProbeJsonReport,
  renderProbeTextReport,
} from "../reporters/probe.js";
import { renderJsonReport } from "../reporters/json.js";
import {
  renderExplainReport,
  renderTextReport,
} from "../reporters/text.js";
import {
  CHECK_TOOL_NAME,
  EXPLAIN_TOOL_NAME,
  MAX_TOOL_PAYLOAD_BYTES,
  PROBE_TOOL_NAME,
  cutUtf8Safe,
  parseFormat,
  parseStringArray,
  type CheckToolArgs,
  type ExplainToolArgs,
  type ProbeToolArgs,
} from "./tool-schemas.js";

const DEFAULT_OWNER_COLUMNS = ["owner_id", "user_id", "tenant_id", "account_id"];

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

export function errorToolResult(error: unknown): CallToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: "text", text: `rls-doctor: ${message}` }],
  };
}

function bound(text: string): string {
  return cutUtf8Safe(text, MAX_TOOL_PAYLOAD_BYTES);
}

export async function handleCheckRls(args: CheckToolArgs): Promise<CallToolResult> {
  let connectionString: string | undefined;
  try {
    connectionString = resolveConnectionString(args.connectionString);
    const schemas = args.schemas && args.schemas.length > 0 ? args.schemas : ["public"];
    const appRoles = parseStringArray(args.appRoles);

    const snapshot = await loadCatalog({
      connectionString,
      schemas,
      statementTimeoutMs: 10_000,
      ...(appRoles.length > 0 ? { appRoles } : {}),
    });
    const report = analyzeCatalog(snapshot, {
      schemas,
      ...(appRoles.length > 0 ? { appRoles } : {}),
    });
    const rendered = parseFormat(args.format) === "json"
      ? renderJsonReport(report)
      : renderTextReport(report);
    return textResult(bound(rendered));
  } catch (error) {
    return errorToolResult(new Error(formatCliError(error, connectionString)));
  }
}

export async function handleProbeAccess(args: ProbeToolArgs): Promise<CallToolResult> {
  let connectionString: string | undefined;
  try {
    connectionString = resolveConnectionString(args.connectionString);
    const schemas = args.schemas && args.schemas.length > 0 ? args.schemas : ["public"];
    const appRoles = parseStringArray(args.appRoles);
    const subjects = parseStringArray(args.subjects);
    const ownerColumns = parseStringArray(args.ownerColumns);

    if (appRoles.length === 0) {
      return errorToolResult(new Error("appRoles is required for probes."));
    }

    const run = await runProbes({
      connectionString,
      schemas,
      appRoles,
      ownerColumns: ownerColumns.length > 0 ? ownerColumns : DEFAULT_OWNER_COLUMNS,
      ...(subjects.length > 0 ? { subjects } : {}),
      sampleLimit: 1_000,
      statementTimeoutMs: 10_000,
    });
    const report = analyzeProbeResults(run, { schemas, roles: appRoles });
    const rendered = parseFormat(args.format) === "json"
      ? renderProbeJsonReport(report)
      : renderProbeTextReport(report);
    return textResult(bound(rendered));
  } catch (error) {
    return errorToolResult(new Error(formatCliError(error, connectionString)));
  }
}

export async function handleExplainTable(args: ExplainToolArgs): Promise<CallToolResult> {
  let connectionString: string | undefined;
  try {
    connectionString = resolveConnectionString(args.connectionString);
    const tableRef = args.table.trim();
    const schema = tableRef.includes(".") ? tableRef.split(".")[0]! : "public";

    const snapshot = await loadCatalog({
      connectionString,
      schemas: [schema],
      statementTimeoutMs: 10_000,
    });
    const report = analyzeCatalog(snapshot, { schemas: [schema] });
    const table = getTableAudit(report, tableRef);
    if (!table) {
      return errorToolResult(
        new Error(`Table not found in selected schemas: ${tableRef}`),
      );
    }
    return textResult(bound(renderExplainReport(table)));
  } catch (error) {
    return errorToolResult(new Error(formatCliError(error, connectionString)));
  }
}

export async function handleToolCall(
  name: string,
  args: Record<string, unknown> | undefined,
): Promise<CallToolResult> {
  const payload = args ?? {};
  if (name === CHECK_TOOL_NAME) {
    return handleCheckRls(payload as unknown as CheckToolArgs);
  }
  if (name === PROBE_TOOL_NAME) {
    return handleProbeAccess(payload as unknown as ProbeToolArgs);
  }
  if (name === EXPLAIN_TOOL_NAME) {
    return handleExplainTable(payload as unknown as ExplainToolArgs);
  }
  return errorToolResult(new Error(`unknown tool: ${name}`));
}
