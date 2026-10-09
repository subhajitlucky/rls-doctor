import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { readFile } from "node:fs/promises";
import { analyzeCatalog, getTableAudit } from "../audit/analyzer.js";
import { analyzeProbeResults } from "../audit/probe.js";
import { parseSchemaSql } from "../audit/schema-file.js";
import { formatCliError, resolveConnectionString } from "../cli-support.js";
import { loadCatalog } from "../db/catalog.js";
import { runProbes } from "../db/probe.js";
import { buildProofArtifact, buildProofClaims } from "../proof/runner.js";
import { planRepair, renderPatch } from "../repair/repair.js";
import { verifyRepairStatic } from "../repair/verify.js";
import { MCP_SERVER_VERSION } from "./server.js";
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
  PROVE_TOOL_NAME,
  REPAIR_TOOL_NAME,
  cutUtf8Safe,
  parseFormat,
  parseProveToolArgs,
  parseRepairToolArgs,
  parseStringArray,
  type CheckToolArgs,
  type ExplainToolArgs,
  type ProbeToolArgs,
  type ProveToolArgs,
  type RepairToolArgs,
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

export async function handleProveIsolation(args: ProveToolArgs): Promise<CallToolResult> {
  try {
    const contents = await Promise.all(args.schemaFiles.map((file) => readFile(file, "utf8")));
    const parsed = parseSchemaSql(contents.join("\n"));
    const wanted = args.table;
    const tables = wanted === undefined
      ? parsed.snapshot.tables
      : parsed.snapshot.tables.filter((table) =>
          wanted.includes(".") ? `${table.schema}.${table.name}` === wanted : table.name === wanted
        );
    const claims = buildProofClaims(tables, parsed.snapshot.policies, args.roles);
    const artifact = buildProofArtifact(
      claims,
      { schemaFiles: args.schemaFiles, schemas: parsed.schemas, roles: args.roles },
      parsed.limitations,
      MCP_SERVER_VERSION,
    );
    return textResult(bound(`${JSON.stringify(artifact, null, 2)}\n`));
  } catch (error) {
    return errorToolResult(new Error(formatCliError(error)));
  }
}

export async function handleProposeRepair(args: RepairToolArgs): Promise<CallToolResult> {
  try {
    const contents = await Promise.all(args.schemaFiles.map((file) => readFile(file, "utf8")));
    const originalSql = contents.join("\n");
    const parsed = parseSchemaSql(originalSql);
    const table = parsed.snapshot.tables.find((entry) =>
      args.table.includes(".") ? `${entry.schema}.${entry.name}` === args.table : entry.name === args.table
    );
    if (table === undefined) {
      return errorToolResult(new Error(`Table not found in the schema files: ${args.table}`));
    }
    const plan = planRepair(table, args.roles);
    if (plan === undefined) {
      return textResult(`${JSON.stringify({
        status: "not-applicable",
        table: `${table.schema}.${table.name}`,
        reason: "row level security is already enabled; no repair template applies",
      }, null, 2)}\n`);
    }
    const verification = verifyRepairStatic(originalSql, plan, args.roles);
    const payload = {
      status: verification.status,
      table: `${table.schema}.${table.name}`,
      patch: verification.status === "verified" ? renderPatch(plan) : null,
      verification,
      note:
        "Static verification only: the CLI `fix` command adds live shadow verification " +
        "and writes the patch. Nothing was written and nothing was applied.",
    };
    return textResult(bound(`${JSON.stringify(payload, null, 2)}\n`));
  } catch (error) {
    return errorToolResult(new Error(formatCliError(error)));
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
  if (name === PROVE_TOOL_NAME) {
    return handleProveIsolation(parseProveToolArgs(payload));
  }
  if (name === REPAIR_TOOL_NAME) {
    return handleProposeRepair(parseRepairToolArgs(payload));
  }
  return errorToolResult(new Error(`unknown tool: ${name}`));
}
