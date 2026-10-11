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
import { MCP_SERVER_NAME, MCP_SERVER_VERSION } from "./server.js";
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
  DESCRIBE_TOOL_NAME,
  EXPLAIN_TOOL_NAME,
  MAX_TOOL_PAYLOAD_BYTES,
  PROBE_TOOL_NAME,
  PROVE_TOOL_NAME,
  REPAIR_TOOL_NAME,
  TOOL_DEFINITIONS,
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

export type ToolErrorCode =
  | "connection-required"
  | "connection-failed"
  | "invalid-arguments"
  | "not-found"
  | "internal-error";

const NEXT_ACTIONS: Record<ToolErrorCode, string> = {
  "connection-required":
    "Set DATABASE_URL or SUPABASE_DB_URL (prefer read-only credentials), or pass " +
    "connectionString. Ask the user before connecting to a live database.",
  "connection-failed":
    "Verify the database is reachable, the credentials are valid and read-only, and " +
    "the requested schemas exist. Never print the connection string.",
  "invalid-arguments":
    "Inspect the tool input schema and retry with the required arguments, or call " +
    "describe_capabilities for the full contract.",
  "not-found":
    "Call check_rls to list audited tables, use a schema-qualified name, or verify " +
    "the schema file paths exist.",
  "internal-error":
    "Retry once; if it persists, report the tool name and arguments (never the " +
    "connection string) before trying a different approach.",
};

/** Structured, machine-branchable tool failure. Never echoes credentials. */
export function toolError(code: ToolErrorCode, message: string): CallToolResult {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { error: { code, message, nextAction: NEXT_ACTIONS[code] } },
          null,
          2,
        ),
      },
    ],
  };
}

/** Map an unexpected failure to a structured error result. */
export function errorToolResult(error: unknown): CallToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return toolError("internal-error", `rls-doctor: ${message}`);
}

function requireConnection(
  value: string | undefined,
): { connectionString: string } | { error: CallToolResult } {
  try {
    return { connectionString: resolveConnectionString(value) };
  } catch (error) {
    return { error: toolError("connection-required", formatCliError(error)) };
  }
}

function bound(text: string): string {
  return cutUtf8Safe(text, MAX_TOOL_PAYLOAD_BYTES);
}

export async function handleCheckRls(args: CheckToolArgs): Promise<CallToolResult> {
  const connection = requireConnection(args.connectionString);
  if ("error" in connection) return connection.error;
  const { connectionString } = connection;
  try {
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
    return toolError("connection-failed", formatCliError(error, connectionString));
  }
}

export async function handleProbeAccess(args: ProbeToolArgs): Promise<CallToolResult> {
  const connection = requireConnection(args.connectionString);
  if ("error" in connection) return connection.error;
  const { connectionString } = connection;
  try {
    const schemas = args.schemas && args.schemas.length > 0 ? args.schemas : ["public"];
    const appRoles = parseStringArray(args.appRoles);
    const subjects = parseStringArray(args.subjects);
    const ownerColumns = parseStringArray(args.ownerColumns);

    if (appRoles.length === 0) {
      return toolError("invalid-arguments", "appRoles is required for probes.");
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
    return toolError("connection-failed", formatCliError(error, connectionString));
  }
}

export async function handleExplainTable(args: ExplainToolArgs): Promise<CallToolResult> {
  const connection = requireConnection(args.connectionString);
  if ("error" in connection) return connection.error;
  const { connectionString } = connection;
  try {
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
      return toolError("not-found", `Table not found in selected schemas: ${tableRef}`);
    }
    return textResult(bound(renderExplainReport(table)));
  } catch (error) {
    return toolError("connection-failed", formatCliError(error, connectionString));
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
    return fileError(error);
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
      return toolError("not-found", `Table not found in the schema files: ${args.table}`);
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
    return fileError(error);
  }
}

function fileError(error: unknown): CallToolResult {
  const missing = (error as { code?: unknown } | null)?.code === "ENOENT";
  return toolError(
    missing ? "not-found" : "invalid-arguments",
    formatCliError(error),
  );
}

/** Describe the server contract so agents do not have to discover it by trial. */
export function handleDescribeCapabilities(): CallToolResult {
  return textResult(
    `${JSON.stringify(
      {
        server: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
        transport: "stdio",
        tools: TOOL_DEFINITIONS.map(({ name, description, annotations }) => ({
          name,
          description,
          mode: name === CHECK_TOOL_NAME || name === PROBE_TOOL_NAME || name === EXPLAIN_TOOL_NAME
            ? "live-database"
            : "offline",
          annotations,
        })),
        guarantees: [
          "Every tool is read-only against the target database and never mutates it.",
          "probe_access impersonates roles inside begin ... read only and always rolls back.",
          "prove_isolation and propose_repair run fully offline from schema files.",
          "propose_repair returns a patch only when static verification flips every witness to proved.",
          "Errors are structured: { error: { code, message, nextAction } }.",
        ],
        requiresUserApproval: [
          "Any live-database tool (check_rls, probe_access, explain_table) when a connection string is configured or provided: ask the user before connecting, and prefer read-only credentials.",
        ],
        coverageLimitations: [
          "Catalog analysis cannot prove application-level authorization.",
          "Offline parsing does not evaluate DO block logic or ALTER POLICY statements.",
          "Probe evidence depends on seeded data; empty tables prove nothing.",
          "Live catalog analysis covers only the selected schemas.",
        ],
        usage:
          "Run check_rls after schema changes or before release; probe_access with " +
          "appRoles and two or more subjects proves cross-tenant reads; " +
          "prove_isolation and propose_repair work offline from migration files; " +
          "explain_table covers one table in depth. A clean check under offline " +
          "coverage limitations is not a full clean result.",
      },
      null,
      2,
    )}\n`,
  );
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
  if (name === DESCRIBE_TOOL_NAME) {
    return handleDescribeCapabilities();
  }
  return toolError(
    "invalid-arguments",
    `Unknown tool "${name}". Available tools: ${TOOL_DEFINITIONS.map((tool) => tool.name).join(", ")}.`,
  );
}
