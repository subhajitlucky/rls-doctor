#!/usr/bin/env node
import { createRequire } from "node:module";
import { Command } from "commander";
import { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
import { analyzeProbeResults, shouldFailProbe } from "./audit/probe.js";
import type { Severity } from "./audit/types.js";
import { formatCliError, resolveConnectionString } from "./cli-support.js";
import { loadCatalog } from "./db/catalog.js";
import { runProbes } from "./db/probe.js";
import { renderJsonReport } from "./reporters/json.js";
import { renderProbeJsonReport, renderProbeTextReport } from "./reporters/probe.js";
import { renderExplainReport, renderTextReport } from "./reporters/text.js";

const program = new Command();
const require = createRequire(import.meta.url);
const packageJson = require("../package.json") as { version: string };

program
  .name("rls-doctor")
  .description("Audit Postgres and Supabase Row Level Security posture from the command line.")
  .version(packageJson.version);

program
  .command("check")
  .description("Inspect database catalog metadata and report RLS risks.")
  .option("-c, --connection <url>", "Postgres connection string. Defaults to DATABASE_URL or SUPABASE_DB_URL.")
  .option("-s, --schema <schema...>", "Schema names to audit.", ["public"])
  .option("--json", "Print machine-readable JSON output.")
  .option("--fail-on <severity>", "Exit with code 1 when this severity or higher exists.", "high")
  .option("--statement-timeout <ms>", "Catalog query timeout in milliseconds.", "10000")
  .option(
    "--app-roles <role...>",
    "Additional application roles to treat as reachable identities, for example app_user or web_user."
  )
  .action(async (options: CheckOptions) => {
    let connectionString: string | undefined;

    try {
      connectionString = resolveConnectionString(options.connection);
      const schemas = normalizeSchemas(options.schema);
      const failOn = normalizeFailOn(options.failOn);
      const statementTimeoutMs = Number(options.statementTimeout);
      const appRoles = normalizeAppRoles(options.appRoles);

      if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
        throw new Error("--statement-timeout must be a positive number.");
      }

      const snapshot = await loadCatalog({
        connectionString,
        schemas,
        statementTimeoutMs,
        ...(appRoles.length > 0 ? { appRoles } : {})
      });

      const report = analyzeCatalog(snapshot, {
        schemas,
        ...(appRoles.length > 0 ? { appRoles } : {})
      });
      process.stdout.write(options.json ? renderJsonReport(report) : renderTextReport(report));

      if (shouldFail(report, failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error, connectionString)}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("explain")
  .argument("<table>", "Table name, for example profiles or public.profiles.")
  .description("Explain the RLS posture for one table.")
  .option("-c, --connection <url>", "Postgres connection string. Defaults to DATABASE_URL or SUPABASE_DB_URL.")
  .option("-s, --schema <schema...>", "Schema names to audit.", ["public"])
  .option("--statement-timeout <ms>", "Catalog query timeout in milliseconds.", "10000")
  .option(
    "--app-roles <role...>",
    "Additional application roles to treat as reachable identities, for example app_user or web_user."
  )
  .action(async (tableRef: string, options: ExplainOptions) => {
    let connectionString: string | undefined;

    try {
      connectionString = resolveConnectionString(options.connection);
      const schemas = normalizeSchemas(options.schema);
      const statementTimeoutMs = Number(options.statementTimeout);
      const appRoles = normalizeAppRoles(options.appRoles);

      if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
        throw new Error("--statement-timeout must be a positive number.");
      }

      const snapshot = await loadCatalog({
        connectionString,
        schemas,
        statementTimeoutMs,
        ...(appRoles.length > 0 ? { appRoles } : {})
      });

      const report = analyzeCatalog(snapshot, {
        schemas,
        ...(appRoles.length > 0 ? { appRoles } : {})
      });
      const table = getTableAudit(report, tableRef);

      if (!table) {
        throw new Error(`Table not found in selected schemas: ${tableRef}`);
      }

      process.stdout.write(renderExplainReport(table));
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error, connectionString)}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("probe")
  .description("Impersonate application roles in a rolled-back transaction and report what rows they can read.")
  .option("-c, --connection <url>", "Postgres connection string. Defaults to DATABASE_URL or SUPABASE_DB_URL.")
  .option("-s, --schema <schema...>", "Schema names to probe.", ["public"])
  .option("--app-roles <role...>", "Application roles to impersonate with SET LOCAL ROLE.")
  .option(
    "--owner-columns <column...>",
    "Owner or tenant columns used for cross-owner checks.",
    ["owner_id", "user_id", "tenant_id", "account_id"]
  )
  .option("--tables <table...>", "Only probe these tables (bare or schema-qualified names).")
  .option("--sample-limit <n>", "Maximum rows sampled per probe.", "1000")
  .option("--statement-timeout <ms>", "Probe query timeout in milliseconds.", "10000")
  .option("--json", "Print machine-readable JSON output.")
  .option("--fail-on <severity>", "Exit with code 1 when this severity or higher exists.", "high")
  .action(async (options: ProbeCliOptions) => {
    let connectionString: string | undefined;

    try {
      connectionString = resolveConnectionString(options.connection);
      const schemas = normalizeSchemas(options.schema);
      const failOn = normalizeFailOn(options.failOn);
      const statementTimeoutMs = Number(options.statementTimeout);
      const sampleLimit = Number(options.sampleLimit);
      const appRoles = normalizeAppRoles(options.appRoles);

      if (appRoles.length === 0) {
        throw new Error("--app-roles is required for probes.");
      }
      if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
        throw new Error("--statement-timeout must be a positive number.");
      }
      if (!Number.isInteger(sampleLimit) || sampleLimit <= 0) {
        throw new Error("--sample-limit must be a positive integer.");
      }

      const run = await runProbes({
        connectionString,
        schemas,
        appRoles,
        ownerColumns: normalizeColumns(options.ownerColumns),
        ...(options.tables === undefined ? {} : { tables: options.tables }),
        sampleLimit,
        statementTimeoutMs
      });

      const report = analyzeProbeResults(run, { schemas, roles: appRoles });
      process.stdout.write(
        options.json ? renderProbeJsonReport(report) : renderProbeTextReport(report)
      );

      if (shouldFailProbe(report, failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error, connectionString)}\n`);
      process.exitCode = 2;
    }
  });

program.parseAsync(process.argv);

interface CheckOptions {
  connection?: string;
  schema: string[];
  json?: boolean;
  failOn: string;
  statementTimeout: string;
  appRoles?: string[];
}

interface ExplainOptions {
  connection?: string;
  schema: string[];
  statementTimeout: string;
  appRoles?: string[];
}

interface ProbeCliOptions {
  connection?: string;
  schema: string[];
  appRoles?: string[];
  ownerColumns: string[];
  tables?: string[];
  sampleLimit: string;
  statementTimeout: string;
  json?: boolean;
  failOn: string;
}

function normalizeColumns(columns: string[]): string[] {
  return [...new Set(columns.map((column) => column.trim()).filter((column) => column.length > 0))];
}

function normalizeSchemas(schemas: string[]): string[] {
  const normalized = schemas.map((schema) => schema.trim()).filter(Boolean);

  if (normalized.length === 0) {
    throw new Error("At least one schema is required.");
  }

  return [...new Set(normalized)];
}

function normalizeAppRoles(appRoles: string[] | undefined): string[] {
  return [
    ...new Set(
      (appRoles ?? [])
        .map((role) => role.trim())
        .filter((role) => role.length > 0)
    )
  ];
}

function normalizeFailOn(value: string): Severity | "none" {
  if (["info", "low", "medium", "high", "critical", "none"].includes(value)) {
    return value as Severity | "none";
  }

  throw new Error("--fail-on must be one of info, low, medium, high, critical, none.");
}
