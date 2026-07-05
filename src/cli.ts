#!/usr/bin/env node
import { createRequire } from "node:module";
import { Command } from "commander";
import { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
import type { Severity } from "./audit/types.js";
import { loadCatalog } from "./db/catalog.js";
import { renderJsonReport } from "./reporters/json.js";
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
  .action(async (options: CheckOptions) => {
    try {
      const connectionString = resolveConnectionString(options.connection);
      const schemas = normalizeSchemas(options.schema);
      const failOn = normalizeFailOn(options.failOn);
      const statementTimeoutMs = Number(options.statementTimeout);

      if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
        throw new Error("--statement-timeout must be a positive number.");
      }

      const snapshot = await loadCatalog({
        connectionString,
        schemas,
        statementTimeoutMs
      });

      const report = analyzeCatalog(snapshot, { schemas });
      process.stdout.write(options.json ? renderJsonReport(report) : renderTextReport(report));

      if (shouldFail(report, failOn)) {
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatError(error)}\n`);
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
  .action(async (tableRef: string, options: ExplainOptions) => {
    try {
      const connectionString = resolveConnectionString(options.connection);
      const schemas = normalizeSchemas(options.schema);
      const statementTimeoutMs = Number(options.statementTimeout);

      if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
        throw new Error("--statement-timeout must be a positive number.");
      }

      const snapshot = await loadCatalog({
        connectionString,
        schemas,
        statementTimeoutMs
      });

      const report = analyzeCatalog(snapshot, { schemas });
      const table = getTableAudit(report, tableRef);

      if (!table) {
        throw new Error(`Table not found in selected schemas: ${tableRef}`);
      }

      process.stdout.write(renderExplainReport(table));
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatError(error)}\n`);
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
}

interface ExplainOptions {
  connection?: string;
  schema: string[];
  statementTimeout: string;
}

function resolveConnectionString(value?: string): string {
  const connectionString = value ?? process.env.DATABASE_URL ?? process.env.SUPABASE_DB_URL;

  if (!connectionString) {
    throw new Error("Missing connection string. Pass --connection or set DATABASE_URL.");
  }

  return connectionString;
}

function normalizeSchemas(schemas: string[]): string[] {
  const normalized = schemas.map((schema) => schema.trim()).filter(Boolean);

  if (normalized.length === 0) {
    throw new Error("At least one schema is required.");
  }

  return [...new Set(normalized)];
}

function normalizeFailOn(value: string): Severity | "none" {
  if (["info", "low", "medium", "high", "critical", "none"].includes(value)) {
    return value as Severity | "none";
  }

  throw new Error("--fail-on must be one of info, low, medium, high, critical, none.");
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
