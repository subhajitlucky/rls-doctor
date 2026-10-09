#!/usr/bin/env node
import { createRequire } from "node:module";
import { readFile, writeFile } from "node:fs/promises";
import { Command } from "commander";
import { analyzeCatalog, getTableAudit, shouldFail } from "./audit/analyzer.js";
import { loadBaseline } from "./audit/baseline.js";
import { compareWithBaseline } from "./audit/fingerprint.js";
import { analyzeProbeResults, shouldFailProbe } from "./audit/probe.js";
import { parseSchemaSql } from "./audit/schema-file.js";
import type { AuditReport, Severity } from "./audit/types.js";
import { formatCliError, resolveConnectionString } from "./cli-support.js";
import { loadCatalog } from "./db/catalog.js";
import { runProbes } from "./db/probe.js";
import { renderJsonReport } from "./reporters/json.js";
import { renderProbeJsonReport, renderProbeTextReport } from "./reporters/probe.js";
import { renderSarifReport } from "./reporters/sarif.js";
import { renderScoreOutput } from "./reporters/score.js";
import { renderExplainReport, renderTextReport } from "./reporters/text.js";
import { buildReceipt, serializeReceipt, verifyReceipt } from "./receipts/receipt.js";
import { runShadow } from "./shadow/runner.js";

const program = new Command();
const require = createRequire(import.meta.url);
const packageJson = require("../package.json") as { version: string };
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  .option("--format <format>", "Output format: text, json, or sarif.")
  .option("--baseline <path>", "Compare findings with a prior JSON report; only new findings can fail the run.")
  .option("--update-baseline", "Write the current report to the --baseline path and exit 0.", false)
  .option("--schema-file <path>", "Audit a SQL schema or migration file offline; no database connection is used.")
  .option("--receipt <path>", "Write a portable coverage receipt to this path.")
  .option("--receipt-key <path>", "Sign the receipt with an Ed25519 private key (PEM).")
  .option("--score", "Print only the RLS Score, for example RLS Score: 34/100.", false)
  .option("--badge", "Print a shields.io badge URL for the RLS Score.", false)
  .option("--statement-timeout <ms>", "Catalog query timeout in milliseconds.", "10000")
  .option(
    "--app-roles <role...>",
    "Additional application roles to treat as reachable identities, for example app_user or web_user."
  )
  .action(async (options: CheckOptions) => {
    let connectionString: string | undefined;

    try {
      const schemas = normalizeSchemas(options.schema);
      const failOn = normalizeFailOn(options.failOn);
      const format = parseFormat(options);
      const appRoles = normalizeAppRoles(options.appRoles);

      if (options.updateBaseline === true && options.baseline === undefined) {
        throw new Error("--update-baseline requires --baseline <path>.");
      }

      const baseline =
        options.baseline === undefined || options.updateBaseline === true
          ? undefined
          : await loadBaseline(options.baseline);

      let report: AuditReport;

      if (options.schemaFile !== undefined) {
        if (options.connection !== undefined) {
          throw new Error("--schema-file and --connection cannot be combined.");
        }
        const sql = await readFile(options.schemaFile, "utf8");
        const parsed = parseSchemaSql(sql);
        report = analyzeCatalog(parsed.snapshot, {
          schemas: parsed.schemas,
          ...(appRoles.length > 0 ? { appRoles } : {}),
          limitations: parsed.limitations
        });
      } else {
        connectionString = resolveConnectionString(options.connection);
        const statementTimeoutMs = Number(options.statementTimeout);
        if (!Number.isFinite(statementTimeoutMs) || statementTimeoutMs <= 0) {
          throw new Error("--statement-timeout must be a positive number.");
        }

        const snapshot = await loadCatalog({
          connectionString,
          schemas,
          statementTimeoutMs,
          ...(appRoles.length > 0 ? { appRoles } : {})
        });

        report = analyzeCatalog(snapshot, {
          schemas,
          ...(appRoles.length > 0 ? { appRoles } : {})
        });
      }

      if (baseline !== undefined) {
        const comparison = compareWithBaseline(baseline.fingerprints, report);
        report.baseline = {
          new: comparison.new.length,
          unchanged: comparison.unchanged.length,
          resolved: comparison.resolved.length
        };
      }

      if (options.updateBaseline === true && options.baseline !== undefined) {
        await writeFile(options.baseline, renderJsonReport(report), "utf8");
        process.stderr.write(`rls-doctor: baseline updated at ${options.baseline}\n`);
        return;
      }

      if (options.receipt !== undefined) {
        const privateKeyPem =
          options.receiptKey === undefined ? undefined : await readFile(options.receiptKey, "utf8");
        const receipt = buildReceipt(report, {
          source: options.schemaFile === undefined ? "catalog" : "schema-file",
          toolVersion: packageJson.version,
          ...(privateKeyPem === undefined ? {} : { privateKeyPem })
        });
        await writeFile(options.receipt, serializeReceipt(receipt), "utf8");
        process.stderr.write(`rls-doctor: receipt written to ${options.receipt}\n`);
      }

      const scoreOutput = renderScoreOutput(report, options);
      const output = scoreOutput ?? (
        format === "json"
          ? renderJsonReport(report)
          : format === "sarif"
            ? renderSarifReport(report, { toolVersion: packageJson.version })
            : renderTextReport(report)
      );
      process.stdout.write(output);

      const baselineFingerprints =
        baseline === undefined ? undefined : new Set(baseline.fingerprints);
      if (
        shouldFail(
          report,
          failOn,
          baselineFingerprints === undefined ? {} : { baselineFingerprints }
        )
      ) {
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
    "--subjects <uuid...>",
    "Simulate these user IDs through Supabase-compatible request.jwt.claims while probing."
  )
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
      const subjects = normalizeSubjects(options.subjects);

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
        ...(subjects.length > 0 ? { subjects } : {}),
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

program
  .command("demo")
  .description("Start a disposable PostgreSQL, prove a cross-tenant leak, and clean up. No configuration needed.")
  .action(async () => {
    try {
      const { runDemo } = await import("./demo/runner.js");
      const outcome = await runDemo();
      process.stdout.write(outcome.output);
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error)}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("verify-receipt")
  .argument("<file>", "Path to a receipt JSON file.")
  .description("Verify a coverage receipt: digest integrity, optional signature, and coverage summary.")
  .action(async (file: string) => {
    try {
      const text = await readFile(file, "utf8");
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        process.stderr.write(`rls-doctor: ${file} is not valid JSON\n`);
        process.exitCode = 2;
        return;
      }
      const verification = verifyReceipt(parsed);
      if (!verification.valid) {
        for (const reason of verification.reasons) {
          process.stderr.write(`rls-doctor: receipt invalid: ${reason}\n`);
        }
        process.exitCode = 2;
        return;
      }
      process.stdout.write(verification.summary);
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error)}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("shadow")
  .description("Replay migration files in a disposable PostgreSQL and compare static vs live analysis.")
  .option(
    "--schema-file <path...>",
    "SQL schema or migration files to replay, in order; repeatable or space-separated."
  )
  .option("--seed <path>", "Optional seed SQL; when present, probe runs too.")
  .option(
    "--app-roles <role...>",
    "Roles to probe when --seed is provided.",
    ["authenticated"]
  )
  .option("--fail-on <severity>", "Exit with code 1 when live findings reach this severity.", "high")
  .option("--receipt <path>", "Write a portable coverage receipt (marked as shadow).")
  .option("--receipt-key <path>", "Sign the receipt with an Ed25519 private key (PEM).")
  .action(async (options: ShadowCliOptions) => {
    try {
      const failOn = normalizeFailOn(options.failOn);
      const privateKeyPem =
        options.receiptKey === undefined ? undefined : await readFile(options.receiptKey, "utf8");
      const outcome = await runShadow({
        schemaFiles: options.schemaFile ?? [],
        ...(options.seed === undefined ? {} : { seedFile: options.seed }),
        ...(options.appRoles === undefined ? {} : { appRoles: normalizeAppRoles(options.appRoles) }),
        failOn,
        toolVersion: packageJson.version,
        ...(options.receipt === undefined ? {} : { receipt: options.receipt }),
        ...(privateKeyPem === undefined ? {} : { receiptKeyPem: privateKeyPem })
      });
      process.stdout.write(outcome.output);
      process.exitCode = outcome.exitCode;
    } catch (error) {
      process.stderr.write(`rls-doctor: ${formatCliError(error)}\n`);
      process.exitCode = 2;
    }
  });

program
  .command("mcp")
  .description("Serve read-only RLS audits over the Model Context Protocol on stdio.")
  .action(async () => {
    const { startMcpStdioServer } = await import("./mcp/server.js");
    await startMcpStdioServer();
  });

program.parseAsync(process.argv);

interface CheckOptions {
  connection?: string;
  schema: string[];
  json?: boolean;
  failOn: string;
  statementTimeout: string;
  appRoles?: string[];
  format?: string;
  baseline?: string;
  updateBaseline?: boolean;
  schemaFile?: string;
  receipt?: string;
  receiptKey?: string;
  score?: boolean;
  badge?: boolean;
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
  subjects?: string[];
  ownerColumns: string[];
  tables?: string[];
  sampleLimit: string;
  statementTimeout: string;
  json?: boolean;
  failOn: string;
}

interface ShadowCliOptions {
  schemaFile?: string[];
  seed?: string;
  appRoles?: string[];
  failOn: string;
  receipt?: string;
  receiptKey?: string;
}


function normalizeSubjects(subjects: string[] | undefined): string[] {
  const normalized = [
    ...new Set((subjects ?? []).map((subject) => subject.trim()).filter((subject) => subject.length > 0))
  ];

  for (const subject of normalized) {
    if (!UUID_PATTERN.test(subject)) {
      throw new Error(`--subjects expects UUID values, received "${subject}".`);
    }
  }

  return normalized;
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

type OutputFormat = "text" | "json" | "sarif";

function parseFormat(options: CheckOptions): OutputFormat {
  if (options.format !== undefined && !["text", "json", "sarif"].includes(options.format)) {
    throw new Error("--format must be one of text, json, sarif.");
  }

  if (options.json === true && options.format !== undefined && options.format !== "json") {
    throw new Error("--json conflicts with the selected --format value.");
  }

  return options.json === true
    ? "json"
    : ((options.format as OutputFormat | undefined) ?? "text");
}

function normalizeFailOn(value: string): Severity | "none" {
  if (["info", "low", "medium", "high", "critical", "none"].includes(value)) {
    return value as Severity | "none";
  }

  throw new Error("--fail-on must be one of info, low, medium, high, critical, none.");
}
