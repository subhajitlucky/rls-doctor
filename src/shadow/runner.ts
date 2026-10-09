import { readFile, writeFile } from "node:fs/promises";
import pg from "pg";
import { analyzeCatalog, shouldFail } from "../audit/analyzer.js";
import { analyzeProbeResults } from "../audit/probe.js";
import { parseSchemaSql } from "../audit/schema-file.js";
import type { AuditReport, ProbeReport, Severity } from "../audit/types.js";
import { loadCatalog } from "../db/catalog.js";
import { runProbes } from "../db/probe.js";
import { buildReceipt, serializeReceipt } from "../receipts/receipt.js";
import { renderProbeTextReport } from "../reporters/probe.js";
import { renderTextReport } from "../reporters/text.js";
import { dockerAvailable, withDisposablePostgres } from "./postgres.js";

const OWNER_COLUMNS = ["owner_id", "user_id", "tenant_id", "account_id"];
const MAX_COMPARISON_LINES = 10;

export interface ShadowOptions {
  schemaFiles: string[];
  seedFile?: string;
  appRoles?: string[];
  failOn: Severity | "none";
  toolVersion: string;
  receipt?: string;
  receiptKeyPem?: string;
}

export interface ShadowOutcome {
  output: string;
  exitCode: 0 | 1 | 2;
}

export interface ShadowComparison {
  matched: number;
  staticOnly: string[];
  liveOnly: string[];
}

function findingKeys(report: AuditReport): Set<string> {
  const keys = new Set<string>();
  for (const finding of report.schemaFindings) {
    keys.add(`${finding.id} ${finding.schema ?? ""}`);
  }
  for (const table of report.tables) {
    for (const finding of table.findings) {
      keys.add(`${finding.id} ${finding.schema}.${finding.table}`);
    }
  }
  return keys;
}

/**
 * Compare the offline (static) analysis of a migration stream with the live
 * catalog analysis of the same SQL replayed in a disposable PostgreSQL. A
 * mismatch means the parser and the database disagree — a coverage fact, not
 * a guessed finding.
 */
export function compareShadowFindings(
  staticReport: AuditReport,
  liveReport: AuditReport,
): ShadowComparison {
  const staticKeys = findingKeys(staticReport);
  const liveKeys = findingKeys(liveReport);
  return {
    matched: [...staticKeys].filter((key) => liveKeys.has(key)).length,
    staticOnly: [...staticKeys].filter((key) => !liveKeys.has(key)).sort(),
    liveOnly: [...liveKeys].filter((key) => !staticKeys.has(key)).sort(),
  };
}

/**
 * Mirror World: replay migration files in a disposable PostgreSQL container,
 * run the real catalog audit (and probe when seed data is provided), compare
 * static vs live analysis, and always remove the container. The audited
 * database is never touched.
 */
export async function runShadow(options: ShadowOptions): Promise<ShadowOutcome> {
  if (options.schemaFiles.length === 0) {
    throw new Error("--schema-file is required for shadow verification.");
  }
  if (!(await dockerAvailable())) {
    throw new Error(
      "Docker is required for shadow verification (a disposable PostgreSQL container).",
    );
  }

  const fileContents = await Promise.all(options.schemaFiles.map((file) => readFile(file, "utf8")));
  const parsed = parseSchemaSql(fileContents.join("\n"));
  const staticReport = analyzeCatalog(parsed.snapshot, {
    schemas: parsed.schemas,
    limitations: parsed.limitations,
  });

  const live = await withDisposablePostgres(async (connectionString) => {
    const admin = new pg.Client({ connectionString });
    await admin.connect();
    try {
      for (const content of fileContents) {
        await admin.query(content);
      }
      if (options.seedFile !== undefined) {
        await admin.query(await readFile(options.seedFile, "utf8"));
      }
    } finally {
      await admin.end().catch(() => undefined);
    }

    const schemas = parsed.schemas;
    const snapshot = await loadCatalog({ connectionString, schemas });
    const liveReport = analyzeCatalog(snapshot, { schemas });

    let probe: ProbeReport | undefined;
    if (options.seedFile !== undefined) {
      const roles = options.appRoles ?? ["authenticated"];
      const run = await runProbes({
        connectionString,
        schemas,
        appRoles: roles,
        ownerColumns: OWNER_COLUMNS,
      });
      probe = analyzeProbeResults(run, { schemas, roles });
    }

    return { liveReport, probe };
  });

  const comparison = compareShadowFindings(staticReport, live.liveReport);
  const output = renderShadowOutput(options, live.liveReport, live.probe, comparison);
  const exitCode: 0 | 1 = shouldFail(live.liveReport, options.failOn) ? 1 : 0;

  if (options.receipt !== undefined) {
    const disagreements = comparison.staticOnly.length + comparison.liveOnly.length;
    const receipt = buildReceipt(live.liveReport, {
      source: "shadow",
      toolVersion: options.toolVersion,
      shadow: true,
      ...(disagreements === 0
        ? {}
        : {
            additionalLimitations: [
              `Shadow comparison disagreed on ${disagreements} finding(s): ` +
              `static-only [${comparison.staticOnly.slice(0, 3).join("; ")}], ` +
              `live-only [${comparison.liveOnly.slice(0, 3).join("; ")}]`,
            ],
          }),
      ...(options.receiptKeyPem === undefined ? {} : { privateKeyPem: options.receiptKeyPem }),
    });
    await writeFile(options.receipt, serializeReceipt(receipt), "utf8");
    process.stderr.write(`rls-doctor: receipt written to ${options.receipt}\n`);
  }

  return { output, exitCode };
}

function renderShadowOutput(
  options: ShadowOptions,
  liveReport: AuditReport,
  probe: ProbeReport | undefined,
  comparison: ShadowComparison,
): string {
  const lines: string[] = [
    "RLS Doctor Shadow Verification",
    "==============================",
    "",
    `Replayed ${options.schemaFiles.length} migration file(s)` +
    `${options.seedFile === undefined ? "" : " plus seed data"} in a disposable PostgreSQL container.`,
    "",
    `Static vs live: ${comparison.matched} finding(s) matched, ` +
    `${comparison.staticOnly.length} static-only, ${comparison.liveOnly.length} live-only.`,
  ];

  for (const key of comparison.staticOnly.slice(0, MAX_COMPARISON_LINES)) {
    lines.push(`  static-only: ${key}`);
  }
  for (const key of comparison.liveOnly.slice(0, MAX_COMPARISON_LINES)) {
    lines.push(`  live-only:   ${key}`);
  }
  if (comparison.staticOnly.length + comparison.liveOnly.length === 0) {
    lines.push("  The offline parser and the database agree on every finding.");
  }

  lines.push("", renderTextReport(liveReport).trimEnd(), "");

  if (probe !== undefined) {
    lines.push(renderProbeTextReport(probe).trimEnd(), "");
  }

  lines.push(
    "Shadow guarantees: the container was removed, the audit database was never touched," +
    `${options.seedFile === undefined ? " and no probe ran (no seed data)." : " and every probe transaction rolled back."}`,
  );
  return `${lines.join("\n")}\n`;
}
