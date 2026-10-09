import pg from "pg";
import { analyzeCatalog } from "../audit/analyzer.js";
import { analyzeProbeResults } from "../audit/probe.js";
import type { AuditReport, ProbeReport } from "../audit/types.js";
import { loadCatalog } from "../db/catalog.js";
import { runProbes } from "../db/probe.js";
import { renderProbeTextReport } from "../reporters/probe.js";
import { renderTextReport } from "../reporters/text.js";
import { dockerAvailable, redact, withDisposablePostgres } from "../shadow/postgres.js";
import { DEMO_REPLAY_OUTPUT } from "./fixture.js";
import { DEMO_SEED_SQL, DEMO_UNSAFE_SCHEMA_SQL } from "./schema.js";

const DEMO_SCHEMA = "rls_doctor_demo";
const OWNER_COLUMNS = ["owner_id", "user_id", "tenant_id", "account_id"];

export interface DemoOutcome {
  output: string;
  live: boolean;
}

export interface DemoHooks {
  isDockerAvailable: () => Promise<boolean>;
  runLiveDemo: () => Promise<string>;
}

/**
 * Zero-config demo: starts a disposable PostgreSQL container, applies the
 * intentionally unsafe demo schema, runs the catalog audit and a rolled-back
 * probe, and always removes the container. Falls back to a recorded run when
 * Docker is unavailable so the demo never fails a fresh machine.
 */
export async function runDemo(hooks: Partial<DemoHooks> = {}): Promise<DemoOutcome> {
  const isDockerAvailable = hooks.isDockerAvailable ?? dockerAvailable;
  const runLiveDemo = hooks.runLiveDemo ?? liveDemo;

  if (!(await isDockerAvailable())) {
    return { output: replayOutput("Docker was not found on this machine."), live: false };
  }

  try {
    return { output: await runLiveDemo(), live: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      output: replayOutput(`The live demo could not run: ${redact(message)}`),
      live: false,
    };
  }
}

export function renderDemoOutput(audit: AuditReport, probe: ProbeReport): string {
  const leak = probe.findings.find((finding) => finding.id === "probe-cross-owner-read");
  const lines: string[] = [
    "RLS Doctor Demo",
    "===============",
    "",
    "Started a disposable PostgreSQL container, applied the intentionally unsafe demo schema, and seeded two users' rows.",
    "",
    renderTextReport(audit).trimEnd(),
    "",
    renderProbeTextReport(probe).trimEnd(),
    "",
  ];

  if (leak !== undefined) {
    lines.push(`PROVEN: ${leak.title}.`);
    lines.push("The probe impersonated the app role inside a read-only transaction and rolled back.");
  }

  lines.push("The container was removed. No database was modified.");
  return `${lines.join("\n")}\n`;
}

function replayOutput(reason: string): string {
  return [
    `Note: ${reason}`,
    "Showing a recorded run instead. Install Docker to see it live.",
    "",
    DEMO_REPLAY_OUTPUT.trimEnd(),
    "",
  ].join("\n");
}

async function liveDemo(): Promise<string> {
  return withDisposablePostgres(async (connectionString) => {
    const admin = new pg.Client({ connectionString });
    await admin.connect();
    try {
      await admin.query(DEMO_UNSAFE_SCHEMA_SQL);
      await admin.query(DEMO_SEED_SQL);
    } finally {
      await admin.end().catch(() => undefined);
    }

    const snapshot = await loadCatalog({ connectionString, schemas: [DEMO_SCHEMA] });
    const audit = analyzeCatalog(snapshot, { schemas: [DEMO_SCHEMA] });
    const run = await runProbes({
      connectionString,
      schemas: [DEMO_SCHEMA],
      appRoles: ["authenticated"],
      ownerColumns: OWNER_COLUMNS,
    });
    const probe = analyzeProbeResults(run, { schemas: [DEMO_SCHEMA], roles: ["authenticated"] });

    return renderDemoOutput(audit, probe);
  });
}
