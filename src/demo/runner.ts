import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import pg from "pg";
import { analyzeCatalog } from "../audit/analyzer.js";
import { analyzeProbeResults } from "../audit/probe.js";
import type { AuditReport, ProbeReport } from "../audit/types.js";
import { loadCatalog } from "../db/catalog.js";
import { runProbes } from "../db/probe.js";
import { renderProbeTextReport } from "../reporters/probe.js";
import { renderTextReport } from "../reporters/text.js";
import { DEMO_REPLAY_OUTPUT } from "./fixture.js";
import { DEMO_SEED_SQL, DEMO_UNSAFE_SCHEMA_SQL } from "./schema.js";

const execFileAsync = promisify(execFile);
const DEMO_SCHEMA = "rls_doctor_demo";
const DEMO_IMAGE = process.env.RLS_DOCTOR_DEMO_IMAGE ?? "postgres:16-alpine";
const READY_TIMEOUT_MS = 60_000;
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

async function dockerAvailable(): Promise<boolean> {
  try {
    await execFileAsync("docker", ["info"], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

async function liveDemo(): Promise<string> {
  const container = `rls-doctor-demo-${randomUUID()}`;
  let connectionString: string | undefined;

  try {
    await docker([
      "run",
      "--rm",
      "-d",
      "--name",
      container,
      "-e",
      "POSTGRES_USER=postgres",
      "-e",
      "POSTGRES_PASSWORD=postgres",
      "-e",
      "POSTGRES_DB=rls_doctor",
      "-p",
      "127.0.0.1::5432",
      DEMO_IMAGE,
    ]);

    const mapping = (await docker(["port", container, "5432/tcp"])).trim();
    const port = mapping.slice(mapping.lastIndexOf(":") + 1);
    if (!/^\d+$/.test(port)) {
      throw new Error("Docker returned an invalid PostgreSQL port mapping.");
    }
    connectionString = `postgres://postgres:postgres@127.0.0.1:${port}/rls_doctor`;
    await waitForPostgres(connectionString);

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
  } finally {
    await docker(["rm", "-f", container]).catch(() => undefined);
  }
}

async function waitForPostgres(url: string): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < READY_TIMEOUT_MS) {
    const client = new pg.Client({ connectionString: url });
    try {
      await client.connect();
      await client.query("select 1");
      await client.end();
      return;
    } catch {
      await client.end().catch(() => undefined);
      await sleep(500);
    }
  }
  throw new Error("Timed out waiting for the disposable PostgreSQL container.");
}

async function docker(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", args, { maxBuffer: 1024 * 1024 });
    return stdout;
  } catch (error) {
    const stderr = typeof error === "object" && error !== null && "stderr" in error
      ? String((error as { stderr?: string }).stderr).trim()
      : String(error);
    throw new Error(`Docker command failed: ${redact(stderr)}`);
  }
}

function redact(value: string): string {
  return value.replaceAll("postgres:postgres", "[redacted]");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
