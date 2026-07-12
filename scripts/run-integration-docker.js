#!/usr/bin/env node
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import pg from "pg";

const execFileAsync = promisify(execFile);
const containerName = `rls-doctor-${randomUUID()}`;
const postgresVersion = process.env.POSTGRES_VERSION ?? "16";
let connectionString;

try {
  await docker([
    "run",
    "--rm",
    "-d",
    "--name",
    containerName,
    "-e",
    "POSTGRES_USER=postgres",
    "-e",
    "POSTGRES_PASSWORD=postgres",
    "-e",
    "POSTGRES_DB=rls_doctor",
    "-p",
    "127.0.0.1::5432",
    `postgres:${postgresVersion}`
  ]);

  const mapping = (await docker(["port", containerName, "5432/tcp"])).trim();
  const port = mapping.slice(mapping.lastIndexOf(":") + 1);
  if (!/^\d+$/.test(port)) throw new Error(`Docker returned an invalid PostgreSQL port mapping: ${mapping}`);
  connectionString = `postgres://postgres:postgres@127.0.0.1:${port}/rls_doctor`;
  await waitForPostgres(connectionString);
  await execFileAsync("node", ["scripts/run-integration.js"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      DATABASE_URL: connectionString,
      RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS: "1"
    },
    maxBuffer: 1024 * 1024
  });

  console.log(`Docker integration test passed on PostgreSQL ${postgresVersion}.`);
} finally {
  await docker(["rm", "-f", containerName]).catch(() => undefined);
}

async function waitForPostgres(url) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < 30_000) {
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

  throw new Error("Timed out waiting for disposable Postgres container.");
}

async function docker(args) {
  try {
    return (await execFileAsync("docker", args, { maxBuffer: 1024 * 1024 })).stdout;
  } catch (error) {
    const diagnostic = typeof error === "object" && error !== null && "stderr" in error ? String(error.stderr).trim() : String(error);
    throw new Error(`Docker command failed: ${redact(diagnostic)}`);
  }
}

function redact(value) {
  const credentialsRedacted = value.replaceAll("postgres:postgres", "[REDACTED_CREDENTIALS]");
  return connectionString ? credentialsRedacted.replaceAll(connectionString, "[REDACTED_DATABASE_URL]") : credentialsRedacted;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
