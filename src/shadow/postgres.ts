import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import pg from "pg";

const execFileAsync = promisify(execFile);
const DEMO_IMAGE = process.env.RLS_DOCTOR_DEMO_IMAGE ?? "postgres:16-alpine";
const READY_TIMEOUT_MS = 60_000;

/**
 * Start a disposable PostgreSQL container, hand its connection string to the
 * callback, and always remove the container afterwards. Used by `demo` and
 * `shadow`; it never touches any database other than its own container.
 */
export async function withDisposablePostgres<T>(
  action: (connectionString: string) => Promise<T>,
): Promise<T> {
  const container = `rls-doctor-shadow-${randomUUID()}`;
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
    const connectionString = `postgres://postgres:postgres@127.0.0.1:${port}/rls_doctor`;
    await waitForPostgres(connectionString);
    return await action(connectionString);
  } finally {
    await docker(["rm", "-f", container]).catch(() => undefined);
  }
}

export async function dockerAvailable(): Promise<boolean> {
  try {
    await execFileAsync("docker", ["info"], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

export async function docker(args: string[]): Promise<string> {
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

export function redact(value: string): string {
  return value.replaceAll("postgres:postgres", "[redacted]");
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
