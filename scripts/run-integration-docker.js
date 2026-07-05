#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import pg from "pg";

const execFileAsync = promisify(execFile);
const containerName = `rls-doctor-${randomUUID()}`;
const port = 55432 + Math.floor(Math.random() * 1000);
const connectionString = `postgres://postgres:postgres@127.0.0.1:${port}/rls_doctor`;

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
    `${port}:5432`,
    "postgres:16"
  ]);

  await waitForPostgres(connectionString);
  await execFileAsync("node", ["scripts/run-integration.js"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      DATABASE_URL: connectionString
    },
    maxBuffer: 1024 * 1024
  });

  console.log("Docker integration test passed.");
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

function docker(args) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, { stdio: "ignore" });
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`docker ${args.join(" ")} failed with exit code ${code}`));
      }
    });
    child.on("error", reject);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
