#!/usr/bin/env node
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import pg from "pg";

const execFileAsync = promisify(execFile);
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.error("DATABASE_URL is required for integration tests.");
  process.exit(2);
}

const client = new pg.Client({ connectionString });

try {
  await client.connect();
  const sql = await readFile(new URL("../demo/unsafe-schema.sql", import.meta.url), "utf8");
  await client.query(sql);
  await client.end();

  const check = await runCli([
    "dist/cli.js",
    "check",
    "--connection",
    connectionString,
    "--schema",
    "rls_doctor_demo",
    "--fail-on",
    "none"
  ]);

  assertIncludes(check.stdout, "highest risk CRITICAL");
  assertIncludes(check.stdout, "[MEDIUM] Row Level Security is disabled");
  assertIncludes(check.stdout, "[CRITICAL] Anonymous-style role can write rows too broadly");

  const explain = await runCli([
    "dist/cli.js",
    "explain",
    "rls_doctor_demo.profiles",
    "--connection",
    connectionString,
    "--schema",
    "rls_doctor_demo"
  ]);

  assertIncludes(explain.stdout, "RLS Doctor Explain: rls_doctor_demo.profiles");
  assertIncludes(explain.stdout, "Risk: CRITICAL");
  assertIncludes(explain.stdout, "Next steps");

  console.log("Integration test passed.");
} catch (error) {
  try {
    await client.end();
  } catch {
    // Ignore close errors while reporting the original failure.
  }

  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

async function runCli(args) {
  return execFileAsync("node", args, {
    cwd: new URL("..", import.meta.url),
    maxBuffer: 1024 * 1024
  });
}

function assertIncludes(value, expected) {
  if (!value.includes(expected)) {
    throw new Error(`Expected output to include "${expected}".\n\nActual output:\n${value}`);
  }
}
