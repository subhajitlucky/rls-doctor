#!/usr/bin/env node
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import pg from "pg";
import { loadCatalog } from "../dist/index.js";

const execFileAsync = promisify(execFile);
const adminUrl = process.env.DATABASE_URL;

if (!adminUrl) {
  console.error("DATABASE_URL is required for integration tests.");
  process.exit(2);
}

const password = randomBytes(24).toString("base64url");
const auditorUrl = withCredentials(adminUrl, "rls_doctor_auditor", password);
const admin = new pg.Client({ connectionString: adminUrl });

try {
  await admin.connect();
  for (const fixture of ["unsafe-schema.sql", "safe-schema.sql"]) {
    await admin.query(await readFile(new URL(`../demo/${fixture}`, import.meta.url), "utf8"));
  }
  if ((await admin.query("select 1 from pg_roles where rolname = 'rls_doctor_auditor'")).rowCount) {
    await admin.query("drop owned by rls_doctor_auditor");
    await admin.query("drop role rls_doctor_auditor");
  }
  await admin.query(`create role rls_doctor_auditor login password '${password}'`);
  const database = (await admin.query("select current_database() as name")).rows[0].name;
  await admin.query(`grant connect on database ${quoteIdentifier(database)} to rls_doctor_auditor`);

  const snapshot = await loadCatalog({
    connectionString: auditorUrl,
    schemas: ["rls_doctor_demo", "rls_doctor_demo_safe"]
  });
  assertFact(snapshot.schemaPrivileges, (p) => p.schema === "rls_doctor_demo" && p.grantee === "authenticated" && p.privilege === "USAGE", "unsafe schema USAGE");
  assertFact(snapshot.relationPrivileges, (p) => p.schema === "rls_doctor_demo" && p.table === "orders" && p.grantee === "authenticated" && p.privilege === "SELECT", "explicit application grant");
  assertFact(snapshot.relationPrivileges, (p) => p.schema === "rls_doctor_demo" && p.table === "profiles" && p.grantee === "authenticated" && p.privilege === "TRUNCATE", "reachable TRUNCATE grant");
  assertFact(snapshot.defaultPrivileges, (p) => p.schema === "rls_doctor_demo" && p.grantee === "authenticated" && p.privilege === "INSERT", "dangerous default privilege");
  assertFact(snapshot.roleMemberships, (m) => m.role === "rls_doctor_demo_reader" && m.member === "authenticated" && m.inheritOption && m.setOption, "membership option direction");

  const unsafe = await runCli(["dist/cli.js", "check", "--connection", auditorUrl, "--schema", "rls_doctor_demo", "--json", "--fail-on", "high"]);
  assertEqual(unsafe.code, 1, "unsafe audit threshold exit");
  assertEqual(unsafe.stderr, "", "unsafe audit stderr");
  const unsafeReport = JSON.parse(unsafe.stdout);
  const unsafeIds = findingIds(unsafeReport);
  for (const id of ["rls-disabled-exposed", "reachable-truncate", "broad-default-table-privilege"]) {
    assert(unsafeIds.has(id), `Unsafe audit did not produce ${id}`);
  }

  const safe = await runCli(["dist/cli.js", "check", "--connection", auditorUrl, "--schema", "rls_doctor_demo_safe", "--json", "--fail-on", "high"]);
  assertEqual(safe.code, 0, "safe audit threshold exit");
  assertEqual(safe.stderr, "", "safe audit stderr");
  const safeReport = JSON.parse(safe.stdout);
  assertEqual(safeReport.summary.findings.high, 0, "safe high findings");
  assertEqual(safeReport.summary.findings.critical, 0, "safe critical findings");

  console.log("Integration test passed.");
} catch (error) {
  console.error(redact(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
} finally {
  await admin.end().catch(() => undefined);
}

async function runCli(args) {
  try {
    const result = await execFileAsync("node", args, { cwd: new URL("..", import.meta.url), maxBuffer: 1024 * 1024 });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && "stdout" in error && "stderr" in error) {
      return { code: Number(error.code), stdout: String(error.stdout), stderr: String(error.stderr) };
    }
    throw error;
  }
}

function withCredentials(value, user, pass) {
  const url = new URL(value);
  url.username = user;
  url.password = pass;
  return url.toString();
}

function quoteIdentifier(value) { return `"${String(value).replaceAll('"', '""')}"`; }

function findingIds(report) {
  return new Set([...(report.schemaFindings ?? []), ...report.tables.flatMap((table) => table.findings)].map((finding) => finding.id));
}

function assertFact(values, predicate, label) { assert(values?.some(predicate), `Catalog did not expose ${label}`); }
function assertEqual(actual, expected, label) { assert(actual === expected, `${label}: expected ${expected}, received ${actual}`); }
function assert(condition, message) { if (!condition) throw new Error(message); }
function redact(value) { return value.replaceAll(adminUrl, "[REDACTED_DATABASE_URL]").replaceAll(auditorUrl, "[REDACTED_AUDITOR_URL]").replaceAll(password, "[REDACTED_PASSWORD]"); }
