#!/usr/bin/env node
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import pg from "pg";
import { loadCatalog } from "../dist/index.js";
import { classifyExecFileError } from "./integration-helpers.js";

const execFileAsync = promisify(execFile);
const adminUrl = process.env.DATABASE_URL;
if (!adminUrl) { console.error("DATABASE_URL is required for integration tests."); process.exit(2); }
if (process.env.RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS !== "1") {
  console.error("Refusing to load destructive shared-role/schema fixtures. Set RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS=1 only for a disposable PostgreSQL database.");
  process.exit(2);
}

const password = randomBytes(24).toString("base64url");
const auditorRole = `rls_doctor_auditor_${randomBytes(8).toString("hex")}`;
const auditorUrl = withCredentials(adminUrl, auditorRole, password);
const admin = new pg.Client({ connectionString: adminUrl });
let adminConnected = false;
let auditorCreated = false;

try {
  await admin.connect();
  adminConnected = true;
  for (const fixture of ["unsafe-schema.sql", "safe-schema.sql"]) await admin.query(await readFile(new URL(`../demo/${fixture}`, import.meta.url), "utf8"));
  await admin.query(`create role ${quoteIdentifier(auditorRole)} login password '${password}'`);
  auditorCreated = true;
  const database = (await admin.query("select current_database() as name")).rows[0].name;
  await admin.query(`grant connect on database ${quoteIdentifier(database)} to ${quoteIdentifier(auditorRole)}`);
  await admin.query(`grant authenticated to ${quoteIdentifier(auditorRole)}`);
  await admin.query(
    `insert into rls_doctor_demo.orders (owner_id, total_cents) values
       ('00000000-0000-0000-0000-000000000001', 100),
       ('00000000-0000-0000-0000-000000000002', 200)`
  );
  await admin.query(
    `insert into rls_doctor_demo.tasks (owner_id, title) values
       ('00000000-0000-0000-0000-000000000001', 'mine'),
       ('00000000-0000-0000-0000-000000000002', 'not mine')`
  );
  await admin.query(
    `insert into rls_doctor_demo_safe.tasks (owner_id, title) values
       ('00000000-0000-0000-0000-000000000001', 'safe mine')`
  );

  const snapshot = await loadCatalog({ connectionString: auditorUrl, schemas: ["rls_doctor_demo", "rls_doctor_demo_safe"] });
  assertFact(snapshot.schemaPrivileges, (p) => p.schema === "rls_doctor_demo" && p.grantee === "authenticated" && p.privilege === "USAGE", "unsafe schema USAGE");
  assertFact(snapshot.relationPrivileges, (p) => p.schema === "rls_doctor_demo" && p.table === "orders" && p.grantee === "authenticated" && p.privilege === "SELECT", "explicit application grant");
  assertFact(snapshot.relationPrivileges, (p) => p.schema === "rls_doctor_demo" && p.table === "profiles" && p.grantee === "authenticated" && p.privilege === "TRUNCATE", "reachable TRUNCATE grant");
  assertFact(snapshot.defaultPrivileges, (p) => p.schema === "rls_doctor_demo" && p.grantee === "authenticated" && p.privilege === "INSERT", "dangerous default privilege");
  assertFact(snapshot.roleMemberships, (m) => m.role === "rls_doctor_demo_reader" && m.member === "authenticated" && m.inheritOption && m.setOption, "membership option direction");

  const unsafe = await runCli(["dist/cli.js", "check", "--connection", auditorUrl, "--schema", "rls_doctor_demo", "--json", "--fail-on", "high"]);
  assertEqual(unsafe.code, 1, "unsafe audit threshold exit");
  assertEqual(unsafe.stderr, "", "unsafe audit stderr");
  const unsafeReport = JSON.parse(unsafe.stdout);
  assertFinding(unsafeReport, { id: "rls-disabled-exposed", schema: "rls_doctor_demo", table: "orders", severity: "high" });
  assertFinding(unsafeReport, { id: "reachable-truncate", schema: "rls_doctor_demo", table: "profiles", severity: "high" });
  assertFinding(unsafeReport, { id: "broad-default-table-privilege", schema: "rls_doctor_demo", severity: "high" });

  const safe = await runCli(["dist/cli.js", "check", "--connection", auditorUrl, "--schema", "rls_doctor_demo_safe", "--json", "--fail-on", "high"]);
  assertEqual(safe.code, 0, "safe audit threshold exit");
  assertEqual(safe.stderr, "", "safe audit stderr");
  const safeReport = JSON.parse(safe.stdout);
  assertEqual(safeReport.summary.findings.high, 0, "safe high findings");
  assertEqual(safeReport.summary.findings.critical, 0, "safe critical findings");
  assertEqual(safeReport.summary.highestSeverity, "none", "safe highest severity");

  const unsafeProbe = await runCli(["dist/cli.js", "probe", "--connection", auditorUrl, "--schema", "rls_doctor_demo", "--app-roles", "authenticated", "--json", "--fail-on", "high"]);
  assertEqual(unsafeProbe.code, 1, "unsafe probe threshold exit");
  assertEqual(unsafeProbe.stderr, "", "unsafe probe stderr");
  const unsafeProbeReport = JSON.parse(unsafeProbe.stdout);
  assert(
    unsafeProbeReport.findings.some((finding) => finding.id === "probe-cross-owner-read" && finding.schema === "rls_doctor_demo" && finding.table === "orders" && finding.severity === "high"),
    "probe did not flag cross-owner reads on rls_doctor_demo.orders"
  );
  const ordersProbe = unsafeProbeReport.probes.find((probe) => probe.table === "orders" && probe.role === "authenticated");
  assertEqual(ordersProbe?.status, "rows", "orders probe status");
  assertEqual(ordersProbe?.distinctOwners, 2, "orders probe distinct owners");
  const tasksProbe = unsafeProbeReport.probes.find((probe) => probe.table === "tasks" && probe.role === "authenticated");
  assertEqual(tasksProbe?.status, "denied", "tasks probe requires a table privilege");

  const safeProbe = await runCli(["dist/cli.js", "probe", "--connection", auditorUrl, "--schema", "rls_doctor_demo_safe", "--app-roles", "authenticated", "--json", "--fail-on", "high"]);
  assertEqual(safeProbe.code, 0, "safe probe threshold exit");
  assertEqual(safeProbe.stderr, "", "safe probe stderr");
  const safeProbeReport = JSON.parse(safeProbe.stdout);
  assertEqual(safeProbeReport.summary.findings.high, 0, "safe probe high findings");
  const safeTasksProbe = safeProbeReport.probes.find((probe) => probe.table === "tasks" && probe.role === "authenticated");
  assertEqual(safeTasksProbe?.status, "rows", "safe tasks probe status");
  assertEqual(safeTasksProbe?.distinctOwners, 1, "safe tasks probe stays scoped to auth.uid()");

  console.log("Integration test passed.");
} catch (error) {
  console.error(redact(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
} finally {
  if (adminConnected && auditorCreated) {
    await admin.query(`drop owned by ${quoteIdentifier(auditorRole)}`).catch(reportCleanupFailure);
    await admin.query(`drop role ${quoteIdentifier(auditorRole)}`).catch(reportCleanupFailure);
  }
  await admin.end().catch(() => undefined);
}

async function runCli(args) {
  try {
    const result = await execFileAsync("node", args, { cwd: new URL("..", import.meta.url), maxBuffer: 1024 * 1024 });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) { return classifyExecFileError(error); }
}
function withCredentials(value, user, pass) { const url = new URL(value); url.username = user; url.password = pass; return url.toString(); }
function quoteIdentifier(value) { return `"${String(value).replaceAll('"', '""')}"`; }
function assertFinding(report, expected) { const findings = [...(report.schemaFindings ?? []), ...report.tables.flatMap((table) => table.findings)]; assert(findings.some((finding) => Object.entries(expected).every(([key, value]) => finding[key] === value)), `Unsafe audit did not produce ${JSON.stringify(expected)}`); }
function assertFact(values, predicate, label) { assert(values?.some(predicate), `Catalog did not expose ${label}`); }
function assertEqual(actual, expected, label) { assert(actual === expected, `${label}: expected ${expected}, received ${actual}`); }
function assert(condition, message) { if (!condition) throw new Error(message); }
function reportCleanupFailure(error) { console.error(redact(`Auditor cleanup failed: ${error.message}`)); process.exitCode = 1; }
function redact(value) { return value.replaceAll(adminUrl, "[REDACTED_DATABASE_URL]").replaceAll(auditorUrl, "[REDACTED_AUDITOR_URL]").replaceAll(auditorRole, "[REDACTED_AUDITOR_ROLE]").replaceAll(password, "[REDACTED_PASSWORD]"); }
