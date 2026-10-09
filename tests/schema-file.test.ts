import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import { parseSchemaSql } from "../src/audit/schema-file.js";

async function parseDemoSchema() {
  const sql = await readFile("demo/unsafe-schema.sql", "utf8");
  return parseSchemaSql(sql);
}

function cli(args: readonly string[]) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "src/cli.ts", ...args],
    { cwd: process.cwd(), encoding: "utf8", timeout: 30_000 }
  );
}

describe("offline schema files", () => {
  it("parses the demo migration into catalog state", async () => {
    const parsed = await parseDemoSchema();

    expect(parsed.schemas).toEqual(["auth", "rls_doctor_demo"]);
    expect(parsed.snapshot.tables).toMatchObject([
      { schema: "rls_doctor_demo", name: "orders", rlsEnabled: false, forceRls: false },
      { schema: "rls_doctor_demo", name: "profiles", rlsEnabled: true, forceRls: false },
      { schema: "rls_doctor_demo", name: "tasks", rlsEnabled: true, forceRls: true }
    ]);
    expect(parsed.snapshot.policies).toHaveLength(3);
    expect(parsed.snapshot.policies).toContainEqual(
      expect.objectContaining({
        table: "tasks",
        command: "ALL",
        roles: ["authenticated"],
        usingExpression: "owner_id = auth.uid()",
        checkExpression: "owner_id = auth.uid()"
      })
    );
    expect(parsed.snapshot.relationPrivileges).toContainEqual(
      expect.objectContaining({ table: "profiles", grantee: "authenticated", privilege: "TRUNCATE" })
    );
    expect(parsed.snapshot.defaultPrivileges).toContainEqual(
      expect.objectContaining({ schema: "rls_doctor_demo", grantee: "authenticated", privilege: "INSERT" })
    );
    expect(parsed.snapshot.roleMemberships).toContainEqual(
      expect.objectContaining({ role: "rls_doctor_demo_reader", member: "authenticated" })
    );
    expect(parsed.limitations).toEqual([
      "A DO block was parsed as unconditional role definitions; its conditional logic was not evaluated."
    ]);
  });

  it("produces the same findings as the live demo with an offline coverage penalty", async () => {
    const parsed = await parseDemoSchema();
    const report = analyzeCatalog(parsed.snapshot, {
      schemas: parsed.schemas,
      limitations: parsed.limitations
    });
    const findings = [...report.schemaFindings, ...report.tables.flatMap((table) => table.findings)];
    const ids = findings.map((finding) => finding.id).sort();

    expect(ids).toEqual([
      "broad-default-table-privilege",
      "force-rls-disabled",
      "public-permissive-policy",
      "public-permissive-policy",
      "public-unconditional-read",
      "public-unconditional-write",
      "reachable-truncate",
      "rls-disabled-exposed",
      "write-policy-missing-check"
    ]);
    expect(report.limitations).toHaveLength(1);
    expect(report.score).toEqual({
      value: 19,
      band: "red",
      findingPenalty: 71,
      coveragePenalty: 10
    });
  });

  it("audits a schema file from the CLI without a database", async () => {
    const result = cli([
      "check",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--json",
      "--fail-on",
      "high"
    ]);

    expect(result.status).toBe(1);
    const report = JSON.parse(result.stdout) as {
      summary: { highestSeverity: string };
      limitations: string[];
      tables: { findings: { id: string }[] }[];
    };
    expect(report.summary.highestSeverity).toBe("critical");
    expect(report.limitations).toHaveLength(1);
    expect(report.tables.flatMap((table) => table.findings).map((finding) => finding.id)).toContain(
      "rls-disabled-exposed"
    );
  });

  it("renders coverage limitations in the text report", async () => {
    const result = cli(["check", "--schema-file", "demo/unsafe-schema.sql", "--fail-on", "none"]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Coverage limitations (offline schema file)");
    expect(result.stdout).toContain("A DO block was parsed as unconditional role definitions");
    expect(result.stdout).toContain("RLS Score: 19/100");
  });

  it("rejects combining --schema-file with --connection", () => {
    const result = cli([
      "check",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--connection",
      "postgres://example"
    ]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("--schema-file and --connection cannot be combined.");
  });

  it("fails cleanly for a missing schema file", () => {
    const result = cli(["check", "--schema-file", "does-not-exist.sql"]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("does-not-exist.sql");
  });
});
