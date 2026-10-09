import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import { parseSchemaSql } from "../src/audit/schema-file.js";
import type { AuditReport } from "../src/audit/types.js";
import { buildReceipt, verifyReceipt } from "../src/receipts/receipt.js";
import { compareShadowFindings } from "../src/shadow/runner.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function cli(args: readonly string[]) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "src/cli.ts", ...args],
    { cwd: process.cwd(), encoding: "utf8", timeout: 120_000 }
  );
}

async function demoReport(): Promise<AuditReport> {
  const sql = await readFile("demo/unsafe-schema.sql", "utf8");
  const parsed = parseSchemaSql(sql);
  return analyzeCatalog(parsed.snapshot, {
    schemas: parsed.schemas,
    limitations: parsed.limitations
  });
}

describe("shadow verification", () => {
  it("reports agreement when static and live findings match", async () => {
    const report = await demoReport();
    const comparison = compareShadowFindings(report, report);

    expect(comparison.staticOnly).toEqual([]);
    expect(comparison.liveOnly).toEqual([]);
    expect(comparison.matched).toBeGreaterThan(0);
  });

  it("reports both directions of a mismatch", async () => {
    const report = await demoReport();
    const altered: AuditReport = {
      ...report,
      tables: report.tables.map((table) =>
        table.table === "orders"
          ? { ...table, findings: [...table.findings, { ...table.findings[0]!, id: "shadow-probe-only" }] }
          : table
      )
    };

    const comparison = compareShadowFindings(report, altered);
    expect(comparison.liveOnly).toContain("shadow-probe-only rls_doctor_demo.orders");

    const reverse = compareShadowFindings(altered, report);
    expect(reverse.staticOnly).toContain("shadow-probe-only rls_doctor_demo.orders");
  });

  it("marks shadow receipts and reports the environment", async () => {
    const receipt = buildReceipt(await demoReport(), {
      source: "shadow",
      toolVersion: "test",
      shadow: true,
      additionalLimitations: ["Shadow comparison disagreed on 1 finding(s)"]
    });

    expect(receipt.shadow).toBe(true);
    expect(receipt.coverage.complete).toBe(false);
    const verification = verifyReceipt(receipt);
    expect(verification.valid).toBe(true);
    expect(verification.summary).toContain("environment: shadow (disposable world)");
    expect(verification.summary).toContain("Shadow comparison disagreed on 1 finding(s)");
  });

  it("runs shadow verification end to end when Docker is available", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-shadow-"));
    temporaryRoots.push(root);
    const receiptPath = join(root, "receipt.json");

    const result = cli([
      "shadow",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--fail-on",
      "none",
      "--receipt",
      receiptPath
    ]);

    if (result.stderr.includes("Docker is required")) {
      expect(result.status).toBe(2);
      return;
    }

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("RLS Doctor Shadow Verification");
    expect(result.stdout).toContain("Static vs live:");
    expect(result.stdout).toContain("Shadow guarantees");

    const verified = cli(["verify-receipt", receiptPath]);
    expect(verified.status).toBe(0);
    expect(verified.stdout).toContain("scope=shadow");
    expect(readFileSync(receiptPath, "utf8")).toContain('"shadow": true');
  }, 60_000);
});
