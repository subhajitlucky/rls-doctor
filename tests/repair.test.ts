import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseSchemaSql } from "../src/audit/schema-file.js";
import { canonicalJson } from "../src/receipts/receipt.js";
import { ownerColumnFor, planRepair, renderPatch } from "../src/repair/repair.js";
import { buildRepairReceipt, verifyRepairStatic } from "../src/repair/verify.js";

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

async function demo() {
  const sql = await readFile("demo/unsafe-schema.sql", "utf8");
  return { sql, parsed: parseSchemaSql(sql) };
}

describe("repair planning", () => {
  it("captures columns and plans an ownership repair", async () => {
    const { parsed } = await demo();
    const orders = parsed.snapshot.tables.find((table) => table.name === "orders")!;

    expect(orders.columns).toContain("owner_id");
    expect(ownerColumnFor(orders)).toBe("owner_id");

    const plan = planRepair(orders, ["authenticated"])!;
    expect(plan.statements).toHaveLength(2);
    expect(plan.statements[0]).toContain("enable row level security");
    expect(plan.statements[1]).toContain('using ("owner_id" = auth.uid())');
    expect(plan.statements[1]).toContain('with check ("owner_id" = auth.uid())');
    expect(renderPatch(plan)).toContain("-- Ownership column: owner_id");
  });

  it("falls back to enable-only with a note when no owner column exists", () => {
    const table = {
      schema: "public",
      name: "notes",
      rlsEnabled: false,
      forceRls: false,
      isPartitioned: false,
      estimatedRows: null,
      columns: ["id", "body"],
    };
    const plan = planRepair(table, ["authenticated"])!;
    expect(plan.statements).toHaveLength(1);
    expect(plan.notes[0]).toContain("every role is denied until a human adds an ownership policy");
  });

  it("has no template for tables with RLS already enabled", async () => {
    const { parsed } = await demo();
    const profiles = parsed.snapshot.tables.find((table) => table.name === "profiles")!;
    expect(planRepair(profiles, ["authenticated"])).toBeUndefined();
  });
});

describe("static repair verification", () => {
  it("verifies the canonical patch and reports advisories separately", async () => {
    const { sql, parsed } = await demo();
    const orders = parsed.snapshot.tables.find((table) => table.name === "orders")!;
    const plan = planRepair(orders, ["authenticated"])!;

    const verification = verifyRepairStatic(sql, plan, ["authenticated"]);
    expect(verification.status).toBe("verified");
    expect(verification.resolved).toHaveLength(4);
    expect(verification.afterWitnesses).toEqual([]);
    expect(verification.newFindings).toEqual([]);
    expect(verification.advisoryFindings).toEqual(["info force-rls-disabled rls_doctor_demo.orders"]);
  });

  it("fails a patch that resolves nothing", async () => {
    const { sql, parsed } = await demo();
    const orders = parsed.snapshot.tables.find((table) => table.name === "orders")!;
    const plan = planRepair(orders, ["authenticated"])!;
    const empty = { ...plan, statements: [] };

    const verification = verifyRepairStatic(sql, empty, ["authenticated"]);
    expect(verification.status).toBe("failed");
    expect(verification.reasons).toContain("the patch did not resolve any witness");
  });

  it("builds a receipt binding the patch hash and digest", async () => {
    const { sql, parsed } = await demo();
    const orders = parsed.snapshot.tables.find((table) => table.name === "orders")!;
    const plan = planRepair(orders, ["authenticated"])!;
    const verification = verifyRepairStatic(sql, plan, ["authenticated"]);
    const patch = renderPatch(plan);
    const at = new Date("2026-10-09T00:00:00Z");
    const receipt = buildRepairReceipt(plan, patch, verification, {
      schemaFiles: ["demo/unsafe-schema.sql"],
      table: "rls_doctor_demo.orders",
      roles: ["authenticated"],
    }, "test", at);

    expect(receipt.patch.sha256).toBe(createHash("sha256").update(patch, "utf8").digest("hex"));
    const { digest, ...body } = receipt;
    expect(digest.value).toBe(createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"));
  });
});

describe("fix CLI", () => {
  it("writes a verified patch and receipt for an exposed table", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-fix-"));
    temporaryRoots.push(root);
    const patchPath = join(root, "fix.sql");
    const receiptPath = join(root, "fix.json");

    const result = cli([
      "fix",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--table",
      "orders",
      "--patch",
      patchPath,
      "--receipt",
      receiptPath
    ]);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Verification: verified");
    expect(result.stdout).toContain("Resolved:         4");
    const patch = readFileSync(patchPath, "utf8");
    expect(patch).toContain("enable row level security");
    expect(patch).toContain("create policy");

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as {
      verification: { status: string; mode: string };
      patch: { sha256: string };
      digest: { value: string };
    };
    expect(receipt.verification.status).toBe("verified");
    expect(receipt.verification.mode).toMatch(/^static/);
    expect(receipt.patch.sha256).toHaveLength(64);
    const { digest, ...body } = receipt;
    expect(digest.value).toBe(createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"));
  }, 120_000);

  it("explains when no template applies and rejects unknown tables", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-fix-"));
    temporaryRoots.push(root);
    const patchPath = join(root, "fix.sql");

    const alreadyEnabled = cli([
      "fix", "--schema-file", "demo/unsafe-schema.sql", "--table", "profiles", "--patch", patchPath,
    ]);
    expect(alreadyEnabled.status).toBe(0);
    expect(alreadyEnabled.stdout).toContain("already enabled");

    const missing = cli([
      "fix", "--schema-file", "demo/unsafe-schema.sql", "--table", "nope", "--patch", patchPath,
    ]);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("Table not found");
  }, 120_000);
});
