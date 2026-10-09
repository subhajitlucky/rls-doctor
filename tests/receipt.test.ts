import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import { parseSchemaSql } from "../src/audit/schema-file.js";
import type { AuditReport } from "../src/audit/types.js";
import {
  buildReceipt,
  canonicalJson,
  receiptDigest,
  serializeReceipt,
  verifyReceipt
} from "../src/receipts/receipt.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function cli(args: readonly string[]) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "src/cli.ts", ...args],
    { cwd: process.cwd(), encoding: "utf8", timeout: 30_000 }
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

describe("coverage receipts", () => {
  it("canonicalizes JSON deterministically with sorted keys", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: [3, { f: 4, e: 5 }] } })).toBe(
      '{"a":{"c":[3,{"e":5,"f":4}],"d":2},"b":1}'
    );
  });

  it("builds a receipt whose digest covers the canonical body", async () => {
    const report = await demoReport();
    const receipt = buildReceipt(report, {
      issuedAt: new Date("2026-10-09T00:00:00Z"),
      source: "schema-file",
      toolVersion: "test"
    });
    const { digest, signature, ...body } = receipt;

    expect(signature).toBeUndefined();
    expect(digest).toEqual({ algorithm: "sha256", value: receiptDigest(body) });
    expect(receipt.score.value).toBe(19);
    expect(receipt.coverage.complete).toBe(false);
    expect(receipt.findings.total).toBe(9);
    expect(receipt.findings.fingerprints.length).toBeGreaterThan(0);

    const verification = verifyReceipt(JSON.parse(serializeReceipt(receipt)));
    expect(verification.valid).toBe(true);
    expect(verification.summary).toContain("integrity: digest verified");
  });

  it("detects a modified receipt body", async () => {
    const receipt = buildReceipt(await demoReport(), { source: "catalog", toolVersion: "test" });
    const tampered = { ...receipt, score: { value: 100, band: "green" } };

    const verification = verifyReceipt(tampered);
    expect(verification.valid).toBe(false);
    expect(verification.reasons).toContain(
      "digest mismatch: the receipt body was modified after issuance"
    );
  });

  it("signs and verifies with an Ed25519 key", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const receipt = buildReceipt(await demoReport(), {
      source: "catalog",
      toolVersion: "test",
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
    });

    expect(receipt.signature?.algorithm).toBe("ed25519");
    expect(verifyReceipt(receipt).valid).toBe(true);
  });

  it("writes and verifies a receipt from the CLI", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-receipt-"));
    temporaryRoots.push(root);
    const receiptPath = join(root, "receipt.json");

    const check = cli([
      "check",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--fail-on",
      "none",
      "--receipt",
      receiptPath
    ]);
    expect(check.status).toBe(0);
    expect(check.stderr).toContain("receipt written");

    const verified = cli(["verify-receipt", receiptPath]);
    expect(verified.status).toBe(0);
    expect(verified.stdout).toContain("integrity: digest verified");
    expect(verified.stdout).toContain("scope=schema-file");
  });

  it("rejects a tampered receipt from the CLI", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-receipt-"));
    temporaryRoots.push(root);
    const receiptPath = join(root, "receipt.json");

    cli([
      "check",
      "--schema-file",
      "demo/unsafe-schema.sql",
      "--fail-on",
      "none",
      "--receipt",
      receiptPath
    ]);
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as { score: { value: number } };
    receipt.score.value = 100;
    writeFileSync(receiptPath, JSON.stringify(receipt), "utf8");

    const verified = cli(["verify-receipt", receiptPath]);
    expect(verified.status).toBe(2);
    expect(verified.stderr).toContain("digest mismatch");
  });
});
