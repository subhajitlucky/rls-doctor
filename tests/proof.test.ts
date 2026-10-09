import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseSchemaSql } from "../src/audit/schema-file.js";
import { decidePredicate } from "../src/proof/predicate.js";
import { buildProofArtifact, buildProofClaims } from "../src/proof/runner.js";
import { canonicalJson } from "../src/receipts/receipt.js";

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

async function parseFixture(name: string) {
  return parseSchemaSql(await readFile(`demo/${name}`, "utf8"));
}

describe("decidable predicate fragment", () => {
  it("proves ownership equalities on either side", () => {
    expect(decidePredicate("owner_id = auth.uid()")).toEqual({ status: "proved", column: "owner_id" });
    expect(decidePredicate("auth.uid() = owner_id")).toEqual({ status: "proved", column: "owner_id" });
    expect(decidePredicate("(select auth.uid()) = owner_id")).toEqual({ status: "proved", column: "owner_id" });
  });

  it("witnesses unconditional predicates and proves deny-all", () => {
    expect(decidePredicate("true").status).toBe("witness");
    expect(decidePredicate("false")).toEqual({ status: "proved", column: null });
    expect(decidePredicate(null)).toEqual({ status: "proved", column: null });
  });

  it("combines conjunctions soundly", () => {
    expect(decidePredicate("owner_id = auth.uid() AND true").status).toBe("proved");
    expect(decidePredicate("owner_id = auth.uid() AND length(name) > 0").status).toBe("proved");
    expect(decidePredicate("true AND true").status).toBe("witness");
    expect(decidePredicate("false AND length(name) > 0")).toEqual({ status: "proved", column: null });
  });

  it("combines disjunctions soundly", () => {
    expect(decidePredicate("owner_id = auth.uid() OR owner_id = auth.uid()").status).toBe("proved");
    expect(decidePredicate("owner_id = auth.uid() OR tenant_id = auth.uid()").status).toBe("witness");
    expect(decidePredicate("owner_id = auth.uid() OR true").status).toBe("witness");
    expect(decidePredicate("owner_id = auth.uid() OR length(name) > 0").status).toBe("witness");
    expect(decidePredicate("length(name) > 0 OR length(title) > 0").status).toBe("undecided");
  });

  it("never guesses outside the fragment", () => {
    expect(decidePredicate("NOT owner_id = auth.uid()").status).toBe("undecided");
    expect(decidePredicate("owner_id IN (select id from admins)").status).toBe("undecided");
    expect(decidePredicate("owner_id::text = auth.uid()::text").status).toBe("undecided");
  });
});

describe("proof claims", () => {
  it("proves isolation for the safe fixture", async () => {
    const parsed = await parseFixture("safe-schema.sql");
    const claims = buildProofClaims(parsed.snapshot.tables, parsed.snapshot.policies, ["authenticated"]);

    expect(claims).toHaveLength(4);
    expect(claims.every((claim) => claim.status === "proved")).toBe(true);
    expect(claims[0]).toMatchObject({ table: "tasks", column: "owner_id" });
  });

  it("finds witnesses in the unsafe fixture", async () => {
    const parsed = await parseFixture("unsafe-schema.sql");
    const claims = buildProofClaims(parsed.snapshot.tables, parsed.snapshot.policies, ["authenticated"]);

    expect(claims.filter((claim) => claim.status === "witness")).toHaveLength(6);
    expect(claims.filter((claim) => claim.status === "proved")).toHaveLength(6);
    expect(claims.find((claim) => claim.table === "orders")?.reason).toContain("RLS is disabled");
    expect(claims.find((claim) => claim.table === "tasks")?.status).toBe("proved");
  });

  it("produces a stable artifact digest", async () => {
    const parsed = await parseFixture("unsafe-schema.sql");
    const claims = buildProofClaims(parsed.snapshot.tables, parsed.snapshot.policies, ["authenticated"]);
    const at = new Date("2026-10-09T00:00:00Z");
    const artifact = buildProofArtifact(claims, { schemaFiles: ["unsafe.sql"], schemas: parsed.schemas, roles: ["authenticated"] }, parsed.limitations, "test", at);
    const { digest, ...body } = artifact;

    expect(digest.value).toBe(createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"));
    expect(buildProofArtifact(claims, { schemaFiles: ["unsafe.sql"], schemas: parsed.schemas, roles: ["authenticated"] }, parsed.limitations, "test", at).digest.value).toBe(digest.value);
  });
});

describe("prove CLI", () => {
  it("exits 1 with witnesses and writes a verifiable artifact", () => {
    const root = mkdtempSync(join(tmpdir(), "rls-doctor-proof-"));
    temporaryRoots.push(root);
    const proofPath = join(root, "proof.json");

    const result = cli(["prove", "--schema-file", "demo/unsafe-schema.sql", "--proof", proofPath]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("WITNESS");
    expect(result.stderr).toContain("proof artifact written");

    const artifact = JSON.parse(readFileSync(proofPath, "utf8")) as {
      claims: { status: string }[];
      digest: { value: string };
    };
    const { digest, ...body } = artifact;
    expect(digest.value).toBe(createHash("sha256").update(canonicalJson(body), "utf8").digest("hex"));
  });

  it("exits 0 when every claim is proved", () => {
    const result = cli(["prove", "--schema-file", "demo/safe-schema.sql", "--json"]);
    expect(result.status).toBe(0);
    const artifact = JSON.parse(result.stdout) as { claims: { status: string }[] };
    expect(artifact.claims.every((claim) => claim.status === "proved")).toBe(true);
  });

  it("filters to a single table", () => {
    const result = cli(["prove", "--schema-file", "demo/unsafe-schema.sql", "--table", "tasks", "--json"]);
    expect(result.status).toBe(0);
    const artifact = JSON.parse(result.stdout) as { claims: { table: string }[] };
    expect(artifact.claims).toHaveLength(4);
    expect(artifact.claims.every((claim) => claim.table === "tasks")).toBe(true);
  });
});
