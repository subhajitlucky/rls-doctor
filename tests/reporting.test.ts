import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import { loadBaseline } from "../src/audit/baseline.js";
import {
  compareWithBaseline,
  findingFingerprint,
  reportFindingFingerprints
} from "../src/audit/fingerprint.js";
import type { AuditReport, CatalogSnapshot, Finding, TableAudit } from "../src/audit/types.js";
import { renderSarifReport } from "../src/reporters/sarif.js";

const emptyCatalogFacts: Pick<
  CatalogSnapshot,
  "relationPrivileges" | "defaultPrivileges" | "roles" | "roleMemberships"
> = { relationPrivileges: [], defaultPrivileges: [], roles: [], roleMemberships: [] };

const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "rls-disabled",
    severity: "medium",
    schema: "public",
    table: "orders",
    title: "Row Level Security is disabled",
    detail: "public.orders has no row-level policy enforcement.",
    recommendation: "Enable RLS.",
    ...overrides
  };
}

function reportWith(findings: Finding[]): AuditReport {
  const table: TableAudit = {
    schema: "public",
    table: "orders",
    rlsEnabled: false,
    forceRls: false,
    policies: [],
    findings
  };

  return {
    schemaVersion: "1.0",
    generatedAt: "2026-09-20T00:00:00.000Z",
    schemas: ["public"],
    summary: {
      tables: 1,
      policies: 0,
      findings: { info: 0, low: 0, medium: findings.length, high: 0, critical: 0 },
      highestSeverity: findings.length > 0 ? "medium" : "none"
    },
    schemaFindings: [],
    tables: [table]
  };
}

describe("finding fingerprints", () => {
  it("are stable for identical findings and sensitive to details", () => {
    const base = finding();
    expect(findingFingerprint(base)).toBe(findingFingerprint({ ...base }));
    expect(findingFingerprint(base)).not.toBe(
      findingFingerprint({ ...base, detail: "different detail" })
    );
    expect(findingFingerprint(base)).not.toBe(
      findingFingerprint({ ...base, table: "profiles" })
    );
  });

  it("deduplicates report fingerprints deterministically", () => {
    const report = reportWith([finding(), finding(), finding({ table: "profiles" })]);
    const fingerprints = reportFindingFingerprints(report);

    expect(fingerprints).toHaveLength(2);
    expect([...fingerprints].sort()).toEqual(fingerprints);
  });

  it("classifies new, unchanged, and resolved findings", () => {
    const baselineReport = reportWith([finding()]);
    const current = reportWith([
      finding(),
      finding({ id: "reachable-truncate", severity: "high", detail: "TRUNCATE is reachable." })
    ]);
    const comparison = compareWithBaseline(reportFindingFingerprints(baselineReport), current);

    expect(comparison.new).toHaveLength(1);
    expect(comparison.unchanged).toHaveLength(1);
    expect(comparison.resolved).toHaveLength(0);

    const resolved = compareWithBaseline(
      [...reportFindingFingerprints(baselineReport), "deadbeefdeadbeef"],
      reportWith([])
    );
    expect(resolved.resolved).toContain("deadbeefdeadbeef");
    expect(resolved.resolved).toHaveLength(2);
  });
});

describe("baseline loading", () => {
  it("reads fingerprints and generation time from a JSON report", async () => {
    const report = analyzeCatalog(
      {
        ...emptyCatalogFacts,
        tables: [
          {
            schema: "public",
            name: "orders",
            owner: "postgres",
            rlsEnabled: false,
            forceRls: false,
            isPartitioned: false,
            estimatedRows: null
          }
        ],
        policies: []
      },
      { schemas: ["public"], generatedAt: new Date("2026-07-05T00:00:00.000Z") }
    );

    const directory = await mkdtemp(join(tmpdir(), "rls-doctor-baseline-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "baseline.json");
    await writeFile(path, JSON.stringify(report), "utf8");

    const baseline = await loadBaseline(path);
    expect(baseline.generatedAt).toBe("2026-07-05T00:00:00.000Z");
    expect(baseline.fingerprints).toEqual(reportFindingFingerprints(report));
  });

  it("rejects files that are not rls-doctor reports", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rls-doctor-baseline-"));
    temporaryDirectories.push(directory);

    const invalidJson = join(directory, "invalid.json");
    await writeFile(invalidJson, "{not json", "utf8");
    await expect(loadBaseline(invalidJson)).rejects.toThrow(/Could not read baseline/);

    const wrongShape = join(directory, "wrong.json");
    await writeFile(wrongShape, JSON.stringify({ schemaVersion: "2.0" }), "utf8");
    await expect(loadBaseline(wrongShape)).rejects.toThrow(/not an rls-doctor JSON report/);
  });
});

describe("SARIF reporter", () => {
  it("renders SARIF 2.1.0 with rules, levels, logical locations, and fingerprints", () => {
    const report = reportWith([
      finding(),
      finding({ id: "reachable-truncate", severity: "high", detail: "TRUNCATE is reachable." })
    ]);
    const sarif = JSON.parse(renderSarifReport(report, { toolVersion: "0.2.0" }));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver).toMatchObject({ name: "rls-doctor", version: "0.2.0" });
    expect(sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id)).toEqual([
      "rls-disabled",
      "reachable-truncate"
    ]);

    const [medium, high] = sarif.runs[0].results;
    expect(medium.level).toBe("warning");
    expect(high.level).toBe("error");
    expect(medium.ruleIndex).toBe(0);
    expect(medium.locations[0].logicalLocations[0]).toMatchObject({
      name: "orders",
      fullyQualifiedName: "public.orders",
      kind: "table"
    });
    expect(medium.partialFingerprints.rlsDoctorFindingV1).toBe(findingFingerprint(finding()));
    expect(medium.properties).toMatchObject({ severity: "medium" });
  });
});
