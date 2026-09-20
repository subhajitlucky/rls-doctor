import { describe, expect, it } from "vitest";
import { analyzeProbeResults, shouldFailProbe } from "../src/audit/probe.js";
import type { ProbeExecutionResult, ProbeRunResult } from "../src/audit/types.js";

function probe(overrides: Partial<ProbeExecutionResult>): ProbeExecutionResult {
  return {
    role: "authenticated",
    schema: "public",
    table: "documents",
    status: "rows",
    sampledRows: 1,
    ownerColumn: "owner_id",
    distinctOwners: 1,
    error: null,
    ...overrides
  };
}

function analyze(run: ProbeRunResult) {
  return analyzeProbeResults(run, { schemas: ["public"], roles: ["authenticated"] });
}

describe("analyzeProbeResults", () => {
  it("flags cross-owner reads as high severity", () => {
    const report = analyze({
      probes: [probe({ sampledRows: 5, distinctOwners: 2 })],
      roleErrors: []
    });

    const finding = report.findings.find((item) => item.id === "probe-cross-owner-read");
    expect(finding).toMatchObject({ severity: "high", schema: "public", table: "documents" });
    expect(finding?.detail).toMatch(/distinct owner_id/);
    expect(report.summary.byStatus.rows).toBe(1);
    expect(report.summary.findings.high).toBe(1);
    expect(report.summary.highestSeverity).toBe("high");
    expect(shouldFailProbe(report, "high")).toBe(true);
    expect(shouldFailProbe(report, "critical")).toBe(false);
    expect(shouldFailProbe(report, "none")).toBe(false);
  });

  it("reports single-owner reads as an informational observation", () => {
    const report = analyze({
      probes: [probe({ sampledRows: 3, distinctOwners: 1 })],
      roleErrors: []
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({ id: "probe-reads-rows", severity: "info" });
    expect(report.summary.highestSeverity).toBe("info");
    expect(shouldFailProbe(report, "low")).toBe(false);
  });

  it("treats zero rows and denied reads as informational", () => {
    const report = analyze({
      probes: [
        probe({ status: "none", sampledRows: 0, distinctOwners: null }),
        probe({ status: "denied", sampledRows: 0, distinctOwners: null })
      ],
      roleErrors: []
    });

    expect(report.findings.map((finding) => finding.id).sort()).toEqual([
      "probe-read-denied",
      "probe-reads-no-rows"
    ]);
    expect(report.summary.byStatus).toMatchObject({ none: 1, denied: 1 });
    expect(report.summary.highestSeverity).toBe("info");
  });

  it("reports probe failures as low severity with the error detail", () => {
    const report = analyze({
      probes: [probe({ status: "error", sampledRows: 0, distinctOwners: null, error: "boom" })],
      roleErrors: []
    });

    expect(report.findings[0]).toMatchObject({ id: "probe-error", severity: "low" });
    expect(report.findings[0]?.detail).toContain("boom");
    expect(shouldFailProbe(report, "low")).toBe(true);
    expect(shouldFailProbe(report, "medium")).toBe(false);
  });

  it("reports roles the audit connection cannot impersonate", () => {
    const report = analyze({
      probes: [],
      roleErrors: [{ role: "app_user", message: "permission denied to set role" }]
    });

    const finding = report.findings.find((item) => item.id === "probe-role-unavailable");
    expect(finding).toMatchObject({ severity: "medium", schema: null, table: null });
    expect(finding?.detail).toContain("app_user");
    expect(shouldFailProbe(report, "medium")).toBe(true);
  });

  it("sorts probes deterministically by schema, table, and role", () => {
    const report = analyze({
      probes: [
        probe({ role: "web_user", table: "orders" }),
        probe({ role: "app_user", table: "orders" }),
        probe({ schema: "app", role: "app_user", table: "accounts" })
      ],
      roleErrors: []
    });

    expect(
      report.probes.map((item) => `${item.schema}.${item.table}:${item.role}`)
    ).toEqual(["app.accounts:app_user", "public.orders:app_user", "public.orders:web_user"]);
  });
});
