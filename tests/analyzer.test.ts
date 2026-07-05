import { describe, expect, it } from "vitest";
import { analyzeCatalog, getTableAudit, shouldFail } from "../src/audit/analyzer.js";
import type { CatalogSnapshot } from "../src/audit/types.js";

describe("analyzeCatalog", () => {
  it("flags tables where RLS is disabled", () => {
    const report = analyzeCatalog(
      {
        tables: [
          {
            schema: "public",
            name: "orders",
            rlsEnabled: false,
            forceRls: false,
            isPartitioned: false,
            estimatedRows: 120
          }
        ],
        policies: []
      },
      { schemas: ["public"], generatedAt: new Date("2026-07-05T00:00:00.000Z") }
    );

    expect(report.summary.highestSeverity).toBe("high");
    expect(report.summary.findings.high).toBe(1);
    expect(report.tables[0]?.findings[0]?.id).toBe("rls-disabled");
  });

  it("flags public unconditional read and write policies", () => {
    const snapshot: CatalogSnapshot = {
      tables: [
        {
          schema: "public",
          name: "profiles",
          rlsEnabled: true,
          forceRls: false,
          isPartitioned: false,
          estimatedRows: 10
        }
      ],
      policies: [
        {
          schema: "public",
          table: "profiles",
          name: "anyone can read",
          command: "SELECT",
          permissive: true,
          roles: ["anon"],
          usingExpression: "true",
          checkExpression: null
        },
        {
          schema: "public",
          table: "profiles",
          name: "anyone can update",
          command: "UPDATE",
          permissive: true,
          roles: ["public"],
          usingExpression: "true",
          checkExpression: null
        }
      ]
    };

    const report = analyzeCatalog(snapshot, { schemas: ["public"] });
    const findingIds = report.tables[0]?.findings.map((finding) => finding.id);

    expect(report.summary.highestSeverity).toBe("critical");
    expect(findingIds).toContain("public-unconditional-read");
    expect(findingIds).toContain("public-unconditional-write");
    expect(findingIds).toContain("write-policy-missing-check");
  });

  it("does not mark scoped authenticated policies as high risk", () => {
    const report = analyzeCatalog(
      {
        tables: [
          {
            schema: "public",
            name: "tasks",
            rlsEnabled: true,
            forceRls: true,
            isPartitioned: false,
            estimatedRows: 4
          }
        ],
        policies: [
          {
            schema: "public",
            table: "tasks",
            name: "users manage own tasks",
            command: "ALL",
            permissive: false,
            roles: ["authenticated"],
            usingExpression: "(owner_id = auth.uid())",
            checkExpression: "(owner_id = auth.uid())"
          }
        ]
      },
      { schemas: ["public"] }
    );

    expect(report.summary.highestSeverity).toBe("info");
    expect(report.summary.findings.high).toBe(0);
    expect(report.summary.findings.critical).toBe(0);
    expect(report.tables[0]?.findings).toHaveLength(0);
  });
});

describe("shouldFail", () => {
  it("compares highest severity with the configured threshold", () => {
    const report = analyzeCatalog(
      {
        tables: [
          {
            schema: "public",
            name: "events",
            rlsEnabled: false,
            forceRls: false,
            isPartitioned: false,
            estimatedRows: null
          }
        ],
        policies: []
      },
      { schemas: ["public"] }
    );

    expect(shouldFail(report, "critical")).toBe(false);
    expect(shouldFail(report, "high")).toBe(true);
    expect(shouldFail(report, "medium")).toBe(true);
    expect(shouldFail(report, "none")).toBe(false);
  });
});

describe("getTableAudit", () => {
  it("finds a table audit by qualified name", () => {
    const report = analyzeCatalog(
      {
        tables: [
          {
            schema: "public",
            name: "profiles",
            rlsEnabled: true,
            forceRls: true,
            isPartitioned: false,
            estimatedRows: null
          }
        ],
        policies: []
      },
      { schemas: ["public"] }
    );

    expect(getTableAudit(report, "public.profiles")?.table).toBe("profiles");
  });

  it("treats unqualified table names as public schema names", () => {
    const report = analyzeCatalog(
      {
        tables: [
          {
            schema: "public",
            name: "profiles",
            rlsEnabled: true,
            forceRls: true,
            isPartitioned: false,
            estimatedRows: null
          }
        ],
        policies: []
      },
      { schemas: ["public"] }
    );

    expect(getTableAudit(report, "profiles")?.schema).toBe("public");
  });
});
