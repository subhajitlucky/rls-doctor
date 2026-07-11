import { describe, expect, it } from "vitest";
import { analyzeCatalog, getTableAudit, shouldFail } from "../src/audit/analyzer.js";
import type { CatalogSnapshot, PolicySnapshot } from "../src/audit/types.js";

function analyzePolicy(policy: Omit<PolicySnapshot, "schema" | "table" | "name" | "permissive">) {
  return analyzeCatalog(
    {
      tables: [
        {
          schema: "public",
          name: "documents",
          rlsEnabled: true,
          forceRls: true,
          isPartitioned: false,
          estimatedRows: null
        }
      ],
      policies: [
        {
          schema: "public",
          table: "documents",
          name: `${policy.command.toLowerCase()} documents`,
          permissive: false,
          ...policy
        }
      ]
    },
    { schemas: ["public"] }
  ).tables[0]!.findings;
}

function findingSignatures(findings: ReturnType<typeof analyzePolicy>) {
  return findings.map(({ id, severity }) => ({ id, severity }));
}

function analyzePolicies(policies: Array<Omit<PolicySnapshot, "schema" | "table">>) {
  return analyzeCatalog(
    {
      tables: [
        {
          schema: "public",
          name: "documents",
          rlsEnabled: true,
          forceRls: true,
          isPartitioned: false,
          estimatedRows: null
        }
      ],
      policies: policies.map((policy) => ({
        schema: "public",
        table: "documents",
        ...policy
      }))
    },
    { schemas: ["public"] }
  ).tables[0]!.findings;
}

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

    expect(report.summary.highestSeverity).toBe("none");
    expect(shouldFail(report, "info")).toBe(false);
    expect(report.summary.findings.high).toBe(0);
    expect(report.summary.findings.critical).toBe(0);
    expect(report.tables[0]?.findings).toHaveLength(0);
  });

  it("represents an empty catalog as clean", () => {
    const report = analyzeCatalog(
      { tables: [], policies: [] },
      { schemas: ["public"] }
    );

    expect(report.summary.highestSeverity).toBe("none");
    expect(shouldFail(report, "info")).toBe(false);
  });

  describe("policy command semantics", () => {
    it("accepts a public INSERT policy with a restrictive WITH CHECK", () => {
      const findings = analyzePolicy({
        command: "INSERT",
        roles: ["public"],
        usingExpression: null,
        checkExpression: "owner_id = auth.uid()"
      });

      expect(findingSignatures(findings)).toEqual([]);
    });

    it("flags a public INSERT policy with an unconditional WITH CHECK", () => {
      const findings = analyzePolicy({
        command: "INSERT",
        roles: ["public"],
        usingExpression: null,
        checkExpression: "true"
      });

      expect(findingSignatures(findings)).toEqual([
        { id: "public-unconditional-write", severity: "critical" }
      ]);
      expect(findings[0]?.suggestedSql).toEqual([
        "-- Adapt this suggested SQL to your schema and access model before executing it.",
        'alter policy "insert documents"',
        '  on "public"."documents"',
        "  to authenticated",
        "  with check ((select auth.uid()) = <owner_column>);"
      ]);
    });

    it("flags a public DELETE policy with an unconditional USING", () => {
      const findings = analyzePolicy({
        command: "DELETE",
        roles: ["public"],
        usingExpression: "1 = 1",
        checkExpression: null
      });

      expect(findingSignatures(findings)).toEqual([
        { id: "public-unconditional-write", severity: "critical" }
      ]);
      expect(findings[0]?.suggestedSql).toEqual([
        "-- Adapt this suggested SQL to your schema and access model before executing it.",
        'alter policy "delete documents"',
        '  on "public"."documents"',
        "  to authenticated",
        "  using ((select auth.uid()) = <owner_column>);"
      ]);
    });

    it("does not require WITH CHECK for DELETE", () => {
      const findings = analyzePolicy({
        command: "DELETE",
        roles: ["authenticated"],
        usingExpression: "owner_id = auth.uid()",
        checkExpression: null
      });

      expect(findingSignatures(findings)).toEqual([]);
    });

    it("uses UPDATE USING as the implicit WITH CHECK when WITH CHECK is absent", () => {
      const findings = analyzePolicy({
        command: "UPDATE",
        roles: ["public"],
        usingExpression: "owner_id = auth.uid()",
        checkExpression: null
      });

      expect(findingSignatures(findings)).toEqual([]);
    });

    it("evaluates ALL across read, insert, update, and delete behavior without duplicate IDs", () => {
      const inheritedCheckFindings = analyzePolicy({
        command: "ALL",
        roles: ["public"],
        usingExpression: "owner_id = auth.uid()",
        checkExpression: null
      });

      expect(findingSignatures(inheritedCheckFindings)).toEqual([]);

      const unconditionalCheckFindings = analyzePolicy({
        command: "ALL",
        roles: ["public"],
        usingExpression: "owner_id = auth.uid()",
        checkExpression: "true"
      });

      expect(findingSignatures(unconditionalCheckFindings)).toEqual([
        { id: "public-unconditional-write", severity: "critical" }
      ]);

      const unconditionalUsingFindings = analyzePolicy({
        command: "ALL",
        roles: ["public"],
        usingExpression: "true",
        checkExpression: "owner_id = auth.uid()"
      });

      expect(findingSignatures(unconditionalUsingFindings)).toEqual([
        { id: "public-unconditional-read", severity: "high" },
        { id: "public-unconditional-write", severity: "critical" }
      ]);
      expect(unconditionalUsingFindings[1]?.suggestedSql).toEqual([
        "-- Adapt this suggested SQL to your schema and access model before executing it.",
        'alter policy "all documents"',
        '  on "public"."documents"',
        "  to authenticated",
        "  using ((select auth.uid()) = <owner_column>)",
        "  with check ((select auth.uid()) = <owner_column>);"
      ]);
    });
  });

  describe("permissive policy composition", () => {
    it("warns when multiple permissive policies apply to the same public-like role and command", () => {
      const findings = analyzePolicies([
        {
          name: "published documents",
          command: "SELECT",
          permissive: true,
          roles: ["anon"],
          usingExpression: "published_at is not null",
          checkExpression: null
        },
        {
          name: "shared documents",
          command: "SELECT",
          permissive: true,
          roles: ["anon"],
          usingExpression: "share_token is not null",
          checkExpression: null
        }
      ]);

      const compositionFinding = findings.find(
        (finding) => finding.id === "multiple-permissive-policies"
      );

      expect(compositionFinding).toMatchObject({ severity: "medium" });
      expect(compositionFinding?.detail).toContain("anon");
      expect(compositionFinding?.detail).toContain("SELECT");
      expect(compositionFinding?.detail).toContain('"published documents"');
      expect(compositionFinding?.detail).toContain('"shared documents"');
      expect(compositionFinding?.detail).toContain("OR-combined");
    });

    it("does not warn when permissive policies apply to unrelated commands", () => {
      const findings = analyzePolicies([
        {
          name: "read documents",
          command: "SELECT",
          permissive: true,
          roles: ["authenticated"],
          usingExpression: "owner_id = auth.uid()",
          checkExpression: null
        },
        {
          name: "update documents",
          command: "UPDATE",
          permissive: true,
          roles: ["authenticated"],
          usingExpression: "owner_id = auth.uid()",
          checkExpression: "owner_id = auth.uid()"
        }
      ]);

      expect(findings).not.toContainEqual(
        expect.objectContaining({ id: "multiple-permissive-policies" })
      );
    });

    it("accounts for a restrictive policy as an AND-combined constraint", () => {
      const findings = analyzePolicies([
        {
          name: "owned documents",
          command: "SELECT",
          permissive: true,
          roles: ["authenticated"],
          usingExpression: "owner_id = auth.uid()",
          checkExpression: null
        },
        {
          name: "team documents",
          command: "ALL",
          permissive: true,
          roles: ["authenticated"],
          usingExpression: "team_id = current_team_id()",
          checkExpression: "team_id = current_team_id()"
        },
        {
          name: "active accounts only",
          command: "ALL",
          permissive: false,
          roles: ["authenticated"],
          usingExpression: "account_is_active()",
          checkExpression: "account_is_active()"
        }
      ]);

      const compositionFindings = findings.filter(
        (finding) => finding.id === "multiple-permissive-policies"
      );

      expect(compositionFindings).toHaveLength(1);
      expect(compositionFindings[0]).toMatchObject({ severity: "low" });
      expect(compositionFindings[0]?.detail).toContain('Restrictive policy "active accounts only"');
      expect(compositionFindings[0]?.detail).toContain("AND-combined");
    });
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
