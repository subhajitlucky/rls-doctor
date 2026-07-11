import { describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import type { CatalogSnapshot } from "../src/audit/types.js";
import { renderJsonReport } from "../src/reporters/json.js";
import { renderExplainReport } from "../src/reporters/text.js";
import { renderTextReport } from "../src/reporters/text.js";

const emptyCatalogFacts: Pick<
  CatalogSnapshot,
  "relationPrivileges" | "defaultPrivileges" | "roles" | "roleMemberships"
> = { relationPrivileges: [], defaultPrivileges: [], roles: [], roleMemberships: [] };

describe("reporters", () => {
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

  const cleanReport = analyzeCatalog(
    {
      ...emptyCatalogFacts,
      tables: [
        {
          schema: "public",
          name: "tasks",
          owner: "postgres",
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

  it("renders text without exposing connection data", () => {
    const text = renderTextReport(report);

    expect(text).toContain("RLS Doctor Report");
    expect(text).toContain("public.orders");
    expect(text).toContain("[MEDIUM] Row Level Security is disabled");
    expect(text).toContain('alter table "public"."orders" enable row level security;');
    expect(text).not.toContain("postgres://");
  });

  it("renders valid JSON", () => {
    const json = renderJsonReport(report);
    const parsed = JSON.parse(json) as typeof report;

    expect(parsed.schemaVersion).toBe("1.0");
    expect(parsed.summary.highestSeverity).toBe("medium");
    expect(parsed.tables[0]?.table).toBe("orders");
    expect(parsed.schemaFindings).toEqual([]);
  });

  it("renders clean reports with no highest risk", () => {
    const text = renderTextReport(cleanReport);

    expect(text).toContain("highest risk NONE");
  });

  it("renders a clean table explanation with no risk", () => {
    const text = renderExplainReport(cleanReport.tables[0]!);

    expect(text).toContain("Risk: NONE");
  });

  it("renders a focused explanation for one table", () => {
    const text = renderExplainReport(report.tables[0]!);

    expect(text).toContain("public.orders");
    expect(text).toContain("RLS: disabled");
    expect(text).toContain("Risk: MEDIUM");
    expect(text).toContain("Next steps");
    expect(text).toContain("Suggested SQL");
  });

  it("renders schema findings before table details", () => {
    const schemaReport = analyzeCatalog(
      {
        ...emptyCatalogFacts,
        tables: [
          {
            schema: "public",
            name: "tasks",
            owner: "postgres",
            rlsEnabled: true,
            forceRls: true,
            isPartitioned: false,
            estimatedRows: null
          }
        ],
        policies: [],
        defaultPrivileges: [
          {
            schema: "public",
            owner: "postgres",
            grantee: "PUBLIC",
            objectType: "TABLE",
            privilege: "DELETE",
            grantable: false
          }
        ]
      },
      { schemas: ["public"] }
    );
    const text = renderTextReport(schemaReport);
    const json = JSON.parse(renderJsonReport(schemaReport)) as typeof schemaReport;

    expect(text).toContain("Schema and role findings");
    expect(text).toContain("[HIGH] Broad default table privilege");
    expect(text.indexOf("Schema and role findings")).toBeLessThan(text.indexOf("public.tasks"));
    expect(json.schemaFindings[0]).toMatchObject({
      id: "broad-default-table-privilege",
      schema: "public",
      severity: "high"
    });
  });

  it("labels null-schema default privileges as owner-specific database-wide defaults", () => {
    const schemaReport = analyzeCatalog(
      {
        ...emptyCatalogFacts,
        tables: [],
        policies: [],
        defaultPrivileges: [
          {
            schema: null,
            owner: "app_owner",
            grantee: "PUBLIC",
            objectType: "TABLE",
            privilege: "SELECT",
            grantable: false
          }
        ]
      },
      { schemas: ["public"] }
    );
    const text = renderTextReport(schemaReport);

    expect(text).toContain("Scope: database-wide / role level");
    expect(text).toContain("Database-wide defaults for owner app_owner");
    expect(text).not.toContain("all schemas");
  });
});
