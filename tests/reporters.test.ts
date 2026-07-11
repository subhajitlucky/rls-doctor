import { describe, expect, it } from "vitest";
import { analyzeCatalog } from "../src/audit/analyzer.js";
import { renderJsonReport } from "../src/reporters/json.js";
import { renderExplainReport } from "../src/reporters/text.js";
import { renderTextReport } from "../src/reporters/text.js";

describe("reporters", () => {
  const report = analyzeCatalog(
    {
      tables: [
        {
          schema: "public",
          name: "orders",
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

  it("renders text without exposing connection data", () => {
    const text = renderTextReport(report);

    expect(text).toContain("RLS Doctor Report");
    expect(text).toContain("public.orders");
    expect(text).toContain("[HIGH] Row Level Security is disabled");
    expect(text).toContain('alter table "public"."orders" enable row level security;');
    expect(text).not.toContain("postgres://");
  });

  it("renders valid JSON", () => {
    const json = renderJsonReport(report);
    const parsed = JSON.parse(json) as typeof report;

    expect(parsed.schemaVersion).toBe("1.0");
    expect(parsed.summary.highestSeverity).toBe("high");
    expect(parsed.tables[0]?.table).toBe("orders");
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
    expect(text).toContain("Risk: HIGH");
    expect(text).toContain("Next steps");
    expect(text).toContain("Suggested SQL");
  });
});
