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

    expect(parsed.summary.highestSeverity).toBe("high");
    expect(parsed.tables[0]?.table).toBe("orders");
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
