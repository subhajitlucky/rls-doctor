import { describe, expect, it } from "vitest";
import { bandForScore, scoreAudit } from "../src/audit/score.js";
import type { AuditReport, AuditScore, SchemaFinding, Severity, TableAudit } from "../src/audit/types.js";
import { renderJsonReport } from "../src/reporters/json.js";
import { renderScoreLine, renderScoreOutput, scoreBadgeUrl } from "../src/reporters/score.js";

function finding(severity: Severity) {
  return {
    id: `fixture-${severity}`,
    severity,
    schema: "public",
    table: "orders",
    title: `${severity} finding`,
    detail: `${severity} detail`,
    recommendation: "Fix it."
  };
}

function table(findings: ReturnType<typeof finding>[]): TableAudit {
  return {
    schema: "public",
    table: "orders",
    rlsEnabled: false,
    forceRls: false,
    policies: [],
    findings
  };
}

function schemaFinding(severity: Severity): SchemaFinding {
  return {
    id: `schema-${severity}`,
    severity,
    schema: null,
    title: `${severity} schema finding`,
    detail: `${severity} detail`,
    recommendation: "Fix it."
  };
}

describe("scoreAudit", () => {
  it("scores a clean catalog at 100 green", () => {
    expect(scoreAudit([], [table([])])).toEqual({
      value: 100,
      band: "green",
      findingPenalty: 0,
      coveragePenalty: 0
    });
  });

  it("applies deterministic severity penalties across tables and schema findings", () => {
    const score = scoreAudit(
      [schemaFinding("high")],
      [table([finding("critical"), finding("medium"), finding("low"), finding("info")])]
    );
    expect(score.findingPenalty).toBe(40);
    expect(score.value).toBe(60);
    expect(score.band).toBe("yellow");
  });

  it("clamps at zero and maps band boundaries", () => {
    const score = scoreAudit(
      [],
      [table([finding("critical"), finding("critical"), finding("critical"), finding("critical")])]
    );
    expect(score.value).toBe(0);
    expect(score.band).toBe("red");
    expect(bandForScore(80)).toBe("green");
    expect(bandForScore(79)).toBe("yellow");
    expect(bandForScore(50)).toBe("yellow");
    expect(bandForScore(49)).toBe("red");
  });
});

function reportWithScore(score: AuditScore): AuditReport {
  return {
    schemaVersion: "1.0",
    generatedAt: "2026-10-08T00:00:00.000Z",
    schemas: ["public"],
    summary: {
      tables: 1,
      policies: 0,
      findings: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
      highestSeverity: "high"
    },
    score,
    schemaFindings: [],
    tables: []
  };
}

describe("score reporters", () => {
  const report = reportWithScore(scoreAudit([], [table([finding("high")])]));

  it("prints one deterministic score line", () => {
    expect(renderScoreLine(report)).toBe("RLS Score: 90/100\n");
  });

  it("builds a shields.io badge URL with the band color", () => {
    expect(scoreBadgeUrl(report)).toBe(
      "https://img.shields.io/badge/RLS%20Score-90%2F100-green"
    );
  });

  it("renders score and badge together and nothing when unselected", () => {
    expect(renderScoreOutput(report, {})).toBeUndefined();
    expect(renderScoreOutput(report, { score: true })).toBe("RLS Score: 90/100\n");
    expect(renderScoreOutput(report, { badge: true })).toBe(
      "https://img.shields.io/badge/RLS%20Score-90%2F100-green\n"
    );
    expect(renderScoreOutput(report, { score: true, badge: true })).toBe(
      "RLS Score: 90/100\nhttps://img.shields.io/badge/RLS%20Score-90%2F100-green\n"
    );
  });

  it("includes the score in JSON output", () => {
    const parsed = JSON.parse(renderJsonReport(report)) as { score: AuditScore };
    expect(parsed.score).toEqual(report.score);
  });
});
