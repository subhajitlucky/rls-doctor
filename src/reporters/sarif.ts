import { findingFingerprint } from "../audit/fingerprint.js";
import type { AuditReport, Severity } from "../audit/types.js";

export interface SarifRenderOptions {
  toolVersion?: string;
  informationUri?: string;
}

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const DEFAULT_INFO_URI = "https://github.com/subhajitlucky/rls-doctor";

const levelBySeverity: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note"
};

export function renderSarifReport(report: AuditReport, options: SarifRenderOptions = {}): string {
  const findings = [...report.schemaFindings, ...report.tables.flatMap((table) => table.findings)];
  const rules = new Map<string, string>();

  for (const finding of findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, finding.title);
    }
  }

  const ruleList = [...rules.entries()].map(([id, title]) => ({ id, title }));
  const ruleIndex = new Map(ruleList.map((rule, index) => [rule.id, index]));

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "rls-doctor",
            ...(options.toolVersion === undefined ? {} : { version: options.toolVersion }),
            informationUri: options.informationUri ?? DEFAULT_INFO_URI,
            rules: ruleList.map((rule) => ({
              id: rule.id,
              shortDescription: { text: rule.title },
              defaultConfiguration: { level: "warning" }
            }))
          }
        },
        results: findings.map((finding) => {
          const table =
            "table" in finding && typeof finding.table === "string" ? finding.table : undefined;
          return {
            ruleId: finding.id,
            ruleIndex: ruleIndex.get(finding.id),
            level: levelBySeverity[finding.severity],
            message: { text: `${finding.title}. ${finding.detail}` },
            locations: [
              {
                logicalLocations: [
                  {
                    ...(table ? { name: table } : {}),
                    ...(finding.schema
                      ? { fullyQualifiedName: table ? `${finding.schema}.${table}` : finding.schema }
                      : {}),
                    kind: "table"
                  }
                ]
              }
            ],
            partialFingerprints: { rlsDoctorFindingV1: findingFingerprint(finding) },
            properties: {
              severity: finding.severity,
              recommendation: finding.recommendation
            }
          };
        })
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
