import type {
  AuditReport,
  HighestSeverity,
  SchemaFinding,
  Severity,
  TableAudit
} from "../audit/types.js";

const severityLabel: Record<HighestSeverity, string> = {
  none: "NONE",
  info: "INFO",
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL"
};

export function renderTextReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push("RLS Doctor Report");
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push(`Schemas: ${report.schemas.join(", ")}`);
  lines.push("");
  lines.push(
    `Summary: ${report.summary.tables} tables, ${report.summary.policies} policies, highest risk ${severityLabel[report.summary.highestSeverity]}`
  );
  lines.push(
    `Findings: critical ${report.summary.findings.critical}, high ${report.summary.findings.high}, medium ${report.summary.findings.medium}, low ${report.summary.findings.low}, info ${report.summary.findings.info}`
  );
  lines.push("");

  const schemaFindings = report.schemaFindings ?? [];
  if (schemaFindings.length > 0) {
    lines.push("Schema and role findings");
    for (const finding of schemaFindings) {
      lines.push(renderSchemaFinding(finding));
    }
    lines.push("");
  }

  for (const table of report.tables) {
    lines.push(renderTable(table));
  }

  if (report.tables.length === 0) {
    lines.push("No tables found in the selected schemas.");
  }

  return `${lines.join("\n")}\n`;
}

function renderSchemaFinding(finding: SchemaFinding): string {
  const lines = [
    `  [${severityLabel[finding.severity]}] ${finding.title}`,
    `    Scope: ${finding.schema ?? "database-wide / role level"}`,
    `    ${finding.detail}`,
    `    Fix: ${finding.recommendation}`
  ];
  if (finding.suggestedSql && finding.suggestedSql.length > 0) {
    lines.push("    Suggested SQL:");
    for (const sqlLine of finding.suggestedSql) lines.push(`      ${sqlLine}`);
  }
  return lines.join("\n");
}

export function renderExplainReport(table: TableAudit): string {
  const lines: string[] = [];
  const highestRisk: HighestSeverity = table.findings
    .map((finding) => finding.severity)
    .sort((a, b) => severityWeight(b) - severityWeight(a))[0] ?? "none";

  lines.push(`RLS Doctor Explain: ${table.schema}.${table.table}`);
  lines.push(`RLS: ${table.rlsEnabled ? "enabled" : "disabled"}`);
  lines.push(`Force RLS: ${table.forceRls ? "enabled" : "disabled"}`);
  lines.push(`Policies: ${table.policies.length}`);
  lines.push(`Risk: ${severityLabel[highestRisk]}`);
  lines.push("");

  if (table.policies.length > 0) {
    lines.push("Policies");
    for (const policy of table.policies) {
      lines.push(
        `  - ${policy.name}: ${policy.command}, ${policy.permissive ? "permissive" : "restrictive"}, roles ${policy.roles.join(", ")}`
      );
    }
    lines.push("");
  }

  lines.push("Next steps");
  if (table.findings.length === 0) {
    lines.push("  - No catalog-level issues found for this table.");
  } else {
    for (const finding of table.findings) {
      lines.push(`  - [${severityLabel[finding.severity]}] ${finding.recommendation}`);
      if (finding.suggestedSql && finding.suggestedSql.length > 0) {
        lines.push("    Suggested SQL:");
        for (const sqlLine of finding.suggestedSql) {
          lines.push(`      ${sqlLine}`);
        }
      }
    }
  }

  return `${lines.join("\n")}\n`;
}

function renderTable(table: TableAudit): string {
  const lines: string[] = [];
  const status = table.rlsEnabled ? "RLS enabled" : "RLS disabled";
  const force = table.forceRls ? "force RLS enabled" : "force RLS disabled";

  lines.push(`${table.schema}.${table.table}`);
  lines.push(`  ${status}; ${force}; ${table.policies.length} policies`);

  if (table.findings.length === 0) {
    lines.push("  OK: no findings from catalog checks");
    lines.push("");
    return lines.join("\n");
  }

  for (const finding of table.findings) {
    lines.push(`  [${severityLabel[finding.severity]}] ${finding.title}`);
    lines.push(`    ${finding.detail}`);
    lines.push(`    Fix: ${finding.recommendation}`);
    if (finding.suggestedSql && finding.suggestedSql.length > 0) {
      lines.push("    Suggested SQL:");
      for (const sqlLine of finding.suggestedSql) {
        lines.push(`      ${sqlLine}`);
      }
    }
  }

  lines.push("");
  return lines.join("\n");
}

function severityWeight(severity: Severity): number {
  const weights: Record<Severity, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  };

  return weights[severity];
}
