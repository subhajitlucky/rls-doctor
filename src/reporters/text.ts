import type { AuditReport, Severity, TableAudit } from "../audit/types.js";

const severityLabel: Record<Severity, string> = {
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

  for (const table of report.tables) {
    lines.push(renderTable(table));
  }

  if (report.tables.length === 0) {
    lines.push("No tables found in the selected schemas.");
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
  }

  lines.push("");
  return lines.join("\n");
}
