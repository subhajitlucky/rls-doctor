import type { ProbeReport } from "../audit/types.js";

export function renderProbeJsonReport(report: ProbeReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function renderProbeTextReport(report: ProbeReport): string {
  const lines: string[] = [];
  lines.push(`RLS Doctor Probe: ${report.schemas.join(", ")} (roles: ${report.roles.join(", ")})`);
  lines.push("");

  const grouped = new Map<string, typeof report.probes>();
  for (const probe of report.probes) {
    const key = `${probe.schema}.${probe.table}`;
    const existing = grouped.get(key) ?? [];
    existing.push(probe);
    grouped.set(key, existing);
  }

  for (const [table, probes] of grouped) {
    lines.push(table);
    for (const probe of probes) {
      const details: string[] = [];
      if (probe.status === "rows") {
        details.push(`sampled ${probe.sampledRows} row(s)`);
        if (probe.distinctOwners !== null) {
          details.push(`${probe.distinctOwners} distinct ${probe.ownerColumn}`);
        }
      } else if (probe.status === "error" && probe.error !== null) {
        details.push(probe.error);
      }
      const suffix = details.length > 0 ? `  ${details.join(", ")}` : "";
      lines.push(`  ${probe.role.padEnd(20)} ${probe.status}${suffix}`);
    }
    lines.push("");
  }

  for (const roleError of report.findings.filter((finding) => finding.id === "probe-role-unavailable")) {
    lines.push(`Role error: ${roleError.detail}`);
  }

  const { findings } = report.summary;
  lines.push(
    `Probe summary: ${report.summary.probes} probe(s); by status ${JSON.stringify(report.summary.byStatus)}`
  );
  lines.push(
    `Findings: ${findings.info} info, ${findings.low} low, ${findings.medium} medium, ${findings.high} high, ${findings.critical} critical (highest: ${report.summary.highestSeverity})`
  );
  for (const finding of report.findings) {
    lines.push(`- [${finding.severity}] ${finding.id} ${finding.schema ?? ""}${finding.table ? `.${finding.table}` : ""}: ${finding.title}`);
  }

  return `${lines.join("\n")}\n`;
}
