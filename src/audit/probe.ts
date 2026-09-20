import type {
  HighestSeverity,
  ProbeFinding,
  ProbeReport,
  ProbeRunResult,
  ProbeStatus,
  Severity
} from "./types.js";

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
const probeStatuses: ProbeStatus[] = ["rows", "none", "denied", "error"];

export interface ProbeAnalysisOptions {
  schemas: string[];
  roles: string[];
  generatedAt?: Date;
}

export function analyzeProbeResults(
  run: ProbeRunResult,
  options: ProbeAnalysisOptions
): ProbeReport {
  const findings: ProbeFinding[] = [];

  for (const roleError of [...run.roleErrors].sort((left, right) => left.role.localeCompare(right.role))) {
    findings.push({
      id: "probe-role-unavailable",
      severity: "medium",
      schema: null,
      table: null,
      title: `Audit credentials cannot impersonate role ${roleError.role}`,
      detail: `SET LOCAL ROLE ${roleError.role} failed: ${roleError.message}`,
      recommendation:
        "Grant the audit connection membership in the application role, or run probes with a superuser connection."
    });
  }

  const probes = [...run.probes].sort(
    (left, right) =>
      left.schema.localeCompare(right.schema) ||
      left.table.localeCompare(right.table) ||
      left.role.localeCompare(right.role) ||
      (left.subject ?? "").localeCompare(right.subject ?? "")
  );

  for (const probe of probes) {
    const location = `${probe.schema}.${probe.table}`;
    const subjectContext = probe.subject === null ? "" : ` as subject ${probe.subject}`;

    if (
      probe.status === "rows" &&
      probe.subject !== null &&
      probe.foreignRows !== null &&
      probe.foreignRows > 0
    ) {
      findings.push({
        id: "probe-cross-subject-read",
        severity: "high",
        schema: probe.schema,
        table: probe.table,
        title: `Role ${probe.role} reads rows belonging to other users on ${location}`,
        detail: `As subject ${probe.subject}, role ${probe.role} read ${probe.foreignRows} row(s) on ${location} whose ${probe.ownerColumn} is not ${probe.subject} (own rows: ${probe.ownRows ?? 0}, sampled ${probe.sampledRows} row(s)).`,
        recommendation:
          "Tighten the policy predicate so this identity can only read rows it owns or that were explicitly shared with it."
      });
      continue;
    }

    if (probe.status === "rows" && probe.subject !== null && probe.ownRows !== null) {
      findings.push({
        id: "probe-subject-reads-own-rows",
        severity: "info",
        schema: probe.schema,
        table: probe.table,
        title: `Subject ${probe.subject} can read its own rows on ${location}`,
        detail: `As subject ${probe.subject}${subjectContext}, role ${probe.role} read ${probe.ownRows} owned row(s) and no rows owned by other subjects on ${location}.`,
        recommendation: "No action needed if this access is intended."
      });
      continue;
    }

    if (probe.status === "rows" && probe.distinctOwners !== null && probe.distinctOwners > 1) {
      findings.push({
        id: "probe-cross-owner-read",
        severity: "high",
        schema: probe.schema,
        table: probe.table,
        title: `Role ${probe.role} reads rows across ${probe.distinctOwners} distinct ${probe.ownerColumn} values`,
        detail: `As ${probe.role}, ${location} returned rows spanning ${probe.distinctOwners} distinct ${probe.ownerColumn} values (sampled ${probe.sampledRows} row(s)).`,
        recommendation:
          "Restrict the policy so each application identity can only read rows it owns or that were explicitly shared with it."
      });
      continue;
    }

    if (probe.status === "rows") {
      findings.push({
        id: "probe-reads-rows",
        severity: "info",
        schema: probe.schema,
        table: probe.table,
        title: `Role ${probe.role} can read rows on ${location}`,
        detail: `As ${probe.role}${subjectContext}, ${location} returned ${probe.sampledRows} row(s)${
          probe.distinctOwners === null
            ? ""
            : ` across ${probe.distinctOwners} distinct ${probe.ownerColumn} value(s)`
        }.`,
        recommendation: "Confirm this read access is intended for this identity."
      });
      continue;
    }

    if (probe.status === "denied") {
      findings.push({
        id: "probe-read-denied",
        severity: "info",
        schema: probe.schema,
        table: probe.table,
        title: `Role ${probe.role} cannot read ${location}`,
        detail: `As ${probe.role}${subjectContext}, reading ${location} was denied by table privileges.`,
        recommendation: "No action needed if this identity should not read this table."
      });
      continue;
    }

    if (probe.status === "none") {
      findings.push({
        id: "probe-reads-no-rows",
        severity: "info",
        schema: probe.schema,
        table: probe.table,
        title: `Role ${probe.role} sees no rows on ${location}`,
        detail: `As ${probe.role}${subjectContext}, ${location} returned zero rows, which is the expected result when RLS default-denies access.`,
        recommendation: "No action needed unless this identity is expected to read rows from this table."
      });
      continue;
    }

    findings.push({
      id: "probe-error",
      severity: "low",
      schema: probe.schema,
      table: probe.table,
      title: `Probe failed for role ${probe.role} on ${location}`,
      detail: `The probe query failed: ${probe.error ?? "unknown error"}`,
      recommendation: "Check table privileges and column types, then re-run the probe."
    });
  }

  const byStatus = Object.fromEntries(
    probeStatuses.map((status) => [status, probes.filter((probe) => probe.status === status).length])
  ) as Record<ProbeStatus, number>;

  const findingsBySeverity = Object.fromEntries(
    severities.map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length
    ])
  ) as Record<Severity, number>;

  return {
    schemaVersion: "1.0",
    generatedAt: (options.generatedAt ?? new Date()).toISOString(),
    schemas: options.schemas,
    roles: options.roles,
    summary: {
      probes: probes.length,
      byStatus,
      findings: findingsBySeverity,
      highestSeverity: highestSeverity(findingsBySeverity)
    },
    probes,
    findings
  };
}

export function shouldFailProbe(report: ProbeReport, failOn: Severity | "none"): boolean {
  if (failOn === "none") {
    return false;
  }

  const threshold = severityRank[failOn];
  return report.findings.some((finding) => severityRank[finding.severity] >= threshold);
}

function highestSeverity(findingsBySeverity: Record<Severity, number>): HighestSeverity {
  for (const severity of [...severities].reverse()) {
    if (findingsBySeverity[severity] > 0) {
      return severity;
    }
  }

  return "none";
}
