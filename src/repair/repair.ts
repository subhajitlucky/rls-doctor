import type { PolicySnapshot, TableSnapshot } from "../audit/types.js";

const OWNER_COLUMN_CANDIDATES = ["owner_id", "user_id", "tenant_id", "account_id", "uid"];
const REPAIR_POLICY_NAME = "rls_doctor_owner_all";

export interface RepairPlan {
  schema: string;
  table: string;
  ownerColumn?: string;
  targets: string[];
  statements: string[];
  notes: string[];
}

function quote(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function qualified(table: { schema: string; name: string }): string {
  return `${quote(table.schema)}.${quote(table.name)}`;
}

export function ownerColumnFor(table: TableSnapshot): string | undefined {
  const columns = table.columns ?? [];
  return OWNER_COLUMN_CANDIDATES.find((candidate) => columns.includes(candidate));
}

/**
 * Generate a canonical, verifiable repair for a table whose row-level
 * security is disabled. The patch is never applied by the tool: it is
 * written only after shadow verification proves it closes the witness and
 * introduces no new findings.
 */
export function planRepair(table: TableSnapshot, roles: readonly string[]): RepairPlan | undefined {
  if (table.rlsEnabled) return undefined;
  const ownerColumn = ownerColumnFor(table);
  const statements = [`alter table ${qualified(table)} enable row level security;`];
  const notes: string[] = [];
  if (ownerColumn === undefined) {
    notes.push(
      "No owner-like column was detected, so the patch enables RLS without a policy: " +
      "every role is denied until a human adds an ownership policy.",
    );
  } else {
    const roleList = roles.length === 0 ? ["authenticated"] : [...roles];
    statements.push(
      `create policy ${quote(REPAIR_POLICY_NAME)} on ${qualified(table)} ` +
      `for all to ${roleList.map(quote).join(", ")} ` +
      `using (${quote(ownerColumn)} = auth.uid()) ` +
      `with check (${quote(ownerColumn)} = auth.uid());`,
    );
  }
  return {
    schema: table.schema,
    table: table.name,
    ...(ownerColumn === undefined ? {} : { ownerColumn }),
    targets: [`rls-disabled ${table.schema}.${table.name}`],
    statements,
    notes,
  };
}

export function renderPatch(plan: RepairPlan): string {
  const lines = [
    "-- Codebase Doctor verified repair",
    `-- Table: ${plan.schema}.${plan.table}`,
    ...(plan.ownerColumn === undefined
      ? []
      : [`-- Ownership column: ${plan.ownerColumn} (owner = auth.uid())`]),
    ...plan.notes.map((note) => `-- Note: ${note}`),
    "",
    ...plan.statements,
    "",
  ];
  return lines.join("\n");
}
