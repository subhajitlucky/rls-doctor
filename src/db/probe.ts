import pg from "pg";
import type {
  ProbeExecutionResult,
  ProbeRoleError,
  ProbeRunResult,
  ProbeStatus,
  ProbeTarget
} from "../audit/types.js";

const { Client } = pg;

export interface ProbeOptions {
  connectionString: string;
  schemas: string[];
  appRoles: readonly string[];
  ownerColumns: readonly string[];
  tables?: readonly string[];
  sampleLimit?: number;
  statementTimeoutMs?: number;
  generatedAt?: Date;
}

const DEFAULT_SAMPLE_LIMIT = 1_000;

export async function runProbes(options: ProbeOptions): Promise<ProbeRunResult> {
  const client = new Client({
    connectionString: options.connectionString,
    statement_timeout: options.statementTimeoutMs ?? 10_000,
    application_name: "rls-doctor-probe"
  });

  await client.connect();

  let transactionStarted = false;

  try {
    // A single read-only, rolled-back transaction guarantees probes never mutate the
    // audited database, even when role impersonation would otherwise allow writes.
    await client.query("begin transaction isolation level repeatable read read only");
    transactionStarted = true;

    const probes: ProbeExecutionResult[] = [];
    const roleErrors: ProbeRoleError[] = [];

    const existingRoles = new Set(
      (
        await client.query<{ rolname: string }>(
          "select rolname from pg_roles where rolname = any($1)",
          [[...options.appRoles]]
        )
      ).rows.map((row) => row.rolname)
    );
    const probeRoles = options.appRoles.filter((role) => {
      if (existingRoles.has(role)) return true;
      roleErrors.push({ role, message: `role "${role}" does not exist` });
      return false;
    });

    const targets = await loadProbeTargets(client, options, probeRoles);

    for (const role of probeRoles) {
      await client.query("savepoint probe_role");
      try {
        await client.query(`set local role ${quoteIdentifier(role)}`);
      } catch (error) {
        // An aborted transaction stays usable after rolling back to the savepoint.
        await client.query("rollback to savepoint probe_role");
        await client.query("release savepoint probe_role");
        roleErrors.push({ role, message: errorMessage(error) });
        continue;
      }

      for (const target of targets) {
        probes.push(
          await probeTable(client, role, target, options.sampleLimit ?? DEFAULT_SAMPLE_LIMIT)
        );
      }

      await client.query("reset role");
      await client.query("release savepoint probe_role");
    }

    await client.query("rollback");
    transactionStarted = false;

    return { probes, roleErrors };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("rollback");
      } catch {
        // Preserve the probe error; connection cleanup still runs below.
      }
    }

    throw error;
  } finally {
    await client.end();
  }
}

async function loadProbeTargets(
  client: pg.Client,
  options: ProbeOptions,
  probeRoles: readonly string[]
): Promise<ProbeTarget[]> {
  const tables = await client.query<{ schema: string; table: string }>(
    `select n.nspname as schema, c.relname as "table"
       from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
      where c.relkind = any(array['r', 'p'])
        and n.nspname = any($1)
        and (
          c.relrowsecurity
          or exists (
            select 1
              from unnest($2::text[]) as probed_role(name)
             where has_table_privilege(probed_role.name, c.oid, 'SELECT')
          )
        )
      order by n.nspname, c.relname`,
    [[...options.schemas], [...probeRoles]]
  );

  const columns = await client.query<{ schema: string; table: string; column: string }>(
    `select table_schema as schema, table_name as "table", column_name as column
       from information_schema.columns
      where table_schema = any($1)
        and column_name = any($2)`,
    [[...options.schemas], [...options.ownerColumns]]
  );
  const ownerColumnsByTable = new Map<string, Set<string>>();
  for (const row of columns.rows) {
    const key = `${row.schema}.${row.table}`;
    const existing = ownerColumnsByTable.get(key) ?? new Set<string>();
    existing.add(row.column);
    ownerColumnsByTable.set(key, existing);
  }

  const filter = options.tables?.map((table) => table.trim()).filter((table) => table.length > 0);

  return tables.rows
    .filter((row) => {
      if (!filter || filter.length === 0) return true;
      return filter.some(
        (entry) => entry === row.table || entry === `${row.schema}.${row.table}`
      );
    })
    .map((row) => {
      const available = ownerColumnsByTable.get(`${row.schema}.${row.table}`);
      const ownerColumn = options.ownerColumns.find((column) => available?.has(column)) ?? null;
      return { schema: row.schema, table: row.table, ownerColumn };
    });
}

async function probeTable(
  client: pg.Client,
  role: string,
  target: ProbeTarget,
  sampleLimit: number
): Promise<ProbeExecutionResult> {
  const qualified = `${quoteIdentifier(target.schema)}.${quoteIdentifier(target.table)}`;
  const base = {
    role,
    schema: target.schema,
    table: target.table,
    ownerColumn: target.ownerColumn
  };

  try {
    await client.query("savepoint probe_sample");
    let sampled: pg.QueryResult<{ count: string }>;
    try {
      sampled = await client.query<{ count: string }>(
        `select count(*)::text as count
           from (select 1 from ${qualified} limit ${sampleLimit}) as sample`
      );
      await client.query("release savepoint probe_sample");
    } catch (error) {
      await client.query("rollback to savepoint probe_sample");
      await client.query("release savepoint probe_sample");
      throw error;
    }
    const sampledRows = Number(sampled.rows[0]?.count ?? 0);

    let distinctOwners: number | null = null;
    if (target.ownerColumn !== null && sampledRows > 0) {
      await client.query("savepoint probe_owners");
      try {
        const owners = await client.query<{ count: string }>(
          `select count(distinct ${quoteIdentifier(target.ownerColumn)})::text as count
             from (select ${quoteIdentifier(target.ownerColumn)} from ${qualified} limit ${sampleLimit}) as sample`
        );
        await client.query("release savepoint probe_owners");
        distinctOwners = Number(owners.rows[0]?.count ?? 0);
      } catch (error) {
        await client.query("rollback to savepoint probe_owners");
        await client.query("release savepoint probe_owners");
        throw error;
      }
    }

    const status: ProbeStatus = sampledRows > 0 ? "rows" : "none";
    return { ...base, status, sampledRows, distinctOwners, error: null };
  } catch (error) {
    if (isPermissionDenied(error)) {
      return { ...base, status: "denied", sampledRows: 0, distinctOwners: null, error: null };
    }

    return {
      ...base,
      status: "error",
      sampledRows: 0,
      distinctOwners: null,
      error: errorMessage(error)
    };
  }
}

function isPermissionDenied(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === "42501";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function quoteIdentifier(identifier: string): string {
  if (identifier.includes("\0")) {
    throw new Error("Identifiers must not contain NUL bytes.");
  }

  return `"${identifier.replaceAll('"', '""')}"`;
}
