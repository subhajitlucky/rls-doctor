import pg from "pg";
import type { CatalogSnapshot, PolicyCommand, PolicySnapshot, TableSnapshot } from "../audit/types.js";

const { Client } = pg;

export interface LoadCatalogOptions {
  connectionString: string;
  schemas: string[];
  statementTimeoutMs?: number;
}

interface TableRow {
  schema: string;
  name: string;
  rls_enabled: boolean;
  force_rls: boolean;
  is_partitioned: boolean;
  estimated_rows: string | number | null;
}

interface PolicyRow {
  schema: string;
  table: string;
  name: string;
  command: string;
  permissive: string | boolean;
  roles: string[] | string;
  using_expression: string | null;
  check_expression: string | null;
}

export async function loadCatalog(options: LoadCatalogOptions): Promise<CatalogSnapshot> {
  const client = new Client({
    connectionString: options.connectionString,
    statement_timeout: options.statementTimeoutMs ?? 10_000,
    application_name: "rls-doctor"
  });

  await client.connect();

  try {
    const [tables, policies] = await Promise.all([
      client.query<TableRow>(tablesSql, [options.schemas]),
      client.query<PolicyRow>(policiesSql, [options.schemas])
    ]);

    return {
      tables: tables.rows.map(mapTable),
      policies: policies.rows.map(mapPolicy)
    };
  } finally {
    await client.end();
  }
}

function mapTable(row: TableRow): TableSnapshot {
  return {
    schema: row.schema,
    name: row.name,
    rlsEnabled: row.rls_enabled,
    forceRls: row.force_rls,
    isPartitioned: row.is_partitioned,
    estimatedRows: row.estimated_rows === null ? null : Number(row.estimated_rows)
  };
}

function mapPolicy(row: PolicyRow): PolicySnapshot {
  return {
    schema: row.schema,
    table: row.table,
    name: row.name,
    command: normalizeCommand(row.command),
    permissive: row.permissive === true || row.permissive === "PERMISSIVE",
    roles: normalizePolicyRoles(row.roles),
    usingExpression: row.using_expression,
    checkExpression: row.check_expression
  };
}

export function normalizePolicyRoles(roles: string[] | string): string[] {
  if (Array.isArray(roles)) {
    return roles;
  }

  const trimmed = roles.trim();

  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    return trimmed
      .slice(1, -1)
      .split(",")
      .map((role) => role.replace(/^"|"$/g, "").trim())
      .filter(Boolean);
  }

  return trimmed ? [trimmed] : [];
}

function normalizeCommand(command: string): PolicyCommand {
  const normalized = command.toUpperCase();

  if (["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"].includes(normalized)) {
    return normalized as PolicyCommand;
  }

  return "ALL";
}

const tablesSql = `
  select
    n.nspname as schema,
    c.relname as name,
    c.relrowsecurity as rls_enabled,
    c.relforcerowsecurity as force_rls,
    c.relkind = 'p' as is_partitioned,
    c.reltuples::bigint as estimated_rows
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')
    and n.nspname = any($1::text[])
  order by n.nspname, c.relname;
`;

const policiesSql = `
  select
    schemaname as schema,
    tablename as table,
    policyname as name,
    cmd as command,
    permissive,
    roles,
    qual as using_expression,
    with_check as check_expression
  from pg_policies
  where schemaname = any($1::text[])
  order by schemaname, tablename, policyname;
`;
