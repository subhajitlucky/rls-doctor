import pg from "pg";
import type {
  CatalogSnapshot,
  DefaultPrivilegeSnapshot,
  PolicyCommand,
  PolicySnapshot,
  RelationPrivilege,
  RelationPrivilegeSnapshot,
  RoleMembershipSnapshot,
  RoleSnapshot,
  TableSnapshot
} from "../audit/types.js";

const { Client } = pg;

export interface LoadCatalogOptions {
  connectionString: string;
  schemas: string[];
  statementTimeoutMs?: number;
}

export interface TableRow {
  schema: string;
  name: string;
  owner: string;
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

export interface RelationPrivilegeRow {
  schema: string;
  table: string;
  grantor: string;
  grantee_oid: string | number;
  grantee: string | null;
  privilege: string;
  grantable: boolean;
}

export interface DefaultPrivilegeRow {
  schema: string | null;
  owner: string;
  grantee_oid: string | number;
  grantee: string | null;
  object_type: string;
  privilege: string;
  grantable: boolean;
}

export interface RoleRow {
  name: string;
  superuser: boolean;
  bypass_rls: boolean;
  inherits: boolean;
}

export interface RoleMembershipRow {
  role: string;
  member: string;
}

export async function loadCatalog(options: LoadCatalogOptions): Promise<CatalogSnapshot> {
  const client = new Client({
    connectionString: options.connectionString,
    statement_timeout: options.statementTimeoutMs ?? 10_000,
    application_name: "rls-doctor"
  });

  await client.connect();

  try {
    const [tables, policies, relationPrivileges, defaultPrivileges, roles, roleMemberships] =
      await Promise.all([
        client.query<TableRow>(tablesSql, [options.schemas]),
        client.query<PolicyRow>(policiesSql, [options.schemas]),
        client.query<RelationPrivilegeRow>(relationPrivilegesSql, [options.schemas]),
        client.query<DefaultPrivilegeRow>(defaultPrivilegesSql, [options.schemas]),
        client.query<RoleRow>(rolesSql),
        client.query<RoleMembershipRow>(roleMembershipsSql)
      ]);

    return {
      tables: tables.rows.map(mapTable),
      policies: policies.rows.map(mapPolicy),
      relationPrivileges: relationPrivileges.rows.map(mapRelationPrivilege),
      defaultPrivileges: defaultPrivileges.rows.map(mapDefaultPrivilege),
      roles: roles.rows.map(mapRole),
      roleMemberships: roleMemberships.rows.map(mapRoleMembership)
    };
  } finally {
    await client.end();
  }
}

export function mapTable(row: TableRow): TableSnapshot {
  return {
    schema: row.schema,
    name: row.name,
    owner: row.owner,
    rlsEnabled: row.rls_enabled,
    forceRls: row.force_rls,
    isPartitioned: row.is_partitioned,
    estimatedRows: row.estimated_rows === null ? null : Number(row.estimated_rows)
  };
}

export function mapRelationPrivilege(row: RelationPrivilegeRow): RelationPrivilegeSnapshot {
  return {
    schema: row.schema,
    table: row.table,
    grantor: row.grantor,
    grantee: normalizeGrantee(row.grantee_oid, row.grantee),
    privilege: normalizeRelationPrivilege(row.privilege),
    grantable: row.grantable
  };
}

export function mapDefaultPrivilege(row: DefaultPrivilegeRow): DefaultPrivilegeSnapshot {
  if (row.object_type !== "TABLE") {
    throw new Error(`Unexpected default privilege object type: ${row.object_type}`);
  }

  return {
    schema: row.schema,
    owner: row.owner,
    grantee: normalizeGrantee(row.grantee_oid, row.grantee),
    objectType: row.object_type,
    privilege: row.privilege,
    grantable: row.grantable
  };
}

export function mapRole(row: RoleRow): RoleSnapshot {
  return {
    name: row.name,
    superuser: row.superuser,
    bypassRls: row.bypass_rls,
    inherits: row.inherits
  };
}

export function mapRoleMembership(row: RoleMembershipRow): RoleMembershipSnapshot {
  return {
    role: row.role,
    member: row.member
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

function normalizeRelationPrivilege(privilege: string): RelationPrivilege {
  if (
    ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"].includes(
      privilege
    )
  ) {
    return privilege as RelationPrivilege;
  }

  throw new Error(`Unexpected relation privilege: ${privilege}`);
}

function normalizeGrantee(granteeOid: string | number, grantee: string | null): string {
  if (Number(granteeOid) === 0) {
    return "PUBLIC";
  }

  if (grantee === null) {
    throw new Error(`Could not resolve privilege grantee OID: ${granteeOid}`);
  }

  return grantee;
}

const tablesSql = `
  select
    n.nspname as schema,
    c.relname as name,
    pg_get_userbyid(c.relowner) as owner,
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

const relationPrivilegesSql = `
  select
    n.nspname as schema,
    c.relname as table,
    pg_get_userbyid(acl.grantor) as grantor,
    acl.grantee::text as grantee_oid,
    case when acl.grantee = 0 then null else pg_get_userbyid(acl.grantee) end as grantee,
    acl.privilege_type as privilege,
    acl.is_grantable as grantable
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) acl
  where c.relkind in ('r', 'p')
    and n.nspname = any($1::text[])
  order by n.nspname, c.relname, grantee, privilege, grantor;
`;

const defaultPrivilegesSql = `
  select
    n.nspname as schema,
    pg_get_userbyid(d.defaclrole) as owner,
    acl.grantee::text as grantee_oid,
    case when acl.grantee = 0 then null else pg_get_userbyid(acl.grantee) end as grantee,
    'TABLE' as object_type,
    acl.privilege_type as privilege,
    acl.is_grantable as grantable
  from pg_default_acl d
  left join pg_namespace n on n.oid = d.defaclnamespace
  cross join lateral aclexplode(d.defaclacl) acl
  where d.defaclobjtype = 'r'
    and (d.defaclnamespace = 0 or n.nspname = any($1::text[]))
  order by schema nulls first, owner, grantee, privilege;
`;

const rolesSql = `
  select
    rolname as name,
    rolsuper as superuser,
    rolbypassrls as bypass_rls,
    rolinherit as inherits
  from pg_roles
  order by rolname;
`;

const roleMembershipsSql = `
  select
    role.rolname as role,
    member.rolname as member
  from pg_auth_members membership
  join pg_roles role on role.oid = membership.roleid
  join pg_roles member on member.oid = membership.member
  order by role.rolname, member.rolname;
`;
