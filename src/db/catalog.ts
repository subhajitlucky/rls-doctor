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
  inherit_option: boolean;
  set_option: boolean;
}

export interface LegacyRoleMembershipRow {
  role: string;
  member: string;
  member_inherits: boolean;
}

interface ServerVersionRow {
  server_version_num: string;
}

export async function loadCatalog(options: LoadCatalogOptions): Promise<CatalogSnapshot> {
  const client = new Client({
    connectionString: options.connectionString,
    statement_timeout: options.statementTimeoutMs ?? 10_000,
    application_name: "rls-doctor"
  });

  await client.connect();

  let transactionStarted = false;

  try {
    await client.query("begin transaction isolation level repeatable read read only");
    transactionStarted = true;

    const version = await client.query<ServerVersionRow>("show server_version_num");
    const serverVersionNum = Number(version.rows[0]?.server_version_num);

    if (!Number.isInteger(serverVersionNum)) {
      throw new Error("PostgreSQL did not return a valid server_version_num");
    }

    // These reads are intentionally sequential. A single pg Client serializes Promise.all calls,
    // and one read-only REPEATABLE READ transaction guarantees a consistent catalog snapshot.
    const tables = await client.query<TableRow>(tablesSql, [options.schemas]);
    const policies = await client.query<PolicyRow>(policiesSql, [options.schemas]);
    const relationPrivileges = await client.query<RelationPrivilegeRow>(relationPrivilegesSql, [
      options.schemas
    ]);
    const defaultPrivileges = await client.query<DefaultPrivilegeRow>(defaultPrivilegesSql, [
      options.schemas
    ]);
    const roles = await client.query<RoleRow>(rolesSql);

    // PostgreSQL 16 introduced per-membership INHERIT and SET options. The legacy query must stay
    // separate so PostgreSQL 15 and older never parse columns that do not exist there.
    const roleMemberships =
      serverVersionNum >= 160_000
        ? (
            await client.query<RoleMembershipRow>(roleMembershipsSql)
          ).rows.map(mapRoleMembership)
        : (
            await client.query<LegacyRoleMembershipRow>(legacyRoleMembershipsSql)
          ).rows.map(mapLegacyRoleMembership);

    const snapshot: CatalogSnapshot = {
      tables: tables.rows.map(mapTable),
      policies: policies.rows.map(mapPolicy),
      relationPrivileges: relationPrivileges.rows.map(mapRelationPrivilege),
      defaultPrivileges: defaultPrivileges.rows.map(mapDefaultPrivilege),
      roles: roles.rows.map(mapRole),
      roleMemberships
    };

    const relevantTopology = filterRelevantRoleTopology(snapshot);
    await client.query("commit");
    transactionStarted = false;

    return { ...snapshot, ...relevantTopology };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("rollback");
      } catch {
        // Preserve the catalog error; connection cleanup still runs below.
      }
    }

    throw error;
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
    member: row.member,
    inheritOption: row.inherit_option,
    setOption: row.set_option
  };
}

export function mapLegacyRoleMembership(row: LegacyRoleMembershipRow): RoleMembershipSnapshot {
  return {
    role: row.role,
    member: row.member,
    // Before PostgreSQL 16, automatic inheritance was controlled by the member role's INHERIT
    // attribute, while every membership allowed SET ROLE.
    inheritOption: row.member_inherits,
    setOption: true
  };
}

export function filterRelevantRoleTopology(snapshot: CatalogSnapshot): {
  roles: RoleSnapshot[];
  roleMemberships: RoleMembershipSnapshot[];
} {
  const roles = snapshot.roles ?? [];
  const roleMemberships = snapshot.roleMemberships ?? [];
  const relevantNames = seedRelevantRoleNames(snapshot);
  const adjacency = new Map<string, Set<string>>();

  for (const membership of roleMemberships) {
    if (!membership.inheritOption && !membership.setOption) {
      continue;
    }

    addNeighbor(adjacency, membership.role, membership.member);
    addNeighbor(adjacency, membership.member, membership.role);
  }

  const queue = [...relevantNames];
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index]!;
    for (const neighbor of adjacency.get(current) ?? []) {
      if (!relevantNames.has(neighbor)) {
        relevantNames.add(neighbor);
        queue.push(neighbor);
      }
    }
  }

  // The cluster catalogs are needed to compute recursive closure, but only the connected
  // inheritance/SET ROLE neighborhoods rooted in audited catalog identities leave the loader.
  return {
    roles: roles.filter((role) => relevantNames.has(role.name)),
    roleMemberships: roleMemberships.filter(
      (membership) =>
        relevantNames.has(membership.role) && relevantNames.has(membership.member)
    )
  };
}

function seedRelevantRoleNames(snapshot: CatalogSnapshot): Set<string> {
  const names = new Set<string>();

  for (const table of snapshot.tables) {
    if (table.owner) names.add(table.owner);
  }

  for (const policy of snapshot.policies) {
    for (const role of policy.roles) {
      if (role !== "public") names.add(role);
    }
  }

  for (const privilege of snapshot.relationPrivileges ?? []) {
    names.add(privilege.grantor);
    if (privilege.grantee !== "PUBLIC") names.add(privilege.grantee);
  }

  for (const privilege of snapshot.defaultPrivileges ?? []) {
    names.add(privilege.owner);
    if (privilege.grantee !== "PUBLIC") names.add(privilege.grantee);
  }

  return names;
}

function addNeighbor(adjacency: Map<string, Set<string>>, role: string, neighbor: string): void {
  const neighbors = adjacency.get(role) ?? new Set<string>();
  neighbors.add(neighbor);
  adjacency.set(role, neighbors);
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
    member.rolname as member,
    membership.inherit_option,
    membership.set_option
  from pg_auth_members membership
  join pg_roles role on role.oid = membership.roleid
  join pg_roles member on member.oid = membership.member
  order by role.rolname, member.rolname;
`;

const legacyRoleMembershipsSql = `
  select
    role.rolname as role,
    member.rolname as member,
    member.rolinherit as member_inherits
  from pg_auth_members membership
  join pg_roles role on role.oid = membership.roleid
  join pg_roles member on member.oid = membership.member
  order by role.rolname, member.rolname;
`;
