import { describe, expect, it } from "vitest";
import {
  filterRelevantRoleTopology,
  mapDefaultPrivilege,
  mapLegacyRoleMembership,
  mapRelationPrivilege,
  mapRole,
  mapRoleMembership,
  mapSchemaPrivilege,
  mapTable,
  normalizePolicyRoles,
  schemaPrivilegesSql
} from "../src/db/catalog.js";
import type {
  CatalogSnapshot as PublicCatalogSnapshot,
  DefaultPrivilegeSnapshot,
  RelationPrivilege,
  RelationPrivilegeSnapshot,
  RoleMembershipSnapshot,
  RoleSnapshot
} from "../src/index.js";

describe("normalizePolicyRoles", () => {
  it("keeps native Postgres text arrays", () => {
    expect(normalizePolicyRoles(["authenticated", "service_role"])).toEqual([
      "authenticated",
      "service_role"
    ]);
  });

  it("parses text-array strings returned by some pg catalog queries", () => {
    expect(normalizePolicyRoles("{public,authenticated}")).toEqual(["public", "authenticated"]);
  });

  it("parses quoted text-array strings", () => {
    expect(normalizePolicyRoles('{"anon","authenticated"}')).toEqual(["anon", "authenticated"]);
  });
});

describe("catalog row mapping", () => {
  it("queries selected schema ACLs with namespace defaults and stable ordering", () => {
    expect(schemaPrivilegesSql).toContain("acldefault('n', n.nspowner)");
    expect(schemaPrivilegesSql).toContain("n.nspname = any($1::text[])");
    expect(schemaPrivilegesSql).toContain("order by n.nspname, grantee, privilege, grantor");
  });
  it("maps relation privileges expanded from an existing relation ACL", () => {
    expect(
      mapRelationPrivilege({
        schema: "app",
        table: "Accounts",
        grantor: "Database Owner",
        grantee_oid: "0",
        grantee: null,
        privilege: "SELECT",
        grantable: false
      })
    ).toEqual({
      schema: "app",
      table: "Accounts",
      grantor: "Database Owner",
      grantee: "PUBLIC",
      privilege: "SELECT",
      grantable: false
    });
  });

  it("maps schema privileges including PUBLIC", () => {
    expect(mapSchemaPrivilege({ schema: "private", grantor: "Owner", grantee_oid: "0", grantee: null, privilege: "USAGE", grantable: false })).toEqual({
      schema: "private", grantor: "Owner", grantee: "PUBLIC", privilege: "USAGE", grantable: false
    });
  });

  it("maps schema-specific default table privileges", () => {
    expect(
      mapDefaultPrivilege({
        schema: "Mixed Case Schema",
        owner: "Owner Role",
        grantee_oid: "16402",
        grantee: "ReadOnly",
        object_type: "TABLE",
        privilege: "SELECT",
        grantable: true
      })
    ).toEqual({
      schema: "Mixed Case Schema",
      owner: "Owner Role",
      grantee: "ReadOnly",
      objectType: "TABLE",
      privilege: "SELECT",
      grantable: true
    });
  });

  it("preserves a null schema and PUBLIC grantee for global default privileges", () => {
    expect(
      mapDefaultPrivilege({
        schema: null,
        owner: "Owner Role",
        grantee_oid: "0",
        grantee: null,
        object_type: "TABLE",
        privilege: "INSERT",
        grantable: false
      })
    ).toMatchObject({ schema: null, grantee: "PUBLIC" });
  });

  it("maps security-relevant role attributes without folding role names", () => {
    expect(
      mapRole({ name: "Case Sensitive Admin", superuser: true, bypass_rls: true, inherits: false })
    ).toEqual({
      name: "Case Sensitive Admin",
      superuser: true,
      bypassRls: true,
      inherits: false
    });
  });

  it("maps PostgreSQL 16 membership options without folding either identity", () => {
    expect(
      mapRoleMembership({
        role: "Reporting Team",
        member: "CaseSensitiveUser",
        inherit_option: true,
        set_option: false
      })
    ).toEqual({
      role: "Reporting Team",
      member: "CaseSensitiveUser",
      inheritOption: true,
      setOption: false
    });
  });

  it("preserves disabled PostgreSQL 16 membership options", () => {
    expect(
      mapRoleMembership({
        role: "No Automatic Access",
        member: "CaseSensitiveUser",
        inherit_option: false,
        set_option: false
      })
    ).toMatchObject({ inheritOption: false, setOption: false });
  });

  it("normalizes legacy memberships using member INHERIT and SET ROLE semantics", () => {
    expect(
      mapLegacyRoleMembership({
        role: "Reporting Team",
        member: "LegacyUser",
        member_inherits: false
      })
    ).toEqual({
      role: "Reporting Team",
      member: "LegacyUser",
      inheritOption: false,
      setOption: true
    });
  });

  it("maps table owner names", () => {
    expect(
      mapTable({
        schema: "app",
        name: "accounts",
        owner: "Table Owner",
        rls_enabled: true,
        force_rls: false,
        is_partitioned: false,
        estimated_rows: "12"
      })
    ).toMatchObject({ owner: "Table Owner", estimatedRows: 12 });
  });
});

describe("public snapshot compatibility", () => {
  it("accepts the pre-metadata catalog shape through the package type exports", () => {
    const snapshot: PublicCatalogSnapshot = {
      tables: [
        {
          schema: "public",
          name: "legacy_table",
          rlsEnabled: true,
          forceRls: false,
          isPartitioned: false,
          estimatedRows: null
        }
      ],
      policies: []
    };

    const exportedTypes: [
      RelationPrivilege?,
      RelationPrivilegeSnapshot?,
      DefaultPrivilegeSnapshot?,
      import("../src/index.js").SchemaPrivilegeSnapshot?,
      RoleSnapshot?,
      RoleMembershipSnapshot?
    ] = [];

    expect(snapshot.tables[0]?.name).toBe("legacy_table");
    expect(exportedTypes).toEqual([]);
  });
});

describe("filterRelevantRoleTopology", () => {
  it("retains standalone application paths to bypass roles and prunes unrelated components", () => {
    const roles = [
      { name: "Authenticated", superuser: false, bypassRls: false, inherits: true },
      { name: "admin", superuser: true, bypassRls: false, inherits: true },
      { name: "service", superuser: false, bypassRls: true, inherits: true },
      { name: "unrelated_a", superuser: false, bypassRls: false, inherits: true },
      { name: "unrelated_b", superuser: false, bypassRls: false, inherits: true }
    ];
    const roleMemberships = [
      {
        role: "admin",
        member: "Authenticated",
        inheritOption: false,
        setOption: true
      },
      {
        role: "unrelated_b",
        member: "unrelated_a",
        inheritOption: true,
        setOption: true
      }
    ];

    const result = filterRelevantRoleTopology({
      tables: [],
      policies: [],
      relationPrivileges: [],
      defaultPrivileges: [],
      roles,
      roleMemberships
    });

    expect(result.roles.map((role) => role.name)).toEqual(["Authenticated", "admin", "service"]);
    expect(result.roleMemberships).toEqual(roleMemberships.slice(0, 1));
  });

  it("seeds owners, policy roles, and privilege identities but not PUBLIC", () => {
    const role = (name: string) => ({
      name,
      superuser: false,
      bypassRls: false,
      inherits: true
    });

    const result = filterRelevantRoleTopology({
      tables: [
        {
          schema: "app",
          name: "documents",
          owner: "table_owner",
          rlsEnabled: true,
          forceRls: false,
          isPartitioned: false,
          estimatedRows: null
        }
      ],
      policies: [
        {
          schema: "app",
          table: "documents",
          name: "read documents",
          command: "SELECT",
          permissive: true,
          roles: ["policy_role", "public"],
          usingExpression: "true",
          checkExpression: null
        }
      ],
      relationPrivileges: [
        {
          schema: "app",
          table: "documents",
          grantor: "relation_grantor",
          grantee: "relation_grantee",
          privilege: "SELECT",
          grantable: false
        },
        {
          schema: "app",
          table: "documents",
          grantor: "relation_grantor",
          grantee: "PUBLIC",
          privilege: "SELECT",
          grantable: false
        }
      ],
      defaultPrivileges: [
        {
          schema: null,
          owner: "default_owner",
          grantee: "default_grantee",
          objectType: "TABLE",
          privilege: "SELECT",
          grantable: false
        }
      ],
      schemaPrivileges: [
        { schema: "app", grantor: "schema_grantor", grantee: "schema_grantee", privilege: "USAGE", grantable: false }
      ],
      roles: [
        role("default_grantee"),
        role("default_owner"),
        role("policy_role"),
        role("relation_grantee"),
        role("relation_grantor"),
        role("schema_grantee"),
        role("schema_grantor"),
        role("table_owner"),
        role("unrelated")
      ],
      roleMemberships: []
    });

    expect(result.roles.map((item) => item.name)).toEqual([
      "default_grantee",
      "default_owner",
      "policy_role",
      "relation_grantee",
      "relation_grantor",
      "schema_grantee",
      "schema_grantor",
      "table_owner"
    ]);
  });

  it("keeps only the cycle-safe transitive neighborhood of catalog roles", () => {
    const roles = [
      { name: "app_owner", superuser: false, bypassRls: false, inherits: true },
      { name: "app_user", superuser: false, bypassRls: false, inherits: true },
      { name: "cycle_a", superuser: false, bypassRls: false, inherits: true },
      { name: "cycle_b", superuser: false, bypassRls: false, inherits: true },
      { name: "reader", superuser: false, bypassRls: false, inherits: true },
      { name: "report_parent", superuser: false, bypassRls: false, inherits: true },
      { name: "unrelated", superuser: false, bypassRls: false, inherits: true }
    ];
    const roleMemberships = [
      {
        role: "reader",
        member: "app_user",
        inheritOption: true,
        setOption: true
      },
      {
        role: "report_parent",
        member: "reader",
        inheritOption: true,
        setOption: true
      },
      { role: "app_owner", member: "reader", inheritOption: false, setOption: false },
      { role: "cycle_a", member: "cycle_b", inheritOption: true, setOption: true },
      { role: "cycle_b", member: "cycle_a", inheritOption: true, setOption: true }
    ];

    const result = filterRelevantRoleTopology({
      tables: [
        {
          schema: "app",
          name: "documents",
          owner: "app_owner",
          rlsEnabled: true,
          forceRls: false,
          isPartitioned: false,
          estimatedRows: null
        }
      ],
      policies: [
        {
          schema: "app",
          table: "documents",
          name: "read documents",
          command: "SELECT",
          permissive: true,
          roles: ["reader", "public"],
          usingExpression: "true",
          checkExpression: null
        }
      ],
      relationPrivileges: [],
      defaultPrivileges: [],
      roles,
      roleMemberships
    });

    expect(result.roles.map((role) => role.name)).toEqual([
      "app_owner",
      "app_user",
      "reader",
      "report_parent"
    ]);
    expect(result.roleMemberships).toEqual(roleMemberships.slice(0, 3));
  });
});
