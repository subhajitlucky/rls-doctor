import { describe, expect, it } from "vitest";
import {
  mapDefaultPrivilege,
  mapRelationPrivilege,
  mapRole,
  mapRoleMembership,
  mapTable,
  normalizePolicyRoles
} from "../src/db/catalog.js";

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

  it("maps role memberships without folding either identity", () => {
    expect(mapRoleMembership({ role: "Reporting Team", member: "CaseSensitiveUser" })).toEqual({
      role: "Reporting Team",
      member: "CaseSensitiveUser"
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
