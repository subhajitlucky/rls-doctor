export const DEMO_REPLAY_OUTPUT = `RLS Doctor Demo
===============

Started a disposable PostgreSQL container, applied the intentionally unsafe demo schema, and seeded two users' rows.

RLS Doctor Report
Generated: 2026-10-09T04:40:10.409Z
Schemas: rls_doctor_demo

Summary: 3 tables, 3 policies, highest risk CRITICAL
Findings: critical 1, high 4, medium 1, low 2, info 1
RLS Score: 29/100

Schema and role findings
  [HIGH] Broad default table privilege
    Scope: rls_doctor_demo
    Defaults for owner postgres in schema rls_doctor_demo grant grantee authenticated privilege INSERT; Application role authenticated. Future tables created by postgres can receive this object privilege without an explicit table grant; actual access also requires schema USAGE.
    Fix: Revoke the broad default privilege and grant only the table privileges required by each application role.

rls_doctor_demo.orders
  RLS disabled; force RLS disabled; 0 policies
  [HIGH] RLS-disabled table is reachable by an application role
    rls_doctor_demo.orders has no row-level checks; Application role authenticated and can exercise INSERT granted to authenticated.
    Fix: Enable RLS and add least-privilege policies for each application role.
    Suggested SQL:
      alter table "rls_doctor_demo"."orders" enable row level security;
      -- Then add policies that match your access model before exposing this table to client roles.

rls_doctor_demo.profiles
  RLS enabled; force RLS disabled; 2 policies
  [HIGH] TRUNCATE is reachable by an application role
    rls_doctor_demo.profiles can be truncated; Application role authenticated and can exercise TRUNCATE granted to authenticated. RLS never protects TRUNCATE.
    Fix: Revoke TRUNCATE from application-facing roles and grant it only to isolated maintenance roles.
  [INFO] FORCE ROW LEVEL SECURITY is disabled
    The table owner bypasses RLS while FORCE RLS is disabled. Superusers and BYPASSRLS roles bypass RLS regardless of FORCE RLS.
    Fix: Enable FORCE RLS for sensitive multi-tenant tables after confirming owner-side maintenance workflows.
    Suggested SQL:
      alter table "rls_doctor_demo"."profiles" force row level security;
  [CRITICAL] Anonymous-style role can write rows too broadly
    Policy "anon can update profiles" allows UPDATE for public with an unconditional predicate.
    Fix: Require authenticated ownership constraints in USING and WITH CHECK for writes.
    Suggested SQL:
      -- Adapt this suggested SQL to your schema and access model before executing it.
      alter policy "anon can update profiles"
        on "rls_doctor_demo"."profiles"
        to authenticated
        using ((select auth.uid()) = <owner_column>)
        with check ((select auth.uid()) = <owner_column>);
  [MEDIUM] Write policy has no explicit WITH CHECK expression
    Policy "anon can update profiles" handles UPDATE without an explicit insert/update constraint.
    Fix: Add WITH CHECK so new or changed rows must satisfy the same ownership and tenant boundaries.
    Suggested SQL:
      -- Adapt this suggested SQL to your schema and access model before executing it.
      alter policy "anon can update profiles"
        on "rls_doctor_demo"."profiles"
        with check ((select auth.uid()) = <owner_column>);
  [LOW] Public-like role uses a permissive policy
    Policy "anon can update profiles" is permissive, so it is OR-combined with other permissive policies.
    Fix: Review whether the policy should be restrictive or scoped to authenticated application roles.
  [HIGH] Anonymous-style role can read rows unconditionally
    Policy "anyone can read profiles" grants SELECT to public with no row predicate.
    Fix: Restrict the policy with tenant, owner, or explicit public-content predicates.
    Suggested SQL:
      -- Adapt this suggested SQL to your schema and access model before executing it.
      alter policy "anyone can read profiles"
        on "rls_doctor_demo"."profiles"
        using (<public_read_predicate>);
  [LOW] Public-like role uses a permissive policy
    Policy "anyone can read profiles" is permissive, so it is OR-combined with other permissive policies.
    Fix: Review whether the policy should be restrictive or scoped to authenticated application roles.

rls_doctor_demo.tasks
  RLS enabled; force RLS enabled; 1 policies
  OK: no findings from catalog checks

RLS Doctor Probe: rls_doctor_demo (roles: authenticated)

rls_doctor_demo.orders
  authenticated          rows  sampled 2 row(s), 2 distinct owner_id

rls_doctor_demo.profiles
  authenticated          none

rls_doctor_demo.tasks
  authenticated          denied

Probe summary: 3 probe(s); by status {"rows":1,"none":1,"denied":1,"error":0}
Findings: 2 info, 0 low, 0 medium, 1 high, 0 critical (highest: high)
- [high] probe-cross-owner-read rls_doctor_demo.orders: Role authenticated reads rows across 2 distinct owner_id values
- [info] probe-reads-no-rows rls_doctor_demo.profiles: Role authenticated sees no rows on rls_doctor_demo.profiles
- [info] probe-read-denied rls_doctor_demo.tasks: Role authenticated cannot read rls_doctor_demo.tasks

PROVEN: Role authenticated reads rows across 2 distinct owner_id values.
The probe impersonated the app role inside a read-only transaction and rolled back.
The container was removed. No database was modified.
`;
