# RLS Doctor v0.2 Design

## Goal

Strengthen `rls-doctor` so its findings reflect PostgreSQL policy-command semantics and the privilege layer that determines whether roles can reach RLS-protected objects.

## Scope

Version 0.2 focuses on correctness, catalog coverage, and CI reliability. It adds grant, default-privilege, role, and membership metadata; fixes command-specific policy analysis; improves combined-policy warnings and suggested SQL; introduces a clean `none` summary state; versions JSON output; sanitizes connection errors; and verifies `--fail-on high` against disposable PostgreSQL fixtures.

The release does not add SARIF, baselines, view/function auditing, complete partition analysis, or an access-simulation command. Those remain follow-up features.

## Architecture

The existing catalog-loader/analyzer/reporter separation remains intact:

```text
PostgreSQL catalogs
  -> typed catalog snapshot
     - tables and policies
     - explicit grants
     - default privileges
     - roles and memberships
  -> analyzer
     - command-aware policy checks
     - policy-combination warnings
     - exposed-table checks
     - privilege and default-privilege checks
  -> text and versioned JSON reporters
  -> threshold-based process exit code
```

Catalog queries collect facts only. The analyzer owns severity and recommendation decisions so the risk model remains deterministic and unit-testable.

Schema-level findings are represented separately from table audits. Existing report fields remain available, and JSON output gains a `schemaVersion` field.

## Policy Semantics

Checks are command-aware:

- `SELECT` evaluates `USING`.
- `DELETE` evaluates `USING` and is treated as a write operation.
- `INSERT` evaluates only `WITH CHECK`.
- `UPDATE` evaluates `USING` and `WITH CHECK`, including PostgreSQL's fallback from an omitted `WITH CHECK` to `USING`.
- `ALL` is evaluated across applicable operations.

This prevents restricted INSERT policies from being marked broad merely because they have no `USING` expression, and it detects broad anonymous DELETE policies.

Multiple permissive policies applying to the same role and command produce an advisory because they are OR-combined. Restrictive policies are accounted for as AND-combined constraints. Version 0.2 does not attempt to prove arbitrary SQL expressions equivalent; it reports explainable structural risks.

## Privilege Model

The catalog snapshot includes:

- explicit relation privileges;
- default relation privileges for future objects;
- role attributes such as superuser and `BYPASSRLS`;
- role memberships used to understand inherited access;
- table ownership.

The analyzer distinguishes a policy from a grant: a policy controls rows only after a role has object privileges. RLS-disabled findings use exposure information instead of claiming that every ungranted internal table is immediately reachable.

Findings explain that table owners normally bypass RLS unless FORCE RLS applies, while superusers and `BYPASSRLS` roles bypass RLS regardless.

## Reporting and Suggestions

A report with no findings uses `highestSeverity: "none"`. Threshold evaluation examines actual finding counts, so `--fail-on info` does not fail a clean or empty audit.

Suggested SQL is tailored to the policy command. Schema-specific identifiers that cannot be inferred, such as ownership columns, are presented as explicit placeholders rather than apparently executable assumptions.

Text output remains human-readable. JSON output preserves current fields and adds a schema version plus schema-level findings.

## Safety and Error Handling

The CLI remains read-only and does not call Supabase management APIs. It queries PostgreSQL catalogs only. Error formatting removes supplied connection strings and embedded URL credentials before writing to stderr. Documentation continues to prefer environment variables or read-only credentials over command-line connection strings.

## Testing

Development follows red-green-refactor:

- analyzer unit tests cover SELECT, INSERT, UPDATE, DELETE, and ALL;
- tests cover permissive/restrictive policy combinations;
- catalog and analyzer tests cover grants, default privileges, memberships, ownership, superuser, and `BYPASSRLS` metadata;
- reporter tests cover clean summaries, schema-level findings, and versioned JSON compatibility;
- CLI tests cover sanitized errors and threshold behavior;
- disposable PostgreSQL integration tests assert that an unsafe schema exits 1 with `--fail-on high`, a safe schema exits 0, and catalog reads work through a low-privilege audit role.

The full typecheck, unit suite, build, CLI version check, package audit, and PostgreSQL integration suite must pass before completion.
