# RLS Doctor Architecture

`rls-doctor` is designed as a small CLI with clear boundaries. The goal is to keep database access, audit logic, reporting, and shell behavior easy to test independently.

## System Shape

```txt
User / CI
  |
  v
CLI parser
  |
  v
Catalog loader
  |
  v
Audit analyzer
  |
  +--> Text reporter
  |
  +--> JSON reporter
  |
  v
Exit code
```

## Modules

| Module | Responsibility |
| --- | --- |
| `src/cli.ts` | Parses commands, validates options, resolves environment fallback, sets exit codes. |
| `src/db/catalog.ts` | Reads tables, policies, relation/schema/default privileges, roles, and memberships from PostgreSQL catalogs. |
| `src/audit/analyzer.ts` | Converts catalog snapshots into findings, severity summaries, and table-level explanations. |
| `src/reporters/text.ts` | Renders human-readable terminal output for local use. |
| `src/reporters/json.ts` | Renders machine-readable output for CI and automation. |
| `src/index.ts` | Exposes library functions and types for programmatic use. |

## Data Flow

1. The CLI receives a command such as `check` or `explain`.
2. It resolves `--connection`, `DATABASE_URL`, or `SUPABASE_DB_URL`.
3. The catalog loader opens a Postgres connection using `pg`.
4. It queries table/policy metadata plus relation ACLs, schema ACLs, default ACLs, role attributes, and memberships.
5. The analyzer builds application-role reachability, groups policies by table/command, and creates table and schema/role findings.
6. A reporter renders either text or JSON.
7. The CLI sets exit code `1` when findings meet the configured threshold. Commander also uses `1` for usage/option parse errors; caught action, connection, and catalog failures use `2`.

## Security Model

`rls-doctor` is read-only by design.

- It does not run migrations.
- It does not mutate tables, grants, or policies.
- It does not call Supabase management APIs.
- It sanitizes credentials from connection errors. Prefer environment variables because `--connection` can still appear in shell history or process listings.
- It supports read-only database users.

The tool only needs enough database permission to inspect catalog metadata for the selected schemas.

## Risk Model

The analyzer keeps two independent layers explicit: privileges determine whether a role can reach an object, while policies restrict rows after access is granted. Current table exposure requires a compatible relation privilege and schema `USAGE`; direct, inherited, and `SET ROLE` routes are considered. PostgreSQL 16 membership `INHERIT`/`SET` options are respected, and PostgreSQL 15 memberships use the server's legacy member-`INHERIT` plus `SET ROLE` behavior.

Policy analysis is command-aware: `SELECT` and `DELETE` use `USING`, `INSERT` uses `WITH CHECK`, and `UPDATE` uses both. An omitted `UPDATE`/`ALL` `WITH CHECK` falls back to `USING`. `ALL` participates in every applicable command, and permissive policies for one role/command are analyzed together because they are OR-combined.

The analyzer focuses on mistakes that are common, high-signal, and explainable:

- RLS disabled, distinguished by whether application access is currently reachable.
- RLS enabled with no policies.
- Public-like roles with unconditional read access.
- Public-like roles with unconditional write access.
- Command-specific unconditional or effectively unconstrained policies.
- Reachable `TRUNCATE`, which is independent of RLS.
- Broad default table privileges, represented as potential future exposure rather than current access.
- Application membership paths to superuser or `BYPASSRLS` roles.
- Public-like permissive policies.
- Missing `FORCE ROW LEVEL SECURITY` hardening.

Table owners bypass RLS unless `FORCE ROW LEVEL SECURITY` is enabled; superusers and `BYPASSRLS` roles bypass it regardless. The loader reports stored default ACL entries and does not claim exact reconstruction of explicit empty overrides.

The tool cannot prove arbitrary SQL predicate correctness, simulate requests, audit views/functions or hosted Supabase management settings, execute suggested SQL, or establish compliance. It should complement application tests and security review.

## Why Text and JSON Reporters Are Separate

Human users need concise terminal output with direct next steps. CI systems need stable structured data. JSON reports declare `schemaVersion: "1.0"`; `schemaFindings` holds findings not owned by a single existing table. Clean reports use `summary.highestSeverity: "none"`, and threshold evaluation counts actual findings so `--fail-on info` does not fail a clean audit.

## Testing Strategy

- Unit tests cover analyzer severity behavior and reporter output.
- Catalog role parsing is tested separately because Postgres drivers can return policy roles in different shapes.
- Integration tests run against a disposable Postgres Docker container and verify unsafe and safe schemas with `--fail-on high` using low-privilege audit credentials. The destructive fixture runner requires `RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS=1`; never set it against a shared, staging, or production database.

## Future Architecture Work

- Add SARIF reporter for GitHub code scanning.
- Add Markdown reporter for pull request comments.
- Add baseline support for known accepted findings.
- Add branch/policy diffing for migration review.
