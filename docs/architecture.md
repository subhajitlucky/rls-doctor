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
| `src/db/catalog.ts` | Connects to Postgres and reads table/policy metadata from catalog views. |
| `src/audit/analyzer.ts` | Converts catalog snapshots into findings, severity summaries, and table-level explanations. |
| `src/reporters/text.ts` | Renders human-readable terminal output for local use. |
| `src/reporters/json.ts` | Renders machine-readable output for CI and automation. |
| `src/index.ts` | Exposes library functions and types for programmatic use. |

## Data Flow

1. The CLI receives a command such as `check` or `explain`.
2. It resolves `--connection`, `DATABASE_URL`, or `SUPABASE_DB_URL`.
3. The catalog loader opens a Postgres connection using `pg`.
4. It queries `pg_class`, `pg_namespace`, and `pg_policies` for the selected schemas.
5. The analyzer groups policies by table and creates findings.
6. A reporter renders either text or JSON.
7. The CLI sets exit code `1` only when findings meet the configured threshold.

## Security Model

`rls-doctor` is read-only by design.

- It does not run migrations.
- It does not mutate tables, grants, or policies.
- It does not call Supabase management APIs.
- It does not print the connection string.
- It supports read-only database users.

The tool only needs enough database permission to inspect catalog metadata for the selected schemas.

## Risk Model

The analyzer focuses on mistakes that are common, high-signal, and explainable:

- RLS disabled.
- RLS enabled with no policies.
- Public-like roles with unconditional read access.
- Public-like roles with unconditional write access.
- Write policies without `WITH CHECK`.
- Public-like permissive policies.
- Missing `FORCE ROW LEVEL SECURITY` hardening.

The tool intentionally avoids pretending that static catalog inspection can prove authorization correctness. It should complement application tests, grant reviews, and security review.

## Why Text and JSON Reporters Are Separate

Human users need concise terminal output with direct next steps. CI systems and future dashboards need stable structured data. Keeping those renderers separate prevents terminal formatting from leaking into automation output.

## Testing Strategy

- Unit tests cover analyzer severity behavior and reporter output.
- Catalog role parsing is tested separately because Postgres drivers can return policy roles in different shapes.
- Integration tests run against a disposable Postgres Docker container and load unsafe demo policies.

## Future Architecture Work

- Add SARIF reporter for GitHub code scanning.
- Add Markdown reporter for pull request comments.
- Add baseline support for known accepted findings.
- Add branch/policy diffing for migration review.
