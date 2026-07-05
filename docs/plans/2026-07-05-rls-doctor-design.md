# RLS Doctor Design

## Goal

Build an original developer CLI that audits Postgres and Supabase Row Level Security posture without touching any hosted account settings.

## Positioning

`rls-doctor` is a local security assistant for developers. It connects with a read-only Postgres connection string, inspects catalog metadata, and reports risky RLS configuration before code reaches production.

## MVP

- `rls-doctor check` audits one or more schemas.
- Human-readable output for local development.
- JSON output for CI and automation.
- `--fail-on low|medium|high|critical|none` controls exit codes.
- No secrets are printed.
- Tests cover scoring, aggregation, and reporter output.

## Risk Model

The first version focuses on signals that can be detected from catalog metadata:

- RLS disabled on application tables.
- RLS enabled with no policies.
- Policies granted to anonymous/public-like roles.
- Permissive policies that look unconditional.
- Write policies without an explicit `WITH CHECK`.
- `FORCE ROW LEVEL SECURITY` disabled as a hardening advisory.

## Architecture

- `src/db/catalog.ts` reads `pg_class`, `pg_namespace`, and `pg_policies`.
- `src/audit/analyzer.ts` converts catalog rows into findings.
- `src/reporters/*` formats output without mixing presentation into audit logic.
- `src/cli.ts` handles command options, connection setup, and process exit behavior.

## Non-Goals

- Do not connect to Supabase management APIs.
- Do not mutate database schema.
- Do not generate production policies automatically in the MVP.
- Do not claim compliance certification.
