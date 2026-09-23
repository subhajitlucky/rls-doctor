# RLS Doctor

[![CI](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/rls-doctor.svg)](https://www.npmjs.com/package/rls-doctor)
[![npm downloads](https://img.shields.io/npm/dm/rls-doctor.svg)](https://www.npmjs.com/package/rls-doctor)

`rls-doctor` is a Postgres and Supabase Row Level Security auditor for the command line.

## When to use this

You want this tool when you are asking any of:

- **Is my Supabase RLS safe?**
- **Can one user read another user's rows?** — `probe` impersonates app roles in a rolled-back transaction and shows real row exposure
- **Do my policies leak tenant data?** — unconditional `using (true)`, missing `WITH CHECK`, broad `to public`
- **Do my app roles have TRUNCATE?** / **Is FORCE RLS on?**
- **Add an RLS check to CI** — one line, JSON or SARIF, baseline-aware

It never mutates the database. Catalog analysis cannot prove application-level authorization.


It connects to a database with a Postgres connection string, reads catalog metadata, and reports RLS risks before they ship to production. Beyond static checks, `probe` impersonates application roles in a rolled-back, read-only transaction and shows which rows they can actually read.

- Status: Published CLI
- Portfolio case study: https://subhajitpradhan.vercel.app/projects/rls-doctor
- Inspect the implementation: `src/audit/analyzer.ts`, `scripts/run-integration.js`, and `.agents/skills/rls-doctor/SKILL.md`

```bash
npx rls-doctor check                 # reads DATABASE_URL or SUPABASE_DB_URL
npx rls-doctor probe --app-roles authenticated   # behavioral cross-tenant proof
```

Example output for a one-table snapshot:

```txt
RLS Doctor Report
Generated: 2026-07-12T00:00:00.000Z
Schemas: public

Summary: 1 tables, 0 policies, highest risk HIGH
Findings: critical 0, high 1, medium 0, low 0, info 0

public.orders
  RLS disabled; force RLS disabled; 0 policies
  [HIGH] RLS-disabled table is reachable by an application role
    public.orders has no row-level checks; Application role authenticated and can exercise SELECT granted to authenticated.
    Fix: Enable RLS and add least-privilege policies for each application role.
    Suggested SQL:
      alter table "public"."orders" enable row level security;
      -- Then add policies that match your access model before exposing this table to client roles.
```

![RLS Doctor terminal preview](docs/assets/terminal-preview.svg)

![RLS Doctor probe preview](docs/assets/probe-preview.svg)

## Why It Matters

Postgres RLS is one of the strongest tools for multi-tenant data isolation, but the failure modes are easy to miss during normal feature work:

- A table is granted to application roles while RLS is still disabled, including through role membership.
- RLS is enabled but no policy exists, breaking application access.
- A policy for `anon` or `public` has an unconditional predicate for an applicable command.
- Command-specific policy predicates are broad or missing: `USING` for reads/deletes, `WITH CHECK` for inserts, and both for updates.
- Default privileges can expose future tables, or an application role can reach `TRUNCATE`, which RLS never protects.
- Sensitive tables do not use `FORCE ROW LEVEL SECURITY`.

`rls-doctor` gives teams a repeatable local and CI check for those mistakes. It does not mutate your database and does not call Supabase management APIs.

## MCP server

Register the read-only MCP tools (`check_rls`, `probe_access`, `explain_table`) so an agent can call them directly:

```bash
claude mcp add rls-doctor -- npx -y rls-doctor mcp
```

## Install

Run without installing:

```bash
npx rls-doctor check
```

Install globally:

```bash
npm install -g rls-doctor
rls-doctor check
```

Prefer `DATABASE_URL` or `SUPABASE_DB_URL` containing read-only audit credentials. Passing a secret with `--connection` can expose it in shell history and process listings. Connection errors are sanitized to remove URL credentials, but credentials should still be treated as secrets.

## Commands

### `check`

Audit one or more schemas:

```bash
rls-doctor check --connection "$DATABASE_URL" --schema public --fail-on high
```

Machine-readable output for CI or dashboards:

```bash
rls-doctor check --connection "$DATABASE_URL" --schema public --json --fail-on high
```

Options:

```txt
-c, --connection <url>       Postgres connection string
-s, --schema <schema...>     Schema names to audit. Default: public
--json                       Print machine-readable JSON
--format <format>            text, json, or sarif. Default: text
--fail-on <severity>         info, low, medium, high, critical, none. Default: high
--baseline <path>            Compare with a prior JSON report; only new findings can fail
--update-baseline            Write the current report to the --baseline path and exit 0
--statement-timeout <ms>     Catalog query timeout. Default: 10000
--app-roles <role...>        Additional roles to treat as reachable application identities
```

By default only Supabase-style identities (`anon`, `anonymous`, `authenticated`) and
`public` are treated as reachable application roles. On generic Postgres databases, pass
your application roles so grants and memberships through them are analyzed with the same
severity as `authenticated`:

```bash
rls-doctor check --connection "$DATABASE_URL" --schema public --app-roles app_user web_user --fail-on high
```

Environment variable fallback (preferred; `DATABASE_URL` takes precedence):

```bash
DATABASE_URL=postgres://readonly_user:password@host:5432/app
SUPABASE_DB_URL=postgres://readonly_user:password@host:5432/postgres
```

### `explain`

Inspect one table:

```bash
rls-doctor explain public.profiles --connection "$DATABASE_URL"
```

Example (abridged excerpt; lines containing `...` are omission markers, not literal CLI output):

```txt
RLS Doctor Explain: public.profiles
RLS: enabled
Force RLS: disabled
Policies: 2
Risk: CRITICAL

Policies
  - anyone can read profiles: SELECT, permissive, roles public
  - anon can update profiles: UPDATE, permissive, roles public

Next steps
  ...
```

### `probe`

Impersonate application roles in a rolled-back, read-only transaction and observe what rows they can actually read:

```bash
rls-doctor probe --connection "$DATABASE_URL" --schema public \
  --app-roles authenticated app_user --owner-columns owner_id tenant_id --fail-on high
```

Simulate specific Supabase users instead of only a role:

```bash
rls-doctor probe --connection "$DATABASE_URL" --schema public \
  --app-roles authenticated \
  --subjects 00000000-0000-0000-0000-000000000001 00000000-0000-0000-0000-000000000002 \
  --fail-on high
```

Probe options:

```txt
--app-roles <role...>        Application roles to impersonate (required)
--subjects <uuid...>         Supabase user ids to simulate via request.jwt.claims
--owner-columns <col...>     Owner/tenant columns to compare (default: owner_id user_id tenant_id account_id)
--sample-limit <n>           Rows sampled per table (default: 1000)
```

What it does:

- Connects with `begin ... read only` and always rolls back. Probes never insert, update, delete, or commit; they are safe to run against production read replicas.
- Uses `SET LOCAL ROLE` to impersonate each `--app-roles` value. The audit connection must be a member of the target role or a superuser.
- Samples up to `--sample-limit` rows per table (default 1000) and, when an owner column exists (`--owner-columns`, default `owner_id`, `user_id`, `tenant_id`, `account_id`), counts distinct owner values.
- A role that reads rows spanning more than one owner/tenant value produces `probe-cross-owner-read` (High) — direct behavioral proof of cross-tenant exposure.
- With `--subjects <uuid...>`, probes simulate Supabase identities by setting `request.jwt.claims` and `request.jwt.claim.sub` inside the transaction, so `auth.uid()` resolves to each subject. Rows readable by that subject whose owner column differs from the subject produce `probe-cross-subject-read` (High) — a direct "can user A read user B's rows?" answer.

Probe findings: `probe-cross-owner-read` and `probe-cross-subject-read` (High), `probe-role-unavailable` (Medium), `probe-error` (Low), and informational `probe-reads-rows`, `probe-subject-reads-own-rows`, `probe-reads-no-rows`, `probe-read-denied`. Exit codes match `check` (see [Exit behavior](#exit-behavior)).

## What It Checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| Reachable `TRUNCATE` | High | RLS never protects `TRUNCATE`. |
| RLS disabled and reachable | High | An application-facing role has a row-access privilege plus schema `USAGE`, or can directly/through `SET ROLE` reach a superuser, without row checks. |
| RLS disabled, not currently reachable | Medium | No reachable application privilege was found, but a later grant can expose the table. |
| RLS enabled with no policies | Medium | Non-owner roles are default-denied and app access may break. |
| Public-like unconditional read | High | A `public`, `anon`, or anonymous-style policy has an unconditional `USING` predicate for `SELECT`/`ALL`. |
| Public-like unconditional write | Critical | A public-like policy has an unconditional command-applicable predicate for `INSERT`, `UPDATE`, `DELETE`, or `ALL`. |
| Omitted `WITH CHECK` leaves the effective write constraint unconditional | Medium | An `INSERT`, `UPDATE`, or `ALL` policy omits `WITH CHECK`, and its PostgreSQL fallback (if any) is unconditional. |
| Multiple permissive policies | Medium for public-like roles; otherwise Low | Policies for the same role/command are OR-combined. |
| Permissive public-like policy | Low | Permissive policies are OR-combined and can widen access unexpectedly. |
| Broad default table privilege | High for writes/`TRUNCATE`; Medium for `SELECT`; Low otherwise | Future tables created by that owner can receive the privilege; actual access still requires schema `USAGE`. |
| Application path to `SUPERUSER`/`BYPASSRLS` | High | These role attributes bypass RLS even when `FORCE` is enabled. |
| `FORCE RLS` disabled | Info | The table owner bypasses RLS; superusers and `BYPASSRLS` roles bypass regardless. |

Policy checks follow PostgreSQL command semantics: `SELECT` evaluates `USING`; `INSERT` evaluates `WITH CHECK`; `DELETE` evaluates `USING` and never needs `WITH CHECK`; `UPDATE` evaluates both. When an `UPDATE` or `ALL` policy omits `WITH CHECK`, PostgreSQL falls back to its `USING` expression, and RLS Doctor analyzes that effective check. `ALL` is checked as each applicable command.

Policies and privileges are different layers. A policy describes which rows an already-privileged role may access; normally, relation grants and schema `USAGE` determine whether it can reach the table. A directly available or `SET ROLE`-reachable superuser is the exception and has ACL/schema-independent object access. `BYPASSRLS` alone bypasses row policies but does not supply object or schema privileges. RLS Doctor follows direct, inherited, and `SET ROLE` membership paths (including PostgreSQL 16 per-membership options; PostgreSQL 15 behavior is normalized), and reports current access separately from default privileges that may affect future tables. It does not claim exact ACL reconstruction for explicit empty default overrides.

Unconditional-policy findings are structural, high-signal warnings rather than proof of final authorization. PostgreSQL OR-combines permissive policies and then AND-combines the result with applicable restrictive policies, so restrictive composition can still constrain effective access.

## CI Usage

```yaml
name: RLS Audit

on:
  pull_request:
    branches: [main]

jobs:
  rls-audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-node@v5
        with:
          node-version: 22.x

      - name: Audit RLS
        run: npx rls-doctor check --schema public --json --fail-on high
        env:
          DATABASE_URL: ${{ secrets.READONLY_DATABASE_URL }}
```

Full guide: [`docs/guides/github-actions.md`](docs/guides/github-actions.md)

### GitHub Action

A composite action is included at the repository root. It installs the published CLI, runs a check, writes the report, and fails the job according to `fail-on` (and only new findings when a baseline is provided).

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v5

  - uses: subhajitlucky/rls-doctor@v0.2.0
    with:
      connection: ${{ secrets.READONLY_DATABASE_URL }}
      schema: public
      format: sarif
      output: rls-doctor.sarif
      fail-on: high
      app-roles: authenticated app_user

  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: rls-doctor.sarif
```

The connection string is passed through the environment, not the command line. SARIF results carry `logicalLocations` (`schema.table`) and stable `partialFingerprints`, so code scanning can track findings across runs even though database tables are not files.

### Baselines

Adopt RLS Doctor on an existing database without failing on day one:

```bash
# Record the current findings once
rls-doctor check --schema public --baseline rls-baseline.json --update-baseline

# Afterwards, only new findings can fail the run
rls-doctor check --schema public --baseline rls-baseline.json --fail-on high
```

Fingerprints are derived from the finding id, schema, table, and detail, so a changed predicate or privilege re-reports as a new finding. JSON reports include `baseline: { new, unchanged, resolved }` when a baseline is used.

Exit behavior:

- `0` when no finding meets the configured threshold.
- `1` when at least one finding meets or exceeds `--fail-on`.
- `1` also for Commander usage and option-parsing errors, before an audit runs.
- `2` for caught action/runtime failures, including missing credentials, connection/catalog errors, invalid action values such as `--fail-on`, or a requested table not being found.

`--fail-on none` always disables finding-based failure. A clean report uses `highestSeverity: "none"`; `--fail-on info` therefore still exits `0` when there are no findings. JSON reports use `schemaVersion: "1.0"` and contain top-level `schemaFindings` for default-privilege and role-bypass findings in addition to per-table findings.

## Supabase Notes

For Supabase projects, `rls-doctor` audits catalog-visible PostgreSQL RLS, grants, and relevant role paths. It does not audit hosted Supabase management settings, views, or functions. Review Data API configuration and other database objects separately.

See [`docs/guides/supabase-rls-patterns.md`](docs/guides/supabase-rls-patterns.md) for unsafe and safer policy examples.

## Agent Skill

This repository includes an agent skill at `.agents/skills/rls-doctor/SKILL.md`.

Install it from GitHub:

```bash
npx skills add subhajitlucky/rls-doctor
```

Use it once without installing:

```bash
npx skills use subhajitlucky/rls-doctor --skill rls-doctor
```

The skill teaches compatible coding agents when to run `rls-doctor`, how to use read-only database credentials, and how to avoid leaking connection strings.

## Demo

The `demo` folder contains disposable SQL fixtures:

- `demo/unsafe-schema.sql` creates intentionally risky policies.
- `demo/safe-schema.sql` shows a safer reference shape.

Print local demo steps:

```bash
npm run demo
```

Run against a disposable database:

```bash
psql "$DATABASE_URL" -f demo/unsafe-schema.sql
npm run build
node dist/cli.js check --connection "$DATABASE_URL" --schema rls_doctor_demo --fail-on none
node dist/cli.js explain rls_doctor_demo.profiles --connection "$DATABASE_URL" --schema rls_doctor_demo
```

Do not run demo fixtures against production databases.

## Architecture

The CLI is intentionally small and inspectable:

```txt
CLI command
  -> catalog loader
  -> audit analyzer
  -> text / JSON reporters
  -> shell exit code
```

Read the deeper architecture note: [`docs/architecture.md`](docs/architecture.md)

## Development

```bash
npm ci
npm run ci
```

Integration test:

```bash
npm run test:integration
```

`npm run test:integration` starts its own disposable Postgres Docker container, opts into destructive fixtures, runs `check`/`explain`, and removes the container. If you invoke `scripts/run-integration.js` yourself, it refuses to continue unless `RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS=1` is set. Use that guard only with a disposable database: the fixtures create/drop schemas and shared roles and alter default privileges.

## Scope and Non-goals

RLS Doctor is a focused catalog audit, not a proof or compliance product. It does not:

- prove arbitrary SQL predicate correctness or simulate requests (`can`-style checks);
- audit views, functions, or hosted Supabase management configuration;
- automatically execute suggested SQL (suggestions are review templates); or
- make a compliance claim.

## Publishing

Publishing is manual. The repository includes `.github/workflows/publish.yml`, which expects an `NPM_TOKEN` repository secret.

Local release checklist:

```bash
npm run ci:full
npm pack --dry-run
npm publish --access public
```

## Roadmap

- Markdown report output.
- Policy diffing between branches.
- Optional SQL migration suggestions.

## Safety

`rls-doctor` sanitizes connection credentials from its own errors and only queries Postgres catalogs. Prefer a low-privilege user and an environment variable; a `--connection` value can still be exposed by the invoking shell or operating system.

This is a security review aid, not a replacement for application-level authorization tests, grant reviews, or a full production security audit.

## Requirements

Node.js 20 or later.

## License

MIT
