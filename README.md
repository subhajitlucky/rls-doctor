# RLS Doctor

[![CI](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/rls-doctor.svg)](https://www.npmjs.com/package/rls-doctor)

`rls-doctor` is a Postgres and Supabase Row Level Security auditor for the command line.

It connects to a database with a Postgres connection string, reads catalog metadata, and reports RLS risks before they ship to production.

- Status: Published CLI
- Portfolio case study: https://subhajitpradhan.vercel.app/projects/rls-doctor
- Inspect the implementation: `src/audit/analyzer.ts`, `scripts/run-integration.js`, and `.agents/skills/rls-doctor/SKILL.md`

```bash
npx rls-doctor check --connection "$DATABASE_URL"
```

```txt
RLS Doctor Report
Generated: 2026-07-12T00:00:00.000Z
Schemas: public

Summary: 1 tables, 0 policies, highest risk HIGH
Findings: critical 0, high 1, medium 0, low 0, info 0

public.orders
  RLS disabled; force RLS disabled; 0 policies
  [HIGH] RLS-disabled table is reachable by an application role
    public.orders has no row-level checks; Application role authenticated has direct access and can exercise SELECT granted to authenticated.
    Fix: Enable RLS and add least-privilege policies for each application role.
```

![RLS Doctor terminal preview](docs/assets/terminal-preview.svg)

## Why It Matters

Postgres RLS is one of the strongest tools for multi-tenant data isolation, but the failure modes are easy to miss during normal feature work:

- A table is granted to application roles while RLS is still disabled, including through role membership.
- RLS is enabled but no policy exists, breaking application access.
- `anon` or `public` can read every row through `using (true)`.
- Command-specific policy predicates are broad or missing: `USING` for reads/deletes, `WITH CHECK` for inserts, and both for updates.
- Default privileges can expose future tables, or an application role can reach `TRUNCATE`, which RLS never protects.
- Sensitive tables do not use `FORCE ROW LEVEL SECURITY`.

`rls-doctor` gives teams a repeatable local and CI check for those mistakes. It does not mutate your database and does not call Supabase management APIs.

## Install

Run without installing:

```bash
npx rls-doctor check --connection "$DATABASE_URL"
```

Install globally:

```bash
npm install -g rls-doctor
rls-doctor check --connection "$DATABASE_URL"
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
--fail-on <severity>         info, low, medium, high, critical, none. Default: high
--statement-timeout <ms>     Catalog query timeout. Default: 10000
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

Example output:

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
  - [HIGH] Restrict the policy with tenant, owner, or explicit public-content predicates.
  - [CRITICAL] Require authenticated ownership checks and explicit WITH CHECK constraints for writes.
```

## What It Checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| Reachable `TRUNCATE` | High | RLS never protects `TRUNCATE`. |
| RLS disabled and reachable | High | An application-facing role has a row-access privilege and schema `USAGE`, without row checks. |
| RLS disabled, not currently reachable | Medium | No reachable application privilege was found, but a later grant can expose the table. |
| RLS enabled with no policies | Medium | Non-owner roles are default-denied and app access may break. |
| Public-like unconditional read | High | `public`, `anon`, or anonymous-style roles can read every row. |
| Public-like unconditional write | Critical | Broad roles can insert, update, or delete rows too freely. |
| Write policy missing effective check | Medium | An insert/update has no effective constraint on new rows. |
| Multiple permissive policies | Medium for public-like roles; otherwise Low | Policies for the same role/command are OR-combined. |
| Permissive public-like policy | Low | Permissive policies are OR-combined and can widen access unexpectedly. |
| Broad default table privilege | High for writes/`TRUNCATE`; Medium for `SELECT`; Low otherwise | Future tables created by that owner can receive the privilege; actual access still requires schema `USAGE`. |
| Application path to `SUPERUSER`/`BYPASSRLS` | High | These role attributes bypass RLS even when `FORCE` is enabled. |
| `FORCE RLS` disabled | Info | The table owner bypasses RLS; superusers and `BYPASSRLS` roles bypass regardless. |

Policy checks follow PostgreSQL command semantics: `SELECT` evaluates `USING`; `INSERT` evaluates `WITH CHECK`; `DELETE` evaluates `USING` and never needs `WITH CHECK`; `UPDATE` evaluates both. When an `UPDATE` or `ALL` policy omits `WITH CHECK`, PostgreSQL falls back to its `USING` expression, and RLS Doctor analyzes that effective check. `ALL` is checked as each applicable command.

Policies and privileges are different layers. A policy describes which rows an already-privileged role may access; relation grants and schema `USAGE` determine whether it can reach the table. RLS Doctor follows direct, inherited, and `SET ROLE` membership paths (including PostgreSQL 16 per-membership options; PostgreSQL 15 behavior is normalized), and reports current access separately from default privileges that may affect future tables. It does not claim exact ACL reconstruction for explicit empty default overrides.

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

Exit codes:

- `0` when no finding meets the configured threshold.
- `1` when at least one finding meets or exceeds `--fail-on`.
- `2` when the CLI cannot run, connect, or parse options.

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
- Baseline files for known accepted findings.
- SARIF output for GitHub code scanning.

## Safety

`rls-doctor` sanitizes connection credentials from its own errors and only queries Postgres catalogs. Prefer a low-privilege user and an environment variable; a `--connection` value can still be exposed by the invoking shell or operating system.

This is a security review aid, not a replacement for application-level authorization tests, grant reviews, or a full production security audit.
