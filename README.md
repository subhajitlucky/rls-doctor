# RLS Doctor

[![CI](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/rls-doctor.svg)](https://www.npmjs.com/package/rls-doctor)

`rls-doctor` is a Postgres and Supabase Row Level Security auditor for the command line.

It connects to a database with a Postgres connection string, reads catalog metadata, and reports RLS risks before they ship to production.

```bash
npx rls-doctor check --connection "$DATABASE_URL"
```

```txt
RLS Doctor Report
Schemas: public

Summary: 3 tables, 4 policies, highest risk HIGH

public.orders
  RLS disabled; force RLS disabled; 0 policies
  [HIGH] Row Level Security is disabled
    public.orders can be read or changed according to table privileges without row-level policy checks.
    Fix: Enable RLS and add least-privilege policies for each application role.
```

![RLS Doctor terminal preview](docs/assets/terminal-preview.svg)

## Why It Matters

Postgres RLS is one of the strongest tools for multi-tenant data isolation, but the failure modes are easy to miss during normal feature work:

- A table is granted to application roles while RLS is still disabled.
- RLS is enabled but no policy exists, breaking application access.
- `anon` or `public` can read every row through `using (true)`.
- Write policies forget `WITH CHECK`, allowing unsafe inserted or updated rows.
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

Use a read-only database user when possible.

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

Connection string fallback:

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
| RLS disabled | High | Table privileges can expose rows without row-level predicates. |
| RLS enabled with no policies | Medium | Non-owner roles are default-denied and app access may break. |
| Public-like unconditional read | High | `public`, `anon`, or anonymous-style roles can read every row. |
| Public-like unconditional write | Critical | Broad roles can insert or update rows too freely. |
| Write policy missing `WITH CHECK` | Medium | Updated or inserted rows may escape the intended ownership boundary. |
| Permissive public-like policy | Low | Permissive policies are OR-combined and can widen access unexpectedly. |
| `FORCE RLS` disabled | Info | Table owners and privileged sessions can bypass RLS. |

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

## Supabase Notes

For Supabase projects, `rls-doctor` audits the Postgres RLS layer. Supabase Data API exposure also depends on grants to roles such as `anon`, `authenticated`, and `service_role`, so review grants and RLS policies together.

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

`npm run test:integration` starts a disposable Postgres Docker container, loads `demo/unsafe-schema.sql`, runs `check`, runs `explain`, and removes the container.

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

`rls-doctor` never prints the connection string. It only queries Postgres catalog views and should be run with a low-privilege user.

This is a security review aid, not a replacement for application-level authorization tests, grant reviews, or a full production security audit.
