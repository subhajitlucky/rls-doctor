# RLS Doctor

[![CI](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/subhajitlucky/rls-doctor/actions/workflows/ci.yml)

`rls-doctor` is a CLI auditor for Postgres and Supabase Row Level Security.

It connects with a Postgres connection string, reads catalog metadata, and reports tables or policies that deserve review before they reach production.

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

## Why This Exists

Supabase and Postgres RLS are powerful, but small policy mistakes can expose tenant data. `rls-doctor` gives developers a fast local and CI check for obvious RLS misconfiguration.

The tool does not mutate your database and does not call Supabase management APIs.

![RLS Doctor terminal preview](docs/assets/terminal-preview.svg)

## Install

```bash
npm install -g rls-doctor
```

Or run without installing after the package is published:

```bash
npx rls-doctor check --connection "$DATABASE_URL"
```

For local development before publishing:

```bash
npm install
npm run build
npm link
rls-doctor check --connection "$DATABASE_URL"
```

Use a read-only database user when possible.

## Commands

### `check`

```bash
rls-doctor check --connection "$DATABASE_URL"
```

Options:

```txt
-c, --connection <url>       Postgres connection string
-s, --schema <schema...>     Schema names to audit, default: public
--json                       Print machine-readable JSON
--fail-on <severity>         info, low, medium, high, critical, none. Default: high
--statement-timeout <ms>     Catalog query timeout. Default: 10000
```

Environment fallback:

```bash
DATABASE_URL=postgres://readonly_user:password@host:5432/app
SUPABASE_DB_URL=postgres://readonly_user:password@host:5432/postgres
```

## CI Example

```bash
rls-doctor check --schema public --json --fail-on high
```

The command exits:

- `0` when no findings meet the threshold.
- `1` when findings meet or exceed `--fail-on`.
- `2` when the CLI cannot run, connect, or parse options.

### `explain`

Focus on one table:

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

## Demo

The `demo` folder contains disposable SQL fixtures:

- `demo/unsafe-schema.sql` creates intentionally risky policies.
- `demo/safe-schema.sql` shows a safer reference shape.

Print the local demo steps:

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

## Development

```bash
npm ci
npm run ci
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

## Current Checks

- RLS disabled on selected schema tables.
- RLS enabled with no policies.
- Policies granted to public-like roles such as `public` or `anon`.
- Unconditional public read/write policies.
- Write policies without explicit `WITH CHECK`.
- `FORCE ROW LEVEL SECURITY` hardening advisory.

## Roadmap

- Policy diffing between branches.
- Markdown report output.
- Optional SQL migration suggestions.

## Safety

`rls-doctor` never prints the connection string. It only queries Postgres catalog views and should be run with a low-privilege user.
