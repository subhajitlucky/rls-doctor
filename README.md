# RLS Doctor

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

## Install

```bash
npm install -g rls-doctor
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

## Current Checks

- RLS disabled on selected schema tables.
- RLS enabled with no policies.
- Policies granted to public-like roles such as `public` or `anon`.
- Unconditional public read/write policies.
- Write policies without explicit `WITH CHECK`.
- `FORCE ROW LEVEL SECURITY` hardening advisory.

## Roadmap

- Policy diffing between branches.
- `explain` command for table-specific policy summaries.
- GitHub Actions example.
- Markdown report output.
- Optional SQL migration suggestions.

## Safety

`rls-doctor` never prints the connection string. It only queries Postgres catalog views and should be run with a low-privilege user.
