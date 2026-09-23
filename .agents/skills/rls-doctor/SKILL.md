---
name: rls-doctor
description: Check whether Postgres or Supabase Row Level Security is safe. Use when asked if RLS is enabled, if policies leak tenant rows, to audit anon or public access, to explain a dangerous policy, to prove cross-tenant reads with a probe, or to add an RLS check to CI. Also use for WITH CHECK, FORCE RLS, TRUNCATE grants, and default-privilege review.
---

# RLS Doctor Skill

Use this skill when a repository needs a local or CI audit of Postgres/Supabase Row Level Security.

## When to use this

Answer yes to any of these and this skill applies:

- "Is my Supabase RLS safe?"
- "Can one user read another user's rows?"
- "Do my policies leak tenant data?"
- "Why is this policy dangerous?"
- "Add an RLS check to CI"
- "What is wrong with `using (true)` on a public policy?"
- "Do my app roles have TRUNCATE?"
- "Is FORCE RLS on?"

Do not use this skill when:

- the task requires changing hosted Supabase dashboard settings
- the user asks for a full penetration test or compliance audit
- no database connection or schema SQL is available

## CLI

Use a trusted, already-installed `rls-doctor` binary, or the explicit local
`./node_modules/.bin/rls-doctor` binary. Package acquisition or package update
is a separate, pinned, user-authorized step that may use the network and perform
cache writes. Do not use an on-demand package runner as the audit step.

Prefer a read-only connection string in `DATABASE_URL` or `SUPABASE_DB_URL`.
Passing a secret with `--connection` can expose it in shell history and process
listings. Never print, echo, or expose a credential, connection string, or secret.

```bash
rls-doctor check --schema public
```

For one table:

```bash
rls-doctor explain public.profiles
```

Behavioral proof (rolled-back, read-only transaction; ask the user before
running this against a live database):

```bash
rls-doctor probe --app-roles authenticated --owner-columns owner_id
```

CI-friendly JSON:

```bash
rls-doctor check --schema public --json --fail-on high
```

### Options

- `--connection <url>` — explicit connection string (prefer env vars)
- `--schema <name...>` — schemas to audit or probe
- `--json` — machine-readable output
- `--format <text|json|sarif>` — report rendering (check)
- `--fail-on <severity>` — info|low|medium|high|critical|none
- `--baseline <path>` / `--update-baseline` — compare or record accepted findings (check)
- `--app-roles <role...>` — reachable application identities
- `--subjects <uuid...>` — simulate Supabase JWT users (probe)
- `--owner-columns <column...>` — tenant columns for cross-owner checks
- `--tables <table...>` — limit probe scope
- `--sample-limit <n>` / `--statement-timeout <ms>` — bounded work
- `--statement-timeout <ms>` — catalog query timeout

### Exit codes

- exit 0 — completed and below the `--fail-on` threshold
- exit 1 — completed and at least one finding met the threshold
- exit 2 — could not complete (invalid input, connection failure, operational error). Never treat exit 2 as a clean result.

## MCP

If the MCP server is registered, prefer its tools over shell calls. All three
are read-only against the target database and never mutate it:

- `check_rls` — catalog posture for one or more schemas
- `probe_access` — impersonate app roles in a rolled-back transaction
- `explain_table` — one table's posture in detail

Register it with `claude mcp add rls-doctor -- npx -y rls-doctor mcp` or the
equivalent client config. That registration is a separate, pinned,
user-authorized install step, not the audit step.

## Workflow

1. Ask the user before connecting to any real database. Confirm permission or approval first.
2. Prefer a read-only connection string or a disposable migrated database.
3. Run `rls-doctor check` on the target schema with the already-installed binary.
4. If the report shows high or critical findings, run `rls-doctor explain <schema.table>`.
5. If the user wants proof, not just catalog shape, run `probe` with two owner IDs against a seeded schema. Empty tables prove nothing.
6. Treat suggested SQL as a review template, not an automatic migration. An external human or separately authorized agent applies changes, then rerun the same scope to verify.
7. For Supabase apps, remind the user that grants and RLS policies are separate layers.

## Safety Rules

- Never print or commit database connection strings. Never expose credentials.
- Do not run demo SQL against production databases.
- Do not use `--run-checks` style execution against an untrusted repository. RLS Doctor has no such flag; do not invent one.
- Do not mutate schemas unless the user explicitly asks for migration work.
- Do not use Supabase management APIs or dashboard actions unless explicitly requested.
- Prefer `--fail-on high` for pull requests and `--fail-on medium` only after expected findings are cleaned up.

## Common Findings

- RLS disabled on selected schema tables
- RLS enabled with no policies
- public-like roles with unconditional read policies (`using (true)`)
- public-like roles with broad write policies
- write policies missing explicit `WITH CHECK`
- `FORCE ROW LEVEL SECURITY` disabled on sensitive tables
- `TRUNCATE` granted to application roles
- broad default table privileges on a schema

## Coverage limits

Catalog analysis is automatic and offline from application source: it reads
pg_catalog metadata only. It cannot prove application-level authorization.
Partial coverage is not a clean result. Static SQL review of expected migration
state is separate from observed live database state. Live database access
requires `--connection` or `DATABASE_URL` and explicit user confirmation. If
the database step failed, do not report the audit as clean.

## GitHub Actions

```yaml
- name: Audit RLS
  run: rls-doctor check --schema public --json --fail-on high
  env:
    DATABASE_URL: ${{ secrets.READONLY_DATABASE_URL }}
```

## References

When deeper guidance is needed, read:

- `docs/guides/supabase-rls-patterns.md`
- `docs/guides/github-actions.md`
- `llms.txt`
- `AGENTS.md`
- `README.md`
