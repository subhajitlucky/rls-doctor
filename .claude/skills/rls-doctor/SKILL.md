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

Prefer the published CLI:

```bash
npx rls-doctor check --connection "$DATABASE_URL" --schema public
```

For one table:

```bash
npx rls-doctor explain public.profiles --connection "$DATABASE_URL"
```

Behavioral proof (rolled-back, read-only):

```bash
npx rls-doctor probe --app-roles authenticated --owner-columns owner_id
```

CI-friendly JSON:

```bash
npx rls-doctor check --connection "$DATABASE_URL" --schema public --json --fail-on high
```

## MCP

If the MCP server is registered, prefer its tools over shell calls. All three
are read-only against the target database:

- `check_rls` — catalog posture for one or more schemas
- `probe_access` — impersonate app roles in a rolled-back transaction
- `explain_table` — one table's posture in detail

## Workflow

1. Ask the user before connecting to any real database.
2. Prefer a read-only connection string or a disposable migrated database.
3. Run `rls-doctor check` on the target schema.
4. If the report shows high or critical findings, run `rls-doctor explain <schema.table>`.
5. If the user wants proof, not just catalog shape, run `probe` with two owner IDs against a seeded schema. Empty tables prove nothing.
6. Treat suggested SQL as a review template, not an automatic migration.
7. For Supabase apps, remind the user that grants and RLS policies are separate layers.

## Safety Rules

- Never print or commit database connection strings.
- Do not run demo SQL against production databases.
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

## GitHub Actions

```yaml
- name: Audit RLS
  run: npx rls-doctor check --schema public --json --fail-on high
  env:
    DATABASE_URL: ${{ secrets.READONLY_DATABASE_URL }}
```

## References

When deeper guidance is needed, read:

- `docs/guides/supabase-rls-patterns.md`
- `docs/guides/github-actions.md`
- `README.md`
