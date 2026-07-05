---
name: rls-doctor
description: Postgres and Supabase Row Level Security audit workflow using the rls-doctor CLI. Use when checking RLS posture, reviewing Supabase policies, adding CI RLS checks, or explaining unsafe RLS findings.
---

# RLS Doctor Skill

Use this skill when a repository needs a local or CI audit of Postgres/Supabase Row Level Security.

## When To Use

Use this skill when asked to:
- check whether RLS is enabled on Postgres or Supabase tables
- audit Supabase policies for broad `anon`, `public`, or unconditional access
- add an RLS audit to CI
- explain why a table or policy is risky
- create safer RLS review notes for a pull request

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

CI-friendly JSON:

```bash
npx rls-doctor check --connection "$DATABASE_URL" --schema public --json --fail-on high
```

## Workflow

1. Ask the user before connecting to any real database.
2. Prefer a read-only connection string or a disposable migrated database.
3. Run `rls-doctor check` on the target schema.
4. If the report shows high or critical findings, run `rls-doctor explain <schema.table>`.
5. Treat suggested SQL as a review template, not an automatic migration.
6. For Supabase apps, remind the user that grants and RLS policies are separate layers.

## Safety Rules

- Never print or commit database connection strings.
- Do not run demo SQL against production databases.
- Do not mutate schemas unless the user explicitly asks for migration work.
- Do not use Supabase management APIs or dashboard actions unless explicitly requested.
- Prefer `--fail-on high` for pull requests and `--fail-on medium` only after expected findings are cleaned up.

## Common Findings

- RLS disabled on selected schema tables
- RLS enabled with no policies
- public-like roles with unconditional read policies
- public-like roles with broad write policies
- write policies missing explicit `WITH CHECK`
- `FORCE ROW LEVEL SECURITY` disabled on sensitive tables

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
