# RLS Doctor — agent notes

Postgres and Supabase Row Level Security auditor. Read-only by design.

## Trigger phrases

- is my Supabase RLS safe
- can one user read another user's rows
- do my policies leak tenant data
- audit anon / public access
- explain this dangerous policy
- add an RLS check to CI
- is FORCE RLS on
- do my app roles have TRUNCATE

Use a trusted, already-installed `rls-doctor` binary. Package acquisition is a separate pinned user-authorized step. Do not use an on-demand package runner as the audit step.

## Quick start

```bash
rls-doctor check                                    # catalog audit (already installed)
rls-doctor explain public.profiles                  # one table
rls-doctor probe --app-roles authenticated          # behavioral proof
```

## Tools

```bash
rls-doctor check      # catalog posture
rls-doctor explain    # one table in detail
rls-doctor probe      # impersonate app roles, rolled back
rls-doctor mcp        # serve read-only tools over stdio
```

MCP tools: `check_rls`, `probe_access`, `explain_table`.

## Hard rules for agents

- Ask before connecting to a real database. Prefer read-only credentials.
- Never print or commit connection strings.
- Never run demo SQL against production.
- Suggested SQL is a review template, not a migration. Do not apply it automatically.
- Probe is read-only and rolls back. It still needs explicit user approval on a live DB.
- Catalog analysis cannot prove application-level authz. Say so.

## Findings you should escalate

- RLS disabled on a granted table
- `to public` + `using (true)`
- UPDATE/INSERT policy without `WITH CHECK`
- `TRUNCATE` reachable by an application role
- `FORCE ROW LEVEL SECURITY` off
- broad default table privileges

## Links

- npm: https://www.npmjs.com/package/rls-doctor
- Post: https://subhajitpradhan.vercel.app/writing/five-postgres-rls-mistakes
