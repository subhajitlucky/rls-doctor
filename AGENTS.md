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

MCP tools: `describe_capabilities` (call first — tool contract, approval
rules, coverage limits), `check_rls`, `probe_access`, `explain_table`,
`prove_isolation`, `propose_repair`. All are read-only and annotated
(`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`).
MCP failures return `{ error: { code, message, nextAction } }`; branch on
`code` (`connection-required`, `connection-failed`, `invalid-arguments`,
`not-found`, `internal-error`) instead of parsing prose.

## Exit codes

- `0`: completed, no finding met `--fail-on`.
- `1`: completed, a finding met `--fail-on`.
- `2`: invalid input or operational failure (connection, parse, IO). Never
  treat exit `2` as clean.

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
- Agent setup (Claude Code, Codex, Gemini, generic stdio): [docs/agents.md](docs/agents.md)
- Post: https://subhajitpradhan.vercel.app/writing/five-postgres-rls-mistakes
