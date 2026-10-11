# GEMINI.md — RLS Doctor

RLS Doctor audits Postgres and Supabase Row Level Security. It is read-only
against the target database and never mutates anything.

## Use it when

- asked whether RLS is safe, or whether one user can read another user's rows
- asked whether policies leak tenant data or `anon`/`public` access is too broad
- adding an RLS gate to CI
- explaining or repairing a dangerous policy

## How to run it

```bash
rls-doctor check --schema-file supabase/migrations/001_init.sql   # offline, no database
rls-doctor check                                                  # catalog audit (reads DATABASE_URL)
rls-doctor probe --app-roles authenticated                        # behavioral proof, always rolled back
```

MCP: `gemini mcp add rls-doctor npx -y rls-doctor@0.5.7 mcp`
Tools: `describe_capabilities`, `check_rls`, `probe_access`, `explain_table`,
`prove_isolation`, `propose_repair`. Call `describe_capabilities` first;
errors return `{ error: { code, message, nextAction } }`.

## Hard rules

- Ask the user before connecting to a live database; prefer read-only credentials.
- Never print or commit connection strings.
- Never apply suggested SQL automatically — it is a review template.
- Say when catalog analysis cannot prove application-level authorization.
- Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` operational failure (never clean).

Full agent notes live in [AGENTS.md](AGENTS.md); per-client setup in
[docs/agents.md](docs/agents.md).
