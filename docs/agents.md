# rls-doctor with coding agents

Every rls-doctor MCP tool is read-only and annotated
`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`.
`prove_isolation` and `propose_repair` run fully offline; `check_rls`,
`probe_access`, and `explain_table` need a database connection and explicit
user approval. Failures return
`{ error: { code, message, nextAction } }` with `code` one of
`connection-required`, `connection-failed`, `invalid-arguments`,
`not-found`, `internal-error`.

Pin the version (`@0.5.8` below) to the release you audited; tool schemas
move with server versions. `initialize` reports the exact server version.

## Claude Code

```bash
claude mcp add rls-doctor --scope user -- npx -y rls-doctor@0.5.8 mcp
```

Auto-approve the read-only tools in `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__rls-doctor__describe_capabilities",
      "mcp__rls-doctor__check_rls",
      "mcp__rls-doctor__probe_access",
      "mcp__rls-doctor__explain_table",
      "mcp__rls-doctor__prove_isolation",
      "mcp__rls-doctor__propose_repair"
    ]
  }
}
```

The agent skill is also installable: `npx skills add subhajitlucky/rls-doctor`.

## Codex CLI

```bash
codex mcp add rls-doctor -- npx -y rls-doctor@0.5.8 mcp
```

Equivalent `~/.codex/config.toml`:

```toml
[mcp_servers.rls-doctor]
command = "npx"
args = ["-y", "rls-doctor@0.5.8", "mcp"]
```

Codex reads [AGENTS.md](AGENTS.md) for repo context.

## Gemini CLI

```bash
gemini mcp add rls-doctor npx -y rls-doctor@0.5.8 mcp
```

Equivalent `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "rls-doctor": {
      "command": "npx",
      "args": ["-y", "rls-doctor@0.5.8", "mcp"]
    }
  }
}
```

Gemini CLI reads [GEMINI.md](GEMINI.md) for project context.

## Any other stdio MCP client (GLM, Kimi, Grok, …)

If the client speaks stdio MCP — directly or through a Claude
Code-compatible harness — this config works as-is:

```json
{
  "mcpServers": {
    "rls-doctor": {
      "command": "npx",
      "args": ["-y", "rls-doctor@0.5.8", "mcp"]
    }
  }
}
```

## Credentials and approval

Do not put connection strings in client config. Prefer
`DATABASE_URL`/`SUPABASE_DB_URL` with read-only credentials, ask the user
before any live-database tool call, and never echo the connection string.
`describe_capabilities` lists the approval rules in machine-readable form.
