# GitHub Actions Usage

Use `rls-doctor` in CI to stop obvious RLS mistakes from shipping.

## Basic Workflow

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

## Recommendations

- Use a read-only database user where possible.
- Point CI at a migrated preview, staging, or disposable database, not production.
- Use `--fail-on high` for pull requests.
- Use `--fail-on medium` once the project has cleaned up expected warnings.
- Store the connection string in GitHub Secrets.

## Local Equivalent

```bash
npx rls-doctor check --connection "$DATABASE_URL" --schema public --fail-on high
```
