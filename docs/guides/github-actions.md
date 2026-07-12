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

This checks the catalog state of an already migrated preview or staging database. Use a dedicated read-only audit role. Environment variables are preferred because a `--connection` argument can be visible in process listings; the CLI sanitizes credentials in connection errors, but the URL is still a secret.

## Disposable PostgreSQL Verification

For migration repositories, build a disposable PostgreSQL service, apply migrations, then audit the result. This avoids coupling pull requests to a mutable shared database.

```yaml
jobs:
  rls-audit:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: app_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres -d app_test"
          --health-interval 5s --health-timeout 5s --health-retries 10
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 22.x
      - run: npm ci
      - name: Apply migrations
        run: npm run migrate:test
        env:
          DATABASE_URL: postgres://postgres:postgres@127.0.0.1:5432/app_test
      - name: Audit migrated schema
        run: npx rls-doctor check --schema public --json --fail-on high
        env:
          DATABASE_URL: postgres://postgres:postgres@127.0.0.1:5432/app_test
```

Replace the migration command and, where practical, create a catalog-readable, non-superuser audit role after migration and use its URL for the audit. PostgreSQL 15 and 16 are supported; role-membership reachability accounts for their different membership-option behavior.

## Recommendations

- Use a read-only database user where possible.
- Point CI at a migrated preview, staging, or disposable database, not production.
- Use `--fail-on high` for pull requests.
- Use `--fail-on medium` once the project has cleaned up expected warnings.
- Store the connection string in GitHub Secrets.
- Treat `schemaFindings` (default privileges and privileged-role paths) as part of the result, not only per-table findings.
- A clean JSON report has `schemaVersion: "1.0"` and `summary.highestSeverity: "none"`.

## Local Equivalent

```bash
DATABASE_URL=postgres://readonly_user:password@host:5432/app \
  npx rls-doctor check --schema public --fail-on high
```

Exit code `0` means no finding met the threshold. A threshold finding exits `1`, but Commander usage or option-parsing errors also exit `1`, so CI logs or JSON output must distinguish those cases. Caught action/runtime failures—including missing credentials, connection/catalog errors, invalid action values, and a missing requested table—exit `2`. `--fail-on none` disables finding-based failure; even `--fail-on info` exits `0` for a clean audit.

The repository's destructive integration fixture runner is separately guarded by `RLS_DOCTOR_ALLOW_DESTRUCTIVE_TESTS=1`. Set it only for a disposable database: those fixtures create and drop schemas/shared roles and change default privileges. The normal Docker integration command supplies the guard to its own disposable container.
