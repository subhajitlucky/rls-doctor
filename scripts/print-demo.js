#!/usr/bin/env node

console.log(`RLS Doctor demo

1. Create a disposable local Postgres database.

2. Load the intentionally unsafe fixture:
   psql "$DATABASE_URL" -f demo/unsafe-schema.sql

3. Build the CLI:
   npm run build

4. Run the audit:
   node dist/cli.js check --connection "$DATABASE_URL" --schema rls_doctor_demo --fail-on none

5. Explain one table:
   node dist/cli.js explain rls_doctor_demo.profiles --connection "$DATABASE_URL" --schema rls_doctor_demo

The fixture is intentionally unsafe so the report shows useful findings.
`);
