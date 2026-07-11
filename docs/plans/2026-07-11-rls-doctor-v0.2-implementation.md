# RLS Doctor v0.2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make RLS findings command-correct, privilege-aware, safe to automate, and verified against a disposable PostgreSQL database.

**Architecture:** Expand the catalog snapshot with grants, default privileges, roles, and memberships while preserving the catalog-loader/analyzer/reporter boundaries. Keep PostgreSQL queries factual and implement all risk classification as pure analyzer logic. Extend reports compatibly with schema-level findings, a JSON schema version, and a real `none` summary state.

**Tech Stack:** TypeScript, Node.js 20+, `pg`, Commander, Vitest, tsup, PostgreSQL 16 integration service.

---

### Task 1: Represent clean reports and versioned output

**Files:**
- Modify: `src/audit/types.ts`
- Modify: `src/audit/analyzer.ts`
- Modify: `src/reporters/text.ts`
- Modify: `tests/analyzer.test.ts`
- Modify: `tests/reporters.test.ts`

**Step 1: Write failing clean-report tests**

Add analyzer assertions that a snapshot containing a FORCE-RLS table with a scoped authenticated policy has:

```ts
expect(report.summary.highestSeverity).toBe("none");
expect(shouldFail(report, "info")).toBe(false);
```

Add reporter assertions:

```ts
expect(parsed.schemaVersion).toBe("1.0");
expect(text).toContain("highest risk NONE");
```

**Step 2: Run tests and confirm the intended failure**

Run:

```bash
npx vitest run tests/analyzer.test.ts tests/reporters.test.ts
```

Expected: FAIL because clean reports currently use `info` and have no `schemaVersion`.

**Step 3: Implement the report contract**

In `src/audit/types.ts` add:

```ts
export type HighestSeverity = Severity | "none";

export interface AuditReport {
  schemaVersion: "1.0";
  // existing fields remain unchanged
}
```

Change `AuditSummary.highestSeverity` to `HighestSeverity`. In `summarize`, return `none` when all counts are zero. Change `shouldFail` to inspect severity counts rather than comparing a synthetic highest value. Add `NONE` to text formatting and emit `schemaVersion` from `analyzeCatalog`.

**Step 4: Run focused tests**

Run the same Vitest command. Expected: PASS.

**Step 5: Commit**

```bash
git add src/audit/types.ts src/audit/analyzer.ts src/reporters/text.ts tests/analyzer.test.ts tests/reporters.test.ts
git commit -m "fix: represent clean rls audits correctly"
```

### Task 2: Make policy analysis command-aware

**Files:**
- Modify: `src/audit/analyzer.ts`
- Modify: `tests/analyzer.test.ts`

**Step 1: Add failing command-matrix tests**

Add focused tests for:

```ts
it("accepts a public INSERT policy with a restrictive WITH CHECK", ...)
it("flags a public INSERT policy with an unconditional WITH CHECK", ...)
it("flags a public DELETE policy with an unconditional USING", ...)
it("does not require WITH CHECK for DELETE", ...)
it("uses UPDATE USING as the implicit WITH CHECK when WITH CHECK is absent", ...)
it("evaluates ALL across read, insert, update, and delete behavior", ...)
```

Assert exact finding IDs and severities rather than only total counts.

**Step 2: Run the analyzer tests**

Run:

```bash
npx vitest run tests/analyzer.test.ts
```

Expected: at least the INSERT and DELETE cases FAIL under the current shared `writeCommands` logic.

**Step 3: Implement operation-specific expression handling**

Replace the shared null-is-unconditional checks with helpers that model applicable expressions:

```ts
function effectiveCheckExpression(policy: PolicySnapshot): string | null {
  if (policy.checkExpression !== null) return policy.checkExpression;
  if (policy.command === "UPDATE" || policy.command === "ALL") return policy.usingExpression;
  return null;
}
```

Evaluate:

- SELECT: broad when `USING` is unconditional;
- INSERT: broad when `WITH CHECK` is absent or unconditional;
- UPDATE: broad when applicable `USING` or effective check is unconditional;
- DELETE: broad when `USING` is unconditional;
- ALL: apply all relevant checks without duplicate finding IDs.

Only report `write-policy-missing-check` when omission creates an unconstrained check. Do not report it for DELETE or for an UPDATE/ALL policy whose scoped `USING` is inherited as its check.

**Step 4: Make suggestions command-aware**

Generate only clauses valid for the policy command. Use explicit placeholders such as `<owner_column>` and add a comment stating that suggested SQL must be adapted before execution.

**Step 5: Run tests and refactor**

Run:

```bash
npx vitest run tests/analyzer.test.ts tests/reporters.test.ts
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src/audit/analyzer.ts tests/analyzer.test.ts tests/reporters.test.ts
git commit -m "fix: audit rls policies by command semantics"
```

### Task 3: Warn about policy composition

**Files:**
- Modify: `src/audit/analyzer.ts`
- Modify: `tests/analyzer.test.ts`

**Step 1: Add failing policy-combination tests**

Cover these behaviors:

```ts
it("warns when multiple permissive policies apply to the same public-like role and command", ...)
it("does not warn when policies apply to unrelated commands", ...)
it("accounts for a restrictive policy as an AND-combined constraint", ...)
```

Expected finding ID: `multiple-permissive-policies`, severity `medium` for public-like roles and `low` otherwise. Do not claim that arbitrary SQL expressions have been proven safe or unsafe.

**Step 2: Run the focused test and confirm failure**

```bash
npx vitest run tests/analyzer.test.ts -t "permissive"
```

Expected: FAIL because analysis currently treats each policy independently.

**Step 3: Implement table-level composition analysis**

After individual policy checks, expand `ALL` to each concrete command, group applicable policies by role and command, and identify groups containing more than one permissive policy. Include restrictive-policy context in the finding detail because restrictive policies are AND-combined with the permissive result.

**Step 4: Run tests**

```bash
npx vitest run tests/analyzer.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/audit/analyzer.ts tests/analyzer.test.ts
git commit -m "feat: explain combined rls policy behavior"
```

### Task 4: Load privilege and role facts from PostgreSQL

**Files:**
- Modify: `src/audit/types.ts`
- Modify: `src/db/catalog.ts`
- Modify: `tests/catalog.test.ts`

**Step 1: Add failing catalog mapping tests**

Define fixtures and mapping expectations for:

- explicit relation privileges from `aclexplode(coalesce(relacl, acldefault(...)))`;
- default table privileges from `pg_default_acl`;
- role attributes (`rolsuper`, `rolbypassrls`, `rolinherit`);
- memberships from `pg_auth_members`;
- table owner names.

Expose pure row-mapping helpers where needed so malformed or unusual role names can be tested without a database.

**Step 2: Run tests and confirm failure**

```bash
npx vitest run tests/catalog.test.ts
```

Expected: FAIL because the snapshot contains only tables and policies.

**Step 3: Extend snapshot types**

Add types shaped like:

```ts
interface RelationPrivilegeSnapshot {
  schema: string;
  table: string;
  grantor: string;
  grantee: string;
  privilege: "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "TRUNCATE" | "REFERENCES" | "TRIGGER";
  grantable: boolean;
}

interface DefaultPrivilegeSnapshot {
  schema: string | null;
  owner: string;
  grantee: string;
  objectType: "TABLE";
  privilege: string;
  grantable: boolean;
}

interface RoleSnapshot {
  name: string;
  superuser: boolean;
  bypassRls: boolean;
  inherits: boolean;
}

interface RoleMembershipSnapshot {
  role: string;
  member: string;
}
```

Add `owner` to `TableSnapshot`, and add `relationPrivileges`, `defaultPrivileges`, `roles`, and `roleMemberships` to `CatalogSnapshot`.

**Step 4: Add parameterized catalog queries**

Query only the selected schemas for relation/default privileges and relevant memberships. Resolve OIDs with `pg_get_userbyid`. Preserve default ACL semantics by distinguishing stored overrides in `pg_default_acl` from the current ACL on existing relations.

Use the existing connection and statement timeout. Do not print query parameters or the connection string.

**Step 5: Run typecheck and catalog tests**

```bash
npm run check
npx vitest run tests/catalog.test.ts
```

Expected: PASS after updating existing test fixtures with empty arrays and owners.

**Step 6: Commit**

```bash
git add src/audit/types.ts src/db/catalog.ts tests/catalog.test.ts tests/analyzer.test.ts tests/reporters.test.ts
git commit -m "feat: collect postgres privilege and role metadata"
```

### Task 5: Analyze grants, defaults, ownership, and bypass roles

**Files:**
- Modify: `src/audit/types.ts`
- Modify: `src/audit/analyzer.ts`
- Modify: `src/reporters/text.ts`
- Modify: `tests/analyzer.test.ts`
- Modify: `tests/reporters.test.ts`

**Step 1: Add failing privilege-model tests**

Cover:

```ts
it("raises high when an application role can reach an RLS-disabled table", ...)
it("does not call an ungranted internal table exposed", ...)
it("follows inherited role grants", ...)
it("reports broad default table privileges for public-like roles", ...)
it("reports application-role default privileges that create future exposure", ...)
it("explains owner bypass when FORCE RLS is disabled", ...)
it("explains that superuser and BYPASSRLS roles bypass FORCE RLS", ...)
```

Application-facing roles for v0.2 are `PUBLIC`, `anon`, `anonymous`, and `authenticated`. Findings for custom roles arise when they inherit from one of these roles or possess `BYPASSRLS`/superuser attributes relevant to an audited object.

**Step 2: Run tests and confirm failure**

```bash
npx vitest run tests/analyzer.test.ts
```

Expected: FAIL because grants and roles are not analyzed.

**Step 3: Add schema-level findings**

Extend `AuditReport` with:

```ts
schemaFindings: SchemaFinding[];
```

Keep table findings in `TableAudit`. Include schema findings in summary counts and threshold evaluation. Default privileges with a null schema are labeled as database-wide defaults for their owner.

**Step 4: Implement effective-role expansion**

Build a cycle-safe membership graph. Respect `rolinherit`: inherited grants are effective only through inheriting members. Treat `PUBLIC` as applying to every role. Keep the implementation pure and deterministic.

**Step 5: Implement privilege findings**

- RLS disabled plus reachable application privilege: `rls-disabled-exposed`, high.
- RLS disabled without an application grant: retain an advisory `rls-disabled`, medium, without claiming exposure.
- Broad public-like default table privilege: `broad-default-table-privilege`, high for write and medium for SELECT.
- Superuser or `BYPASSRLS` role with application-facing membership: `rls-bypass-role`, high.
- Owner bypass without FORCE RLS remains info and accurately excludes superuser/BYPASSRLS from FORCE protection.

**Step 6: Update text and JSON tests**

Render schema findings before table details and verify summary counts include them. Existing table/report keys remain intact.

**Step 7: Run focused verification**

```bash
npm run check
npx vitest run tests/analyzer.test.ts tests/reporters.test.ts
```

Expected: PASS.

**Step 8: Commit**

```bash
git add src/audit/types.ts src/audit/analyzer.ts src/reporters/text.ts tests/analyzer.test.ts tests/reporters.test.ts
git commit -m "feat: audit grants and default privileges"
```

### Task 6: Sanitize CLI errors and connection handling

**Files:**
- Create: `src/cli-support.ts`
- Modify: `src/cli.ts`
- Create: `tests/cli-support.test.ts`

**Step 1: Add failing redaction tests**

Test that formatting an error containing the supplied URL:

```ts
postgres://audit_user:very-secret@db.example.test:5432/app
```

does not include `very-secret`, the full URL, or percent-encoded password variants, while retaining a useful message and host where safe.

**Step 2: Run the test**

```bash
npx vitest run tests/cli-support.test.ts
```

Expected: FAIL because no reusable sanitizer exists.

**Step 3: Implement reusable sanitization**

Move connection resolution and error sanitization into `src/cli-support.ts`. Pass the resolved connection string to the sanitizer in both command catch blocks. Redact the exact URL, decoded/encoded user-info, and URL-shaped credentials without altering ordinary PostgreSQL diagnostic text.

**Step 4: Run tests and typecheck**

```bash
npm run check
npx vitest run tests/cli-support.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/cli.ts src/cli-support.ts tests/cli-support.test.ts
git commit -m "fix: redact credentials from cli errors"
```

### Task 7: Verify threshold behavior against PostgreSQL

**Files:**
- Modify: `demo/unsafe-schema.sql`
- Modify: `demo/safe-schema.sql`
- Modify: `scripts/run-integration.js`

**Step 1: Change integration expectations before implementation cleanup**

Load both demo schemas. Run the unsafe schema with `--fail-on high` and assert exit code 1 plus expected findings. Run the safe schema with the same threshold and assert exit code 0.

Create a non-superuser, read-only `rls_doctor_auditor` role after fixtures are installed. Use its connection for CLI checks so catalog visibility assumptions are exercised.

**Step 2: Run the integration test**

```bash
npm run test:integration
```

Expected before fixture/catalog corrections: FAIL for the newly asserted exit or privilege behavior.

**Step 3: Complete fixtures and process assertions**

Add representative explicit grants and default privileges to the unsafe schema. Revoke broad defaults and grant only scoped privileges in the safe schema. Update the child-process helper so expected exit code 1 is captured as an audit result rather than mistaken for an execution error.

Never print the database connection string when an assertion fails.

**Step 4: Run integration verification**

```bash
npm run test:integration
```

Expected: PASS with one unsafe failure assertion and one safe success assertion.

**Step 5: Commit**

```bash
git add demo/unsafe-schema.sql demo/safe-schema.sql scripts/run-integration.js
git commit -m "test: verify rls audit thresholds against postgres"
```

### Task 8: Update public documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/guides/supabase-rls-patterns.md`
- Modify: `docs/guides/github-actions.md`

**Step 1: Update documented checks and report contract**

Document command-aware checks, grant/default-privilege coverage, clean `none` summaries, JSON `schemaVersion`, environment-variable preference, and the difference between policies and privileges.

Clearly state remaining non-goals: the tool does not prove arbitrary policy expressions correct, simulate application requests, audit hosted Supabase configuration, or automatically execute suggested SQL.

**Step 2: Verify examples against built output**

```bash
npm run build
npm run demo
```

Expected: examples and terminology match actual CLI output.

**Step 3: Commit**

```bash
git add README.md docs/architecture.md docs/guides/supabase-rls-patterns.md docs/guides/github-actions.md
git commit -m "docs: document privilege-aware rls audits"
```

### Task 9: Run complete release verification

**Files:**
- Modify only files required by failures attributable to this change.

**Step 1: Run static and unit verification**

```bash
npm run check
npm test
npm run build
npm run test:cli-version
```

Expected: all commands exit 0.

**Step 2: Run dependency and integration verification**

```bash
npm audit --audit-level=low
npm run test:integration
```

Expected: both commands exit 0.

**Step 3: Inspect the final diff and package contents**

```bash
git diff HEAD~8 --check
npm pack --dry-run
git status --short
```

Expected: no whitespace errors, expected package files only, and no uncommitted generated artifacts.

**Step 4: Commit any verification-only corrections**

```bash
git add <specific-corrected-files>
git commit -m "fix: complete rls doctor v0.2 verification"
```

Skip this commit when no corrections are needed.
