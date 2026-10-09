# Proof-carrying repairs

Every scanner finds problems. `rls-doctor fix` is different: it produces a
repair that arrives with a **machine-checked certificate**.

The tool generates a canonical patch for an exposed table, verifies it in
shadow — statically always, and against a live disposable PostgreSQL when
Docker is available — and writes the patch **only if verification proves**
that it:

1. resolves the witnesses it targets, and
2. introduces no new medium-or-higher findings.

The tool never applies anything. You get a patch file and a receipt; a human
or a separately authorized agent applies it, then reruns `check` and `prove`
to confirm the same scope.

```bash
rls-doctor fix --schema-file supabase/migrations/*.sql \
  --table public.orders --patch fix-orders.sql --receipt fix-orders.json
```

## What it generates

For a table with row-level security disabled and an owner-like column
(`owner_id`, `user_id`, `tenant_id`, `account_id`, `uid`):

```sql
alter table "public"."orders" enable row level security;
create policy "rls_doctor_owner_all" on "public"."orders"
  for all to "authenticated"
  using ("owner_id" = auth.uid())
  with check ("owner_id" = auth.uid());
```

Without an owner-like column, the patch enables RLS alone — fail-closed — and
the receipt states plainly: *every role is denied until a human adds an
ownership policy*.

## The verification gate

| Check | Rule |
| --- | --- |
| Witnesses resolved | every witness on the target table before the patch must be proved after |
| No regressions | no new **medium or higher** finding may appear |
| Advisories | new info/low findings are listed as non-blocking, never hidden |

Two verification modes, both stated in the receipt:

- **static** — re-parse the original SQL with the patch appended and re-prove.
  Always available; sound within the decidable fragment.
- **static+live** — additionally apply both in a disposable PostgreSQL
  container and compare catalog-derived proofs. Skipped, with an explicit
  limitation, when Docker is unavailable.

If verification fails, **no patch is written** and nothing is applied.

## The receipt

`--receipt` writes canonical JSON with a SHA-256 digest over the body:

```json
{
  "repairVersion": "1",
  "subject": { "schemaFiles": ["…"], "table": "public.orders", "roles": ["authenticated"] },
  "patch": { "sql": "…", "sha256": "…" },
  "verification": {
    "status": "verified",
    "mode": "static+live",
    "beforeWitnesses": ["…"], "afterWitnesses": [],
    "resolved": ["…"], "newFindings": [],
    "advisoryFindings": ["info force-rls-disabled public.orders"]
  },
  "digest": { "algorithm": "sha256", "value": "…" }
}
```

The patch hash binds the certificate to the exact bytes a reviewer approves:
if the patch changes by one character, the receipt no longer describes it.

## Why this is the extraordinary part

A finding tells you something is wrong. A verified repair tells you something
is *fixed*, and proves it without touching your repository — the same
rollback discipline as `probe`, applied to remediation itself. Exit `0` when
a verified patch is written, `1` when verification fails, `2` on operational
failure.
