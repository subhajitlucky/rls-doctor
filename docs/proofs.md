# Formal proof mode

`rls-doctor prove` answers a precise question offline: **for this table,
command, and role, do the parsed policies guarantee that every admitted row
belongs to the caller?**

It is sound and bounded by construction. Inside its decidable fragment it
returns a proof or a witness; outside it, `undecided` with a reason. It never
guesses.

## The decidable fragment

Supported atoms:

| Expression | Meaning |
| --- | --- |
| `true` / `false` | unconditional / deny-all |
| `<column> = auth.uid()` | ownership equality, either side, with or without `(select …)` |

Combined with `AND` and `OR` (parentheses respected). Everything else — `NOT`,
`IN (subquery)`, casts, function calls, comparisons — is `undecided`.

## Decisions

| Decision | Meaning |
| --- | --- |
| `proved(column)` | every row the predicate admits satisfies `column = auth.uid()` |
| `proved(null)` | the predicate admits no rows (deny-all) |
| `witness(reason)` | the predicate can admit a row outside the ownership boundary |
| `undecided(reason)` | outside the fragment; never counted as a proof |

Composition rules (sound):

- `A AND B` proves `column` if either side proves it; proves deny-all if
  either side denies all; witnesses only when both sides admit every row.
- `A OR B` proves `column` only when both sides prove the **same** column;
  witnesses if any side witnesses, or if the sides constrain different
  columns; otherwise `undecided`.

## Policy composition

For each table, command (`SELECT`, `INSERT`, `UPDATE`, `DELETE`), and role:

- `INSERT`/`UPDATE` use `WITH CHECK`, falling back to `USING` exactly like
  PostgreSQL.
- Permissive policies are OR-combined; restrictive policies AND-combine.
- No applicable policy means default deny (`proved(null)`).
- A table with RLS disabled is a `witness` for every command: policies are
  not enforced.

## Artifact

`--proof <path>` writes:

```json
{
  "proofVersion": "1",
  "tool": { "name": "rls-doctor", "version": "0.5.5" },
  "generatedAt": "…",
  "subject": { "schemaFiles": ["…"], "schemas": ["…"], "roles": ["authenticated"] },
  "limitations": ["…"],
  "claims": [ { "schema": "…", "table": "…", "command": "SELECT", "role": "authenticated",
                "status": "proved", "column": "owner_id", "reason": "…", "policies": ["…"] } ],
  "digest": { "algorithm": "sha256", "value": "…" }
}
```

The digest is SHA-256 over the canonical JSON body (recursively sorted keys),
so any edit to a claim invalidates it. Exit codes: `0` no witnesses, `1` at
least one witness, `2` operational failure.

## Example

```
rls_doctor_demo.orders    SELECT  authenticated   WITNESS    RLS is disabled; policies are not enforced
rls_doctor_demo.profiles  SELECT  authenticated   WITNESS    the predicate admits every row
rls_doctor_demo.tasks     SELECT  authenticated   PROVED     every admitted row satisfies owner_id = auth.uid()
```

The unsafe demo schema yields 6 witnesses; the safe reference schema yields
4/4 proofs. `probe` proves the same property behaviorally against real data;
`prove` proves it statically, with no database at all.
