# We statically audited 60 open-source Supabase apps: 63% ship at least one high-risk RLS pattern

*2026-10-09 · rls-doctor v0.5.x offline analyzer · aggregate, anonymized results*

Row Level Security is the only thing standing between one tenant and another's
rows in most Supabase apps. So we asked a simple question: **in public
codebases, how often is it half-configured?**

We analyzed the SQL migrations of 60 public repositories that use Supabase
migrations — statically, offline, without connecting to a single database.
Here's what the analyzer found.

## Headline numbers

| Metric | Result |
| --- | --- |
| Repositories analyzed | 60 (0 failed) |
| Migration files parsed | 1,404 (~23 per repo) |
| Tables / policies reconstructed | 1,654 tables · 3,073 policies |
| Repos with ≥1 **high or critical** RLS finding | **38 / 60 (63%)** |
| Repos with ≥1 **critical** finding | 15 / 60 (25%) |
| Repos with ≥1 **high** finding | 35 / 60 (58%) |
| Median RLS Score | **38 / 100** (average 39) |

## What patterns showed up

Counted by how many *repositories* contained at least one instance:

| Pattern | Severity | Repos |
| --- | --- | --- |
| `public-unconditional-read` — `to public using (true)` reads | high | 35 |
| `rls-enabled-no-policies` — RLS on, zero policies | medium | 19 |
| `public-unconditional-write` — unconditional `INSERT`/`UPDATE`/`DELETE` for `public`/`anon` | critical | 15 |
| `write-policy-missing-check` — write policy with no `WITH CHECK` | medium | 5 |
| `rls-disabled-exposed` — RLS off on a granted table | high | 4 |
| `reachable-truncate` — app role can `TRUNCATE` | high | 2 |
| `broad-default-table-privilege` — future tables inherit a broad grant | high | 1 |

Across the sample the analyzer emitted 52 critical, 270 high, 846 medium,
2,508 low, and 1,451 info findings. The score is severity-weighted, so the low
and info volume (permissive-policy notes, FORCE RLS info) drags the median
down without being a leak by itself.

## What this proves — and what it doesn't

**It proves the pattern, not the leak.** These are static findings in
migration files. A repo can have `using (true)` on a table that is *meant* to
be public content, and a repo can look strict in SQL and still be exposed
through a view or a service-role endpoint. Only a probe against real data can
prove who reads whose rows — that's what `rls-doctor probe` does, inside a
read-only transaction that always rolls back.

**Parser coverage is bounded and we count it.** 34 of 60 repos (57%) contained
at least one statement the offline parser could not evaluate (dynamic `DO`
blocks, `ALTER POLICY`, functions). Those became coverage limitations in the
report, never guessed findings. The true rate of risky patterns could be
higher, not lower.

**The sample is a convenience sample.** Repositories were the first 60 unique,
non-fork results from a GitHub code search for `path:supabase/migrations
extension:sql` — small and mid-size projects, not a random sample of
production apps. We state it so nobody reads this as a census.

**No repository is named.** Per our
[disclosure policy](../disclosure-policy.md), only aggregate, anonymized
numbers are published.

## Why this matters for the agent era

Most of these migrations were written the same way: a table is created, RLS is
enabled or forgotten, a policy is added, and the app ships. The failure modes
are structural — policies OR-combine, `WITH CHECK` silently falls back to
`USING`, table owners bypass RLS, and `TRUNCATE` is never protected — which is
exactly the class of mistake a static checker can catch before merge.

Two commands cover the whole loop, with no database and no credentials:

```bash
npx rls-doctor demo
# disposable Postgres, proven cross-tenant read, rolled back, container removed

rls-doctor check --schema-file supabase/migrations/0001_init.sql --fail-on high
# offline audit in CI: patterns, score, and explicit coverage limitations
```

## Reproduce it

```bash
git clone https://github.com/subhajitlucky/rls-doctor
cd rls-doctor && npm ci && npm run build
GITHUB_TOKEN=... node scripts/study-supabase-rls.mjs --limit 60 --pages 2 --out results.json
```

The script prints and writes only aggregate, anonymized records (repository
indexes, no names). Numbers move as repositories change; the snapshot above is
from 2026-10-09.
