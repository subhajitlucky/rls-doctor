# X / LinkedIn thread — rls-doctor

Copy for the soft-launch thread. Post the GIF on the first tweet; one idea per
tweet; no hashtags, no upvote requests.

1. Can user A read user B's rows?

   Your RLS says no. This proves it — in 30 seconds, with no database setup.

   [attach `rls-demo.gif`]

2. `npx rls-doctor demo`

   Spins up a disposable Postgres, applies an unsafe schema, impersonates the
   app role in a read-only transaction, and prints the cross-tenant read.
   Everything rolls back. The container is removed.

3. The failure modes it hunts:
   · `to public using (true)` reads
   · unconditional writes for anon/public
   · `WITH CHECK` missing (silently falls back to `USING`)
   · reachable `TRUNCATE` (RLS never protects it)
   · owner bypass, broad default grants

4. It never guesses.

   Every report ends with `coverage-limitations` — what it could not check.
   A clean run means the scope was actually checked. No silent all-clears.

5. We ran it statically over 60 public Supabase projects:

   63% had at least one high or critical RLS pattern.
   Median score: 38/100.
   Anonymized, reproducible, limitations stated:
   [link to study]

6. For CI: `rls-doctor check --schema-file supabase/migrations/0001_init.sql
   --fail-on high` — offline, no credentials, deterministic fingerprints and
   baselines so only new findings fail the build.

7. MIT, read-only by design. Feedback welcome — especially false positives.

   Repo: github.com/subhajitlucky/rls-doctor
   `npx rls-doctor demo`
