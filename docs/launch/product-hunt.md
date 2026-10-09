# Product Hunt — rls-doctor

## Listing

- **Name**: RLS Doctor
- **Tagline** (≤60): `Don't trust your RLS. Prove it.`
- **Short description** (≤260):
  `Prove who can read your Postgres/Supabase rows before an attacker does. One command spins up a disposable database and proves a cross-tenant read; audits migrations offline in CI. Read-only, never guesses, reports what it couldn't check.`
- **Topics**: Developer Tools · Security · Open Source · Databases
- **Links**: GitHub https://github.com/subhajitlucky/rls-doctor · npm https://www.npmjs.com/package/rls-doctor
- **Pricing**: Free · Open source

## Gallery order (1270×760)

1. `screenshot-probe.png` — the proof: `probe-cross-owner-read`
2. `rls-demo.gif` — one-command demo, score 29/100
3. `screenshot-check.png` — catalog findings with suggested SQL
4. Optional 4th: terminal frame of `check --schema-file ... --score`

## Maker comment (post at launch)

> Hi Product Hunt! RLS Doctor exists because "is my Supabase RLS safe?" is
> usually answered by reading policies and hoping. Policies OR-combine,
> `WITH CHECK` falls back to `USING`, owners bypass RLS, and `TRUNCATE` is
> never protected.
>
> `npx rls-doctor demo` gives you a proven answer in seconds: disposable
> Postgres, impersonated app roles, a rolled-back read-only transaction, and
> a cross-tenant read printed with evidence. `check` audits live catalogs or
> migration files offline, scores the result 0–100, and always lists what it
> could not check.
>
> We also audited 60 public Supabase projects statically: 63% had at least
> one high or critical RLS pattern (anonymized, methodology in the repo).
>
> It's MIT, read-only by design, and never prints your secrets. Feedback —
> especially false positives — very welcome.

## Launch-day checklist

- [ ] Publish at 12:01am PT (PH day boundary).
- [ ] Post the maker comment immediately.
- [ ] Reply to every comment within the hour for the first 6 hours.
- [ ] Cross-post the PH link to the LinkedIn post and the X thread.
- [ ] Do not message people asking for upvotes; share once, publicly.
- [ ] Track: visitors → GitHub stars → npm downloads → demo runs.
- [ ] At end of day: collect top 3 requests, add to the roadmap doc.
