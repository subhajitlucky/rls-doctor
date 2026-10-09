# Show HN — rls-doctor

## Submission

- **Title**: `Show HN: RLS Doctor – prove if one Postgres user can read another's rows`
- **URL**: https://github.com/subhajitlucky/rls-doctor
- **Post when**: Tue–Thu, 8–10am US Eastern. Do not ask for upvotes anywhere.

## First comment (post immediately after submitting)

> Hi HN — author here. RLS is Postgres's tenant-isolation tool, and it's easy
> to leave half-configured: policies OR-combine, `WITH CHECK` silently falls
> back to `USING`, table owners bypass RLS, and `TRUNCATE` is never protected.
>
> RLS Doctor does two things:
>
> 1. `rls-doctor demo` spins up a disposable Postgres, applies an
>    intentionally unsafe schema, and **proves** a cross-tenant read by
>    impersonating the app role inside a read-only transaction that always
>    rolls back. One command, no credentials, container removed afterwards.
> 2. `rls-doctor check` audits a live catalog (read-only) or a SQL migration
>    file offline (`--schema-file`, no database), emits a deterministic
>    RLS Score, and reports coverage limitations instead of guessing.
>
> We also ran it statically over 60 public Supabase projects: **63% contained
> at least one high or critical RLS pattern**, median score 38/100. Aggregate
> and anonymized only, with methodology and limitations:
> https://github.com/subhajitlucky/rls-doctor/blob/main/docs/blog/2026-10-09-open-source-rls-audit.md
>
> What it deliberately doesn't do: it never writes to your database, never
> prints secrets, and never claims a clean result when coverage was
> incomplete. Probe results depend on seeded data — empty tables prove
> nothing, and we say so in the output.
>
> Happy to answer anything about the analysis rules, the probe transaction
> model, or the study methodology.

## HN etiquette checklist

- [ ] Post the first comment immediately (link posts have no body).
- [ ] Reply to every top-level comment the first day, technical and specific.
- [ ] Never ask for upvotes; never mention voting.
- [ ] If someone finds a false positive: reproduce it in the thread, file the
      fixture as an issue, and say what changed.
- [ ] If the study is challenged on sampling: agree it's a convenience
      sample; point to the stated limitations.
- [ ] Keep a pinned note of the top 3 criticisms; fix or document them before
      the Product Hunt push.

## Follow-up comment (if the thread asks "how is this different from X?")

> Two differences that matter to us: (1) `probe` proves access behaviorally
> instead of inferring it from policy text, and (2) every report prints what
> it could not check (`coverage-limitations`), so a clean run means the scope
> was actually checked. Static scanners that don't do both tend to either
> guess or over-claim.
