# Supabase RLS Patterns

`rls-doctor` is a local catalog auditor. It complements Supabase Security Advisor and the dashboard, but it does not replace a full application security review.

## Supabase Access Model

For Supabase Data API access, two layers matter:

1. Schema `USAGE`, table privileges, and reachable role membership normally decide whether a role such as `anon` or `authenticated` can reach a table.
2. RLS policies decide which rows that role can read or modify.

These layers are cumulative: a policy does not grant table access, and a grant does not express per-row ownership. RLS Doctor follows direct, inherited, and `SET ROLE` paths and normally requires a relation privilege plus schema `USAGE` when classifying current table reachability. A directly available or `SET ROLE`-reachable superuser is the exception because superuser object access is ACL/schema-independent. `BYPASSRLS` alone does not grant object or schema access. Default table privileges are different again: they can grant access to future tables created by a particular owner, subject to schema access, but are not evidence that an existing table is currently reachable.

## Unsafe Patterns

### RLS Disabled

```sql
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  total_cents integer not null
);

grant select, insert, update, delete on public.orders to authenticated;
```

Problem: authenticated users can reach the table, but no row-level predicate is enforced.

Safer baseline:

```sql
alter table public.orders enable row level security;
alter table public.orders force row level security;
```

### Broad Public Read

```sql
create policy "anyone can read profiles"
  on public.profiles
  for select
  to public
  using (true);
```

Problem: this policy contributes an unconditional `SELECT` predicate for `public`. That can be intentional for a public catalog, but it is a high-signal structural risk for user, tenant, billing, or operational data. Applicable restrictive policies can still constrain the final effective policy.

Safer public-content pattern:

```sql
create policy "public profiles are readable"
  on public.profiles
  for select
  to anon, authenticated
  using (is_public = true);
```

### Authenticated Without Ownership

```sql
create policy "signed in users can read"
  on public.tasks
  for select
  to authenticated
  using (true);
```

Problem: authentication is not authorization. This policy contributes an unconditional permissive read predicate for every signed-in user; applicable restrictive policies can still narrow final effective access.

Safer owner pattern:

```sql
create policy "users read own tasks"
  on public.tasks
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);
```

### Update Policy Without Explicit WITH CHECK

```sql
create policy "users update own tasks"
  on public.tasks
  for update
  to authenticated
  using ((select auth.uid()) = owner_id);
```

At first glance the existing row is scoped while the updated row appears unconstrained. PostgreSQL's fallback changes that conclusion.

PostgreSQL nuance: for `UPDATE`, an omitted `WITH CHECK` falls back to `USING`. The example's scoped `USING` is therefore an effective new-row check, and RLS Doctor does not label it unconstrained. An explicit `WITH CHECK` remains clearer and lets you enforce a distinct post-update rule. `INSERT` uses only `WITH CHECK`; `DELETE` uses only `USING` and does not need `WITH CHECK`; `SELECT` uses only `USING`; `ALL` is evaluated under each command's semantics.

Safer update pattern:

```sql
create policy "users update own tasks"
  on public.tasks
  for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
```

## Recommended Migration Shape

For tables exposed through Supabase client libraries, keep grants, RLS, and policies together in one reviewable migration.

```sql
grant select, insert, update, delete on public.tasks to authenticated;

alter table public.tasks enable row level security;
alter table public.tasks force row level security;

create policy "users read own tasks"
  on public.tasks
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "users insert own tasks"
  on public.tasks
  for insert
  to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "users update own tasks"
  on public.tasks
  for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
```

Review the column names and predicates for your actual tenant model before applying any template.

Also review privileges that RLS cannot constrain. In particular, do not grant `TRUNCATE` to application-facing roles: RLS never protects it. Table owners normally bypass policies unless `FORCE ROW LEVEL SECURITY` is enabled, while superusers and `BYPASSRLS` roles bypass RLS even with `FORCE`.

Suggested SQL emitted by RLS Doctor is a review template and is never executed automatically. The audit does not prove arbitrary predicate correctness, simulate client requests, audit views/functions or hosted Supabase management configuration, or establish compliance.
