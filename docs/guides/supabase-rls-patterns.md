# Supabase RLS Patterns

`rls-doctor` is a local catalog auditor. It complements Supabase Security Advisor and the dashboard, but it does not replace a full application security review.

## Supabase Access Model

For Supabase Data API access, two layers matter:

1. Grants decide whether a Postgres role such as `anon`, `authenticated`, or `service_role` can reach a table, view, or function.
2. RLS policies decide which rows that role can read or modify.

RLS cannot help if a table is exposed with broad grants and unsafe policies. Grants also cannot express per-row ownership by themselves.

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

Problem: every row is readable. That can be correct for a public catalog, but it is risky for user, tenant, billing, or operational data.

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

Problem: authentication is not authorization. Every signed-in user can read every row.

Safer owner pattern:

```sql
create policy "users read own tasks"
  on public.tasks
  for select
  to authenticated
  using ((select auth.uid()) = owner_id);
```

### Write Policy Without WITH CHECK

```sql
create policy "users update own tasks"
  on public.tasks
  for update
  to authenticated
  using ((select auth.uid()) = owner_id);
```

Problem: the existing row is scoped, but the updated row may not be constrained.

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
