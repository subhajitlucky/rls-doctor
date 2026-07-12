-- Safer reference shape for rls-doctor demos.
-- This file assumes a Supabase-style auth.uid() helper and authenticated role.

drop schema if exists rls_doctor_demo_safe cascade;
create schema rls_doctor_demo_safe;
create extension if not exists pgcrypto;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated;
  end if;
end
$$;

revoke all on schema rls_doctor_demo_safe from public;
grant usage on schema rls_doctor_demo_safe to authenticated;
alter default privileges in schema rls_doctor_demo_safe revoke all on tables from public, authenticated;

create schema if not exists auth;
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select '00000000-0000-0000-0000-000000000001'::uuid;
$$;

create table rls_doctor_demo_safe.tasks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text not null,
  created_at timestamptz not null default now()
);

alter table rls_doctor_demo_safe.tasks enable row level security;
alter table rls_doctor_demo_safe.tasks force row level security;
grant select, insert, update on rls_doctor_demo_safe.tasks to authenticated;

create policy "users read own tasks"
  on rls_doctor_demo_safe.tasks
  for select
  to authenticated
  using (owner_id = auth.uid());

create policy "users create own tasks"
  on rls_doctor_demo_safe.tasks
  for insert
  to authenticated
  with check (owner_id = auth.uid());

create policy "users update own tasks"
  on rls_doctor_demo_safe.tasks
  for update
  to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());
