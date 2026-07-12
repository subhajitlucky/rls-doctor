-- Demo schema for rls-doctor.
-- Run this only against a disposable local database.

drop schema if exists rls_doctor_demo cascade;
create schema rls_doctor_demo;
create extension if not exists pgcrypto;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'rls_doctor_demo_reader') then
    create role rls_doctor_demo_reader;
  end if;
end
$$;

grant rls_doctor_demo_reader to authenticated;
grant usage on schema rls_doctor_demo to authenticated, rls_doctor_demo_reader;
alter default privileges in schema rls_doctor_demo revoke all on tables from authenticated;
alter default privileges in schema rls_doctor_demo grant insert on tables to authenticated;

create schema if not exists auth;
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select '00000000-0000-0000-0000-000000000001'::uuid;
$$;

create table rls_doctor_demo.orders (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  total_cents integer not null,
  created_at timestamptz not null default now()
);

create table rls_doctor_demo.profiles (
  id uuid primary key default gen_random_uuid(),
  display_name text not null,
  email text not null
);

create table rls_doctor_demo.tasks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text not null
);

grant select on rls_doctor_demo.orders to authenticated, rls_doctor_demo_reader;
grant select, update, truncate on rls_doctor_demo.profiles to authenticated;

alter table rls_doctor_demo.profiles enable row level security;
create policy "anyone can read profiles"
  on rls_doctor_demo.profiles
  for select
  to public
  using (true);

create policy "anon can update profiles"
  on rls_doctor_demo.profiles
  for update
  to public
  using (true);

alter table rls_doctor_demo.tasks enable row level security;
alter table rls_doctor_demo.tasks force row level security;
create policy "users manage own tasks"
  on rls_doctor_demo.tasks
  for all
  to authenticated
  using (owner_id = auth.uid())
  with check (owner_id = auth.uid());
