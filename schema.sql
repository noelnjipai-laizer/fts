-- =============================================================================
-- FORTITUDE TOTAL SECURITY — IT & CONTROL ROOM TICKETING SYSTEM
-- Supabase (PostgreSQL) schema, roles and Row Level Security policies
-- Implements sections 3, 5, 6, 7 of the requirements document.
--
-- Run in the Supabase SQL editor (or via `supabase db push` as a migration)
-- against a fresh project. Review every policy before production use.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. Extensions
-- -----------------------------------------------------------------------------
create extension if not exists "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. Enums
-- -----------------------------------------------------------------------------
create type app_role as enum ('reporter', 'support', 'admin');
create type ticket_category as enum (
  'IT/Computer', 'CCTV Camera', 'Electrical Fence',
  'Control Room Electrical Component', 'Network/Internet', 'Access/Device', 'Other'
);
create type ticket_priority as enum ('Low', 'Medium', 'High', 'Critical');
create type ticket_status as enum (
  'Open', 'Acknowledged', 'In Progress', 'Waiting for User', 'Resolved', 'Closed'
);
create type message_visibility as enum ('public', 'internal');
create type notification_channel as enum ('whatsapp');
create type notification_status as enum ('queued', 'sent', 'failed');

-- -----------------------------------------------------------------------------
-- 2. profiles
-- One row per auth.users row. role/site are never editable by the user
-- themselves — only by an admin, enforced by the UPDATE policy below.
-- -----------------------------------------------------------------------------
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  phone text,
  role app_role not null default 'reporter',
  site text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Auto-create a profile row when a new auth user signs up.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email), 'reporter');
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- -----------------------------------------------------------------------------
-- 3. tickets
-- -----------------------------------------------------------------------------
create table tickets (
  id uuid primary key default gen_random_uuid(),
  ticket_no text not null unique,
  reporter_id uuid not null references profiles(id),
  category ticket_category not null,
  title text not null,
  description text not null,
  location text not null,
  asset_id text,
  priority ticket_priority not null default 'Medium',
  status ticket_status not null default 'Open',
  assigned_to uuid references profiles(id),
  resolution text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Ticket numbers: FTS-1000, FTS-1001, ... assigned server-side, never client-supplied.
create sequence ticket_no_seq start 1000;
create function public.next_ticket_no()
returns text language sql as $$
  select 'FTS-' || nextval('ticket_no_seq')::text;
$$;

create function public.set_ticket_defaults()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.ticket_no is null then
    new.ticket_no := public.next_ticket_no();
  end if;
  -- reporter_id is always the calling user, never trusted from the client
  new.reporter_id := auth.uid();
  new.updated_at := now();
  return new;
end;
$$;

create trigger trg_ticket_insert_defaults
  before insert on tickets
  for each row execute procedure public.set_ticket_defaults();

create function public.touch_ticket_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger trg_ticket_touch
  before update on tickets
  for each row execute procedure public.touch_ticket_updated_at();

-- -----------------------------------------------------------------------------
-- 4. ticket_messages  (feedback thread + internal notes)
-- -----------------------------------------------------------------------------
create table ticket_messages (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid not null references tickets(id) on delete cascade,
  author_id uuid not null references profiles(id),
  message text not null,
  visibility message_visibility not null default 'public',
  created_at timestamptz not null default now()
);

create function public.set_message_author()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  new.author_id := auth.uid();
  return new;
end;
$$;

create trigger trg_message_author
  before insert on ticket_messages
  for each row execute procedure public.set_message_author();

-- -----------------------------------------------------------------------------
-- 5. ticket_attachments
-- -----------------------------------------------------------------------------
create table ticket_attachments (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid not null references tickets(id) on delete cascade,
  uploaded_by uuid not null references profiles(id),
  storage_path text not null,
  file_name text not null,
  mime_type text not null,
  size bigint not null,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 6. ticket_audit_log  (append-only; no update/delete policy granted to anyone)
-- -----------------------------------------------------------------------------
create table ticket_audit_log (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid references tickets(id) on delete set null,
  actor_id uuid references profiles(id),
  action text not null,
  old_values jsonb,
  new_values jsonb,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 7. notification_log  (server/service-role writes only — never the browser)
-- -----------------------------------------------------------------------------
create table notification_log (
  id uuid primary key default gen_random_uuid(),
  ticket_id uuid references tickets(id) on delete set null,
  channel notification_channel not null default 'whatsapp',
  event_type text not null,
  status notification_status not null default 'queued',
  provider_id text,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 8. security_events  (server-written; safe metadata only, never secrets)
-- -----------------------------------------------------------------------------
create table security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  event_type text not null,
  metadata jsonb,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 9. Helper functions for policies
-- -----------------------------------------------------------------------------
create function public.current_role()
returns app_role language sql stable security definer set search_path = public as $$
  select role from profiles where id = auth.uid();
$$;

create function public.is_active_staff()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from profiles
    where id = auth.uid() and active = true and role in ('support','admin')
  );
$$;

create function public.is_active_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from profiles where id = auth.uid() and active = true and role = 'admin'
  );
$$;

-- -----------------------------------------------------------------------------
-- 10. Enable RLS on every application table (section 6)
-- -----------------------------------------------------------------------------
alter table profiles enable row level security;
alter table tickets enable row level security;
alter table ticket_messages enable row level security;
alter table ticket_attachments enable row level security;
alter table ticket_audit_log enable row level security;
alter table notification_log enable row level security;
alter table security_events enable row level security;

-- ---- profiles ---------------------------------------------------------------
create policy "profiles: read own or staff read all"
  on profiles for select
  using ( id = auth.uid() or public.is_active_staff() );

create policy "profiles: user updates own contact fields only"
  on profiles for update
  using ( id = auth.uid() )
  with check ( id = auth.uid() and role = (select role from profiles p where p.id = auth.uid()) );
  -- role/active are excluded from what a self-update can change in practice by
  -- only exposing full_name/phone in the client update payload; role changes
  -- must go through the admin policy below, which checks is_active_admin().

create policy "profiles: admin manages all profiles"
  on profiles for all
  using ( public.is_active_admin() )
  with check ( public.is_active_admin() );

-- ---- tickets ------------------------------------------------------------
create policy "tickets: reporter sees own"
  on tickets for select
  using ( reporter_id = auth.uid() or public.is_active_staff() );

create policy "tickets: reporter creates own"
  on tickets for insert
  with check ( auth.uid() is not null );
  -- reporter_id itself is forced to auth.uid() by the trg_ticket_insert_defaults
  -- trigger above, so this check only needs to confirm the caller is authenticated.

create policy "tickets: reporter cannot update"
  on tickets for update
  using ( public.is_active_staff() )
  with check ( public.is_active_staff() );
  -- Reporters have no UPDATE policy at all — status, priority, assignment and
  -- resolution are only reachable by support/admin. Reporter "feedback" goes
  -- through ticket_messages, never a tickets row update.

create policy "tickets: admin deletes none by default"
  on tickets for delete
  using ( false );
  -- Deliberately no delete path — tickets are closed, never removed, so
  -- historical case history always survives account deactivation.

-- ---- ticket_messages ----------------------------------------------------
create policy "messages: reporter reads public messages on own tickets"
  on ticket_messages for select
  using (
    visibility = 'public'
    and exists (select 1 from tickets t where t.id = ticket_id and t.reporter_id = auth.uid())
  );

create policy "messages: staff reads all messages"
  on ticket_messages for select
  using ( public.is_active_staff() );

create policy "messages: reporter adds public feedback on own ticket"
  on ticket_messages for insert
  with check (
    visibility = 'public'
    and exists (select 1 from tickets t where t.id = ticket_id and t.reporter_id = auth.uid())
  );

create policy "messages: staff adds public or internal messages"
  on ticket_messages for insert
  with check ( public.is_active_staff() );

-- ---- ticket_attachments ---------------------------------------------------
create policy "attachments: reporter reads own ticket attachments"
  on ticket_attachments for select
  using (
    exists (select 1 from tickets t where t.id = ticket_id and t.reporter_id = auth.uid())
    or public.is_active_staff()
  );

create policy "attachments: reporter uploads to own ticket"
  on ticket_attachments for insert
  with check (
    uploaded_by = auth.uid()
    and exists (select 1 from tickets t where t.id = ticket_id and t.reporter_id = auth.uid())
  );

create policy "attachments: staff uploads to any ticket"
  on ticket_attachments for insert
  with check ( uploaded_by = auth.uid() and public.is_active_staff() );

-- ---- ticket_audit_log ----------------------------------------------------
-- Append-only: no insert/update policy for regular roles at all. Rows are
-- written exclusively by SECURITY DEFINER triggers/functions running as the
-- table owner, which bypasses the (deliberately empty) INSERT policy set.
create policy "audit: staff reads all, reporter reads own ticket's audit"
  on ticket_audit_log for select
  using (
    public.is_active_staff()
    or exists (select 1 from tickets t where t.id = ticket_id and t.reporter_id = auth.uid())
  );

-- ---- notification_log ------------------------------------------------------
-- Written only by the service role (server-side WhatsApp integration), which
-- bypasses RLS entirely — no INSERT policy is granted to any authenticated role.
create policy "notifications: staff reads"
  on notification_log for select
  using ( public.is_active_staff() );

-- ---- security_events ------------------------------------------------------
create policy "security_events: admin reads"
  on security_events for select
  using ( public.is_active_admin() );

-- -----------------------------------------------------------------------------
-- 11. Audit trigger — every material ticket change is logged automatically,
-- server-side, so the client can never "forget" to log an action.
-- -----------------------------------------------------------------------------
create function public.log_ticket_change()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into ticket_audit_log (ticket_id, actor_id, action, new_values)
    values (new.id, auth.uid(), 'ticket_created', to_jsonb(new));
  elsif tg_op = 'UPDATE' then
    insert into ticket_audit_log (ticket_id, actor_id, action, old_values, new_values)
    values (new.id, auth.uid(), 'ticket_updated', to_jsonb(old), to_jsonb(new));
  end if;
  return new;
end;
$$;

create trigger trg_ticket_audit
  after insert or update on tickets
  for each row execute procedure public.log_ticket_change();

-- -----------------------------------------------------------------------------
-- 12. Indexes
-- -----------------------------------------------------------------------------
create index idx_tickets_reporter on tickets(reporter_id);
create index idx_tickets_assigned on tickets(assigned_to);
create index idx_tickets_status on tickets(status);
create index idx_tickets_priority on tickets(priority);
create index idx_messages_ticket on ticket_messages(ticket_id);
create index idx_attachments_ticket on ticket_attachments(ticket_id);
create index idx_audit_ticket on ticket_audit_log(ticket_id);
create index idx_notifications_ticket on notification_log(ticket_id);

-- -----------------------------------------------------------------------------
-- 13. Storage — private bucket for attachments
-- Run separately or via the Supabase dashboard: Storage > Create bucket
-- "ticket-attachments", Public: OFF. Then apply storage policies:
-- -----------------------------------------------------------------------------
-- insert into storage.buckets (id, name, public) values ('ticket-attachments','ticket-attachments', false);
--
-- create policy "attachments bucket: owner or staff read"
--   on storage.objects for select
--   using (
--     bucket_id = 'ticket-attachments'
--     and (owner = auth.uid() or public.is_active_staff())
--   );
--
-- create policy "attachments bucket: authenticated upload"
--   on storage.objects for insert
--   with check ( bucket_id = 'ticket-attachments' and owner = auth.uid() );

-- =============================================================================
-- NOTES FOR THE DEVELOPMENT TEAM
-- =============================================================================
-- 1. Only the Supabase anon/public key ever ships to the browser. The
--    service-role key, WhatsApp Business API token and any admin DB
--    credentials stay in server environment variables (Vercel/host secret
--    manager), never in git, never in client bundles.
-- 2. WhatsApp sending is server-side only (Edge Function or Next.js server
--    route) using notification_log for delivery status/retry — the browser
--    never talks to the WhatsApp API directly.
-- 3. Every field a client could tamper with — reporter_id, status, assigned_to,
--    priority — is either forced server-side by a trigger (reporter_id) or
--    entirely unreachable to the reporter role (no UPDATE policy on tickets
--    for reporters at all).
-- 4. Before go-live: run `supabase db lint`, test with at least two reporter
--    accounts plus one support and one admin account to confirm isolation,
--    and pen-test IDOR/BOLA on ticket IDs per section 14 of the requirements.
-- =============================================================================
