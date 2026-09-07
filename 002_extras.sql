-- =============================================================================
-- FORTITUDE TICKETING — supplementary migration
-- Run this AFTER schema.sql, in the Supabase SQL editor.
-- Adds: (1) a safe way for the browser to write security_events despite RLS,
-- and (2) the storage bucket + policies for private attachments.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. log_security_event(): lets the authenticated (or anonymous, for failed
-- logins) browser session record a security event without being able to
-- write anyone else's user_id. SECURITY DEFINER bypasses the (empty) RLS
-- insert policy on security_events; the function itself enforces that
-- user_id can only ever be auth.uid() — never client-supplied.
-- -----------------------------------------------------------------------------
create or replace function public.log_security_event(p_event_type text, p_metadata jsonb default '{}'::jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into security_events (user_id, event_type, metadata)
  values (auth.uid(), p_event_type, coalesce(p_metadata, '{}'::jsonb));
end;
$$;

-- Any authenticated OR anonymous caller may invoke this (failed-login events
-- happen before a session exists), but they can never set another user's id.
grant execute on function public.log_security_event(text, jsonb) to anon, authenticated;

-- -----------------------------------------------------------------------------
-- 2. Private storage bucket for ticket attachments.
-- -----------------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('ticket-attachments', 'ticket-attachments', false)
on conflict (id) do nothing;

create policy "attachments bucket: owner or staff read"
  on storage.objects for select
  using (
    bucket_id = 'ticket-attachments'
    and (owner = auth.uid() or public.is_active_staff())
  );

create policy "attachments bucket: authenticated upload"
  on storage.objects for insert
  with check ( bucket_id = 'ticket-attachments' and owner = auth.uid() );

-- =============================================================================
-- BOOTSTRAPPING YOUR FIRST ADMINISTRATOR
-- =============================================================================
-- Every new sign-up gets role = 'reporter' by default (see handle_new_user()
-- in schema.sql), and only an existing admin can promote someone else — so
-- the very first admin has to be created by you, directly in SQL, once:
--
--   1. Sign up normally through the app with the account you want to be admin.
--   2. In the Supabase SQL editor, run:
--
--        update profiles set role = 'admin'
--        where id = (select id from auth.users where email = 'you@fortitude.co.tz');
--
--   3. Sign out and back in. You'll now see the Administrator navigation,
--      and can promote/demote every other account from User Management —
--      no more manual SQL needed after this one-time step.
-- =============================================================================
