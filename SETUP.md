# Setup — Fortitude Ticketing System

This is a real, working system: a static frontend (`index.html` / `app.js` / `styles.css`)
talking directly to a Supabase project via `supabase-js`. No Node server to run — just a
Supabase project and any static file host. Expect **20–30 minutes** end to end.

## 1. Create the Supabase project

1. Go to [supabase.com](https://supabase.com) → New project. Pick a strong database password
   and save it somewhere safe.
2. Wait for provisioning to finish (~2 minutes).

## 2. Run the database schema

1. In your project, open **SQL Editor**.
2. Paste the full contents of `schema.sql` and run it. This creates every table, enum, trigger
   and RLS policy described in the requirements document.
3. Paste the full contents of `002_extras.sql` and run it. This adds the private attachments
   bucket, its storage policies, and a small helper function so the app can log security events
   safely.

If either script errors partway through, drop the tables it created (`drop table tickets
cascade;` etc., or just start a fresh project) and re-run from a clean slate — partial schema
runs are hard to reason about.

## 3. Configure authentication

In **Authentication → Providers**, email/password is on by default — that's all this app needs.

In **Authentication → URL Configuration**, set:
- **Site URL**: the URL you'll host this app at (e.g. `https://tickets.fortitude.co.tz`, or
  `http://localhost:8080` while testing locally).
- **Redirect URLs**: add the same URL — this is where password-reset links send people back to.

Optional but recommended: in **Authentication → Providers → Email**, turn on "Confirm email" so
sign-ups must verify their address before signing in.

## 4. Get your API keys

**Project Settings → API**. Copy:
- **Project URL** → goes in `config.js` as `SUPABASE_URL`
- **anon / public key** → goes in `config.js` as `SUPABASE_ANON_KEY`

Do **not** copy the `service_role` key into `config.js` — that key bypasses every RLS policy and
must only ever live in the Edge Function secrets (step 6).

Edit `config.js`:

```js
window.FORTITUDE_CONFIG = {
  SUPABASE_URL: "https://abcdefgh.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbGciOi...",
  WHATSAPP_RECIPIENT_DISPLAY: "+255 782956145"
};
```

## 5. Host the frontend

Any static host works — the app is just `index.html`, `styles.css`, `app.js`, `config.js`.

- **Quick local test**: from this folder, run `python3 -m http.server 8080` and open
  `http://localhost:8080`.
- **Production**: drag the folder into Netlify, or `vercel deploy`, or upload to any static
  bucket/CDN. Make sure the URL matches what you set as the Auth **Site URL** in step 3.

## 6. Create your first administrator

1. Open the hosted app and **Sign Up** with the account you want to be an admin.
2. Back in the Supabase **SQL Editor**, run:
   ```sql
   update profiles set role = 'admin'
   where id = (select id from auth.users where email = 'you@fortitude.co.tz');
   ```
3. Sign out and back in — you'll now see the full Administrator navigation, and can promote or
   demote every other account from **User Management** without touching SQL again.

## 7. (Recommended) Require MFA for admins at the database level

The app lets admins self-enroll TOTP from **Profile**. To also *require* it before any
privileged action can succeed (not just nudge for it in the UI), add this policy check to the
admin-only policies in `schema.sql`/`002_extras.sql` once your admins have enrolled:

```sql
-- Example: require aal2 (MFA-verified session) for admin writes to profiles.
-- Add `and auth.jwt()->>'aal' = 'aal2'` into is_active_admin(), or check
-- (select auth.jwt()->>'aal') = 'aal2' directly inside sensitive policies.
```

This is deliberately left as a follow-up step so you can roll MFA out to your admins first
without locking anyone out mid-migration.

## 8. Deploy the WhatsApp notification function

Requires the [Supabase CLI](https://supabase.com/docs/guides/cli).

```bash
supabase login
supabase link --project-ref <your-project-ref>
supabase functions deploy notify-whatsapp

supabase secrets set \
  WHATSAPP_TOKEN=<your Meta Cloud API token> \
  WHATSAPP_PHONE_ID=<your Cloud API phone number id> \
  WHATSAPP_RECIPIENT=255782956145 \
  WHATSAPP_TEMPLATE_NAME=fortitude_ticket_alert \
  SUPABASE_URL=https://<project-ref>.supabase.co \
  SUPABASE_SERVICE_ROLE_KEY=<service role key, from Project Settings > API>
```

You'll need a WhatsApp Business Cloud API account (via Meta for Developers) and an **approved
message template** named to match `WHATSAPP_TEMPLATE_NAME`, with 6 body variables in this order:
ticket number, priority, category, location, title, status.

Then wire the trigger: **Database → Webhooks → Create a new hook**
- Table: `tickets`
- Events: `INSERT`, `UPDATE`
- Type: HTTP request → your function's URL
  (`https://<project-ref>.functions.supabase.co/notify-whatsapp`)

Until this is deployed, the app still works fully — the Notification Log page will simply stay
empty.

## 9. Test isolation before go-live

This is the most important test in the whole system:

1. Sign up two standard-user accounts (A and B).
2. As A, create a ticket and note its ID from the URL bar or dev tools.
3. As B, try to load that ticket by its ID directly. **You should get "not found," not the
   ticket.** If you ever see B's own tickets contain A's data, or B can open A's ticket by ID,
   stop and re-check that RLS is enabled (`alter table tickets enable row level security;`) and
   that the policies from `schema.sql` applied without error.
4. Repeat with a support account: they should see both tickets.

## 10. Go-live checklist

- [ ] `schema.sql` and `002_extras.sql` both ran without error
- [ ] RLS enabled on every table (schema.sql does this — verify in **Table Editor**, each table
      should show a "RLS enabled" badge)
- [ ] First admin promoted per step 6
- [ ] Isolation tested per step 9 with at least two reporter accounts
- [ ] `config.js` points at your production project, not a dev/staging one
- [ ] WhatsApp function deployed and a test ticket confirmed to arrive on
      +255 782956145
- [ ] Confirm-email turned on for sign-up (step 3) if you want to prevent throwaway addresses
- [ ] Storage bucket `ticket-attachments` confirmed **private** (Table Editor → Storage)
- [ ] Backups: Supabase Pro+ projects get daily backups automatically; confirm your plan covers
      this or set up your own `pg_dump` schedule
