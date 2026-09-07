# Fortitude Total Security — Ticketing System

A complete, working IT/CCTV/electrical-fence/control-room ticketing system, built directly
against your `schema.sql`. Unlike a mock or a local-storage demo, this version is a real
frontend talking to a real Supabase (Postgres) backend — ticket isolation, roles, audit
logging and attachment privacy are all enforced by the database itself via Row Level Security,
not by JavaScript pretending to.

## Start here

Read **`SETUP.md`** — it walks through everything, in order, from a blank Supabase project to
a live system with your first administrator account. Nothing here requires Node.js or a build
step; it's plain HTML/CSS/JS plus two SQL files and one Edge Function.

## File map

| File | Purpose |
|---|---|
| `schema.sql` | Your database schema — tables, enums, triggers, RLS policies (unmodified) |
| `002_extras.sql` | Adds the attachments storage bucket + policies, and a safe security-event logger |
| `index.html` | App shell — loads Supabase JS, your config, styles and app logic |
| `config.js` | **Edit this** — your Supabase project URL and anon key |
| `styles.css` | Visual design (white / dark-blue, per the requirements doc) |
| `app.js` | All application logic: auth, tickets, comments, attachments, admin, MFA |
| `supabase/functions/notify-whatsapp/index.ts` | Server-side WhatsApp Cloud API integration |

## What's real vs. what needs your input

**Real and working once you complete SETUP.md:**
- Sign up / sign in / sign out, email-based password recovery, self-service MFA enrollment
- Ticket create/view/update, feedback, internal staff-only notes
- Private file attachments via signed URLs
- Row Level Security enforcing that a standard user can only ever see their own tickets —
  enforced in Postgres, so it holds even against a modified or malicious client
- An automatic, tamper-proof audit trail (written by database triggers, not app code)
- Role-based admin console: dashboard stats, ticket management, user management, audit log,
  security events

**Needs your input to go live:**
- A WhatsApp Business Cloud API account and an approved message template (Section 8 of
  SETUP.md) — until then, tickets still work, notifications just don't send
- Your first administrator (one manual SQL command, Section 6 of SETUP.md)
- Hosting the static files somewhere (Section 5) — Netlify, Vercel, S3+CloudFront, or your
  own server all work fine

## Design notes

Two roles beyond "reporter" exist in this schema: `support` and `admin` (no separate
"super admin" tier — grant `admin` to whoever needs full control). The ticket status set
matches `schema.sql`'s `ticket_status` enum (`Open → Acknowledged → In Progress → Waiting for
User → Resolved → Closed`). If you want to add `Escalated` or `Reopened` as the original
requirements document describes, extend the enum:

```sql
alter type ticket_status add value 'Escalated';
alter type ticket_status add value 'Reopened';
```

then add them to the `STATUSES` array near the top of `app.js`.
