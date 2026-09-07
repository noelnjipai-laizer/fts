// supabase/functions/notify-whatsapp/index.ts
//
// Deploy:   supabase functions deploy notify-whatsapp
// Secrets:  supabase secrets set WHATSAPP_TOKEN=... WHATSAPP_PHONE_ID=... WHATSAPP_RECIPIENT=255782956145
//           supabase secrets set SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=...
//
// Wire it up: Supabase Dashboard → Database → Webhooks → "Create a new hook"
//   Table: tickets   Events: INSERT, UPDATE   Type: HTTP request
//   URL: https://<project-ref>.functions.supabase.co/notify-whatsapp
//   Headers: Authorization: Bearer <anon or service key used only to authenticate the webhook call>
//
// This function is the ONLY place WhatsApp credentials exist. The browser
// never talks to Meta's API directly, per Section 13 of the requirements doc.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const WHATSAPP_TOKEN = Deno.env.get("WHATSAPP_TOKEN")!;
const WHATSAPP_PHONE_ID = Deno.env.get("WHATSAPP_PHONE_ID")!;
const WHATSAPP_RECIPIENT = Deno.env.get("WHATSAPP_RECIPIENT")!; // E.164 without '+', e.g. "255782956145"
const WHATSAPP_TEMPLATE_NAME = Deno.env.get("WHATSAPP_TEMPLATE_NAME") || "fortitude_ticket_alert";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")! // service role — bypasses RLS, server-side only
);

function decideEvent(payload: any): string | null {
  const type = payload.type; // "INSERT" | "UPDATE"
  const rec = payload.record;
  const old = payload.old_record;
  if (type === "INSERT") return "ticket_created";
  if (type === "UPDATE" && old) {
    if (rec.priority !== old.priority && (rec.priority === "Critical" || rec.priority === "High")) return "priority_escalated";
    if (rec.assigned_to !== old.assigned_to && rec.assigned_to) return "ticket_assigned";
  }
  return null; // no notification-worthy change
}

async function sendWhatsApp(ticket: any, event: string) {
  const labels: Record<string, string> = {
    ticket_created: "NEW TICKET",
    priority_escalated: "PRIORITY ESCALATED",
    ticket_assigned: "TICKET ASSIGNED",
  };
  const body = {
    messaging_product: "whatsapp",
    to: WHATSAPP_RECIPIENT,
    type: "template",
    template: {
      name: WHATSAPP_TEMPLATE_NAME,
      language: { code: "en" },
      components: [{
        type: "body",
        parameters: [
          { type: "text", text: ticket.ticket_no },
          { type: "text", text: ticket.priority },
          { type: "text", text: ticket.category },
          { type: "text", text: ticket.location || "—" },
          { type: "text", text: ticket.title },
          { type: "text", text: ticket.status },
        ],
      }],
    },
  };

  const res = await fetch(`https://graph.facebook.com/v20.0/${WHATSAPP_PHONE_ID}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${WHATSAPP_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  const status = res.ok ? "sent" : "failed";
  const providerId = data?.messages?.[0]?.id || null;

  await supabase.from("notification_log").insert({
    ticket_id: ticket.id,
    channel: "whatsapp",
    event_type: event,
    status,
    provider_id: providerId,
  });

  return { ok: res.ok, data };
}

Deno.serve(async (req) => {
  try {
    const payload = await req.json();
    if (payload.table !== "tickets") {
      return new Response(JSON.stringify({ skipped: "not a tickets event" }), { status: 200 });
    }
    const event = decideEvent(payload);
    if (!event) {
      return new Response(JSON.stringify({ skipped: "no notification-worthy change" }), { status: 200 });
    }
    const result = await sendWhatsApp(payload.record, event);
    return new Response(JSON.stringify(result), { status: result.ok ? 200 : 502 });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), { status: 500 });
  }
});
