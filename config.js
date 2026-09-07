/**
 * Fortitude Total Security — Ticketing System
 * Connection config.
 *
 * Fill these in with YOUR Supabase project's values (Project Settings > API).
 * SUPABASE_ANON_KEY is the public/anon key — it is safe to ship in the
 * browser ONLY because every table it can touch is protected by the Row
 * Level Security policies in schema.sql. Never put the service_role key here.
 */
window.FORTITUDE_CONFIG = {
  SUPABASE_URL: "https://aktznmaxelmacdpoakoa.supabase.co",
  SUPABASE_ANON_KEY: "sb_publishable_Z7zjrFBtkg7G-Ok1IyFpwQ_eCA5rGYt",

  // Display-only — the real number lives in the notify-whatsapp Edge Function's
  // WHATSAPP_RECIPIENT secret, not here.
  WHATSAPP_RECIPIENT_DISPLAY: "+255 782956145"
};
