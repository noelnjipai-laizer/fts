/* =============================================================================
 * Fortitude Total Security — Ticketing System
 * Real Supabase-backed frontend. Talks directly to the schema in schema.sql
 * via supabase-js. All isolation, ownership and role checks are enforced by
 * Postgres Row Level Security — this file does not re-implement them; it
 * only hides controls the current role has no policy for, for a clean UI.
 * ============================================================================= */
(function () {
  "use strict";

  const CFG = window.FORTITUDE_CONFIG || {};
  const NOT_CONFIGURED =
    !CFG.SUPABASE_URL ||
    CFG.SUPABASE_URL.indexOf("YOUR-PROJECT-REF") !== -1 ||
    !CFG.SUPABASE_ANON_KEY ||
    CFG.SUPABASE_ANON_KEY.indexOf("YOUR-ANON-PUBLIC-KEY") !== -1;

  const root = document.getElementById("app");

  if (NOT_CONFIGURED) {
    root.innerHTML =
      '<div class="auth-shell"><div class="auth-side">' +
      '<div><div class="brand-mark">FORTITUDE TOTAL SECURITY</div>' +
      "<h1>Ticketing system</h1>" +
      '<p class="lede">This app has not been connected to a Supabase project yet.</p></div></div>' +
      '<div class="auth-main"><div class="auth-card">' +
      "<h2>Setup needed</h2>" +
      '<div class="msg msg-info">Open <b>config.js</b> and fill in <span class="mono">SUPABASE_URL</span> and ' +
      '<span class="mono">SUPABASE_ANON_KEY</span> from your Supabase project (Project Settings → API), ' +
      "then reload this page. Full steps are in <b>SETUP.md</b>.</div>" +
      "</div></div></div>";
    return;
  }

  const sb = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: true, persistSession: true, detectSessionInUrl: true }
  });

  /* ================= Domain constants (must match schema.sql enums) ================= */
  const CATEGORIES = [
    "IT/Computer", "CCTV Camera", "Electrical Fence",
    "Control Room Electrical Component", "Network/Internet", "Access/Device", "Other"
  ];
  const PRIORITIES = ["Low", "Medium", "High", "Critical"];
  const PRIORITY_INFO = {
    Low: { cls: "pill-low", def: "Minor issue, limited operational impact." },
    Medium: { cls: "pill-medium", def: "Important issue, workaround available or limited effect." },
    High: { cls: "pill-high", def: "Major operational impact or multiple components affected." },
    Critical: { cls: "pill-critical", def: "Immediate security, safety or mission-critical impact." }
  };
  const STATUSES = ["Open", "Acknowledged", "In Progress", "Waiting for User", "Resolved", "Closed"];
  const STATUS_CLASS = { Closed: "closed", Resolved: "resolved" };
  const ROLE_LABEL = { reporter: "Standard User", support: "Support / Operator", admin: "Administrator" };
  const ATTACHMENT_BUCKET = "ticket-attachments";
  const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
  const ALLOWED_ATTACHMENT_TYPES = ["image/jpeg", "image/png", "application/pdf"];

  /* ================= App state ================= */
  let state = {
    session: null,
    profile: null,
    route: "welcome",
    authTab: "signin",
    banner: null,
    mfa: null,          // {factorId, challengeId}
    recovery: false,    // true when URL is a password-recovery link
    activeTicketId: null,
    ticketFilter: { q: "", category: "", priority: "", status: "", assigned: "" },
    userFilter: { q: "", role: "" },
    showAddNoteInternal: false,
    showEnroll2fa: false,
    enroll2faData: null,
    cache: { users: [] }
  };

  function setBanner(type, text) { state.banner = { type, text }; }
  function escapeHtml(s) {
    if (s === undefined || s === null) return "";
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" }) +
      " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  function priorityPill(p) { return `<span class="pill ${PRIORITY_INFO[p] ? PRIORITY_INFO[p].cls : ""}">${escapeHtml(p)}</span>`; }
  function statusPill(s) { return `<span class="pill pill-status ${STATUS_CLASS[s] || ""}">${escapeHtml(s)}</span>`; }

  // Best-effort security event logging via the log_security_event() RPC
  // (SECURITY DEFINER function — see 002_extras.sql). Never blocks the UI.
  async function logSecurityEvent(eventType, metadata) {
    try { await sb.rpc("log_security_event", { p_event_type: eventType, p_metadata: metadata || {} }); }
    catch (e) { /* non-fatal */ }
  }

  /* ================= Auth ================= */
  async function refreshSessionAndProfile() {
    const { data: { session } } = await sb.auth.getSession();
    state.session = session;
    if (session) {
      const { data, error } = await sb.from("profiles").select("*").eq("id", session.user.id).single();
      state.profile = error ? null : data;
    } else {
      state.profile = null;
    }
  }

  async function needsMfaStep() {
    const { data, error } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error || !data) return false;
    return data.nextLevel === "aal2" && data.currentLevel !== "aal2";
  }

  async function doSignUp(fd) {
    const name = fd.get("name").trim(), email = fd.get("email").trim().toLowerCase();
    const phone = fd.get("phone").trim(), site = fd.get("site").trim();
    const pw = fd.get("password"), pw2 = fd.get("password2");
    if (!name || !email || !pw) return setBanner("error", "Name, email and password are required.");
    if (pw.length < 8 || !/[0-9]/.test(pw) || !/[A-Za-z]/.test(pw)) return setBanner("error", "Password must be at least 8 characters and include a letter and a number.");
    if (pw !== pw2) return setBanner("error", "Passwords do not match.");
    const { data, error } = await sb.auth.signUp({
      email, password: pw,
      options: { data: { full_name: name } }
    });
    if (error) return setBanner("error", error.message);
    // Phone/site aren't part of auth metadata capture in the schema trigger; set them now if we already have a session.
    if (data.session) {
      await sb.from("profiles").update({ phone, site }).eq("id", data.user.id);
      await refreshSessionAndProfile();
      state.route = "dashboard";
      setBanner("ok", "Account created.");
    } else {
      setBanner("ok", "Account created. Check your email to confirm your address, then sign in.");
      state.authTab = "signin";
    }
  }

  async function doSignIn(fd) {
    const email = fd.get("email").trim().toLowerCase();
    const password = fd.get("password");
    const { error } = await sb.auth.signInWithPassword({ email, password });
    if (error) {
      await logSecurityEvent("login_failed", { email });
      return setBanner("error", error.message === "Invalid login credentials" ? "Incorrect email or password." : error.message);
    }
    if (await needsMfaStep()) {
      const { data: factors } = await sb.auth.mfa.listFactors();
      const totp = factors && factors.totp && factors.totp[0];
      if (totp) {
        const { data: challenge, error: chErr } = await sb.auth.mfa.challenge({ factorId: totp.id });
        if (chErr) return setBanner("error", chErr.message);
        state.mfa = { factorId: totp.id, challengeId: challenge.id };
        state.route = "mfa";
        return;
      }
    }
    await refreshSessionAndProfile();
    await logSecurityEvent("login_success", {});
    routeAfterLogin();
  }

  async function doVerifyMfa(fd) {
    const code = fd.get("code").trim();
    if (!state.mfa) return;
    const { error } = await sb.auth.mfa.verify({ factorId: state.mfa.factorId, challengeId: state.mfa.challengeId, code });
    if (error) return setBanner("error", "Incorrect code. " + error.message);
    state.mfa = null;
    await refreshSessionAndProfile();
    await logSecurityEvent("login_success_mfa", {});
    routeAfterLogin();
  }

  function routeAfterLogin() {
    const role = state.profile ? state.profile.role : "reporter";
    state.route = role === "reporter" ? "dashboard" : (role === "support" ? "ticket_management" : "admin_dashboard");
    setBanner(null, null);
  }

  async function doSignOut() {
    await logSecurityEvent("logout", {});
    await sb.auth.signOut();
    state.session = null; state.profile = null;
    state.route = "welcome"; state.authTab = "signin";
    setBanner(null, null);
  }

  async function doForgotPassword(fd) {
    const email = fd.get("email").trim().toLowerCase();
    await sb.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin + window.location.pathname });
    setBanner("info", "If that account exists, a password reset email has been sent.");
    state.route = "welcome"; state.authTab = "signin";
  }

  async function doCompleteRecovery(fd) {
    const pw = fd.get("pw"), pw2 = fd.get("pw2");
    if (pw !== pw2) return setBanner("error", "Passwords do not match.");
    if (pw.length < 8 || !/[0-9]/.test(pw) || !/[A-Za-z]/.test(pw)) return setBanner("error", "Password must be at least 8 characters and include a letter and a number.");
    const { error } = await sb.auth.updateUser({ password: pw });
    if (error) return setBanner("error", error.message);
    await logSecurityEvent("password_reset_completed", {});
    state.recovery = false;
    history.replaceState(null, "", window.location.pathname);
    await refreshSessionAndProfile();
    setBanner("ok", "Password updated.");
    routeAfterLogin();
  }

  async function doChangePassword(fd) {
    const current = fd.get("current"), newpw = fd.get("newpw"), newpw2 = fd.get("newpw2");
    if (newpw !== newpw2) return setBanner("error", "New passwords do not match.");
    if (newpw.length < 8 || !/[0-9]/.test(newpw) || !/[A-Za-z]/.test(newpw)) return setBanner("error", "Password must be at least 8 characters and include a letter and a number.");
    // Re-authenticate with current password first.
    const { error: reErr } = await sb.auth.signInWithPassword({ email: state.session.user.email, password: current });
    if (reErr) return setBanner("error", "Current password is incorrect.");
    const { error } = await sb.auth.updateUser({ password: newpw });
    if (error) return setBanner("error", error.message);
    await logSecurityEvent("password_changed", {});
    setBanner("ok", "Password updated.");
  }

  /* ================= MFA enrollment (self-service, from Profile) ================= */
  async function startEnroll2fa() {
    const { data, error } = await sb.auth.mfa.enroll({ factorType: "totp" });
    if (error) return setBanner("error", error.message);
    state.enroll2faData = data;
    state.showEnroll2fa = true;
  }
  async function confirmEnroll2fa(fd) {
    const code = fd.get("code").trim();
    const factorId = state.enroll2faData.id;
    const { data: challenge, error: chErr } = await sb.auth.mfa.challenge({ factorId });
    if (chErr) return setBanner("error", chErr.message);
    const { error } = await sb.auth.mfa.verify({ factorId, challengeId: challenge.id, code });
    if (error) return setBanner("error", "Incorrect code.");
    state.showEnroll2fa = false;
    state.enroll2faData = null;
    setBanner("ok", "Two-factor authentication enabled on your account.");
  }

  /* ================= Ticket data access (RLS does the isolation) ================= */
  async function listTickets() {
    const { data, error } = await sb.from("tickets").select("*").order("created_at", { ascending: false });
    if (error) { setBanner("error", error.message); return []; }
    return data;
  }
  async function getTicket(id) {
    const { data, error } = await sb.from("tickets").select("*").eq("id", id).maybeSingle();
    if (error) { setBanner("error", error.message); return null; }
    return data; // null if not found OR not permitted — RLS makes these indistinguishable, by design
  }
  async function createTicket(fields) {
    if (!fields.category || !fields.title || !fields.description || !fields.priority || !fields.location) {
      return setBanner("error", "Category, title, description, priority and location are required.");
    }
    const { data, error } = await sb.from("tickets").insert({
      category: fields.category, title: fields.title.trim(), description: fields.description.trim(),
      location: fields.location.trim(), asset_id: fields.asset_id || null, priority: fields.priority
      // reporter_id, ticket_no, status default and updated_at are all set server-side by triggers
    }).select().single();
    if (error) return setBanner("error", error.message);
    setBanner("ok", "Ticket " + data.ticket_no + " created.");
    state.activeTicketId = data.id;
    state.route = "ticket_details";
  }
  async function updateTicket(id, fields) {
    const { error } = await sb.from("tickets").update(fields).eq("id", id);
    if (error) return setBanner("error", "Could not update ticket: " + error.message);
    setBanner("ok", "Ticket updated.");
  }
  async function listMessages(ticketId) {
    const { data, error } = await sb.from("ticket_messages").select("*").eq("ticket_id", ticketId).order("created_at", { ascending: true });
    if (error) { setBanner("error", error.message); return []; }
    return data;
  }
  async function addMessage(ticketId, message, visibility) {
    if (!message || !message.trim()) return setBanner("error", "Message cannot be empty.");
    const { error } = await sb.from("ticket_messages").insert({ ticket_id: ticketId, message: message.trim(), visibility });
    if (error) return setBanner("error", error.message);
    setBanner("ok", visibility === "internal" ? "Internal note added." : "Feedback added.");
  }
  async function listAttachments(ticketId) {
    const { data, error } = await sb.from("ticket_attachments").select("*").eq("ticket_id", ticketId).order("created_at", { ascending: false });
    if (error) return [];
    return data;
  }
  async function uploadAttachment(ticketId, file) {
    if (!ALLOWED_ATTACHMENT_TYPES.includes(file.type)) return setBanner("error", "Only JPEG, PNG or PDF files are allowed.");
    if (file.size > MAX_ATTACHMENT_BYTES) return setBanner("error", "File must be 5 MB or smaller.");
    const path = ticketId + "/" + crypto.randomUUID() + "-" + file.name.replace(/[^a-zA-Z0-9.\-_]/g, "_");
    const { error: upErr } = await sb.storage.from(ATTACHMENT_BUCKET).upload(path, file, { contentType: file.type });
    if (upErr) return setBanner("error", "Upload failed: " + upErr.message);
    const { error: rowErr } = await sb.from("ticket_attachments").insert({
      ticket_id: ticketId, storage_path: path, file_name: file.name, mime_type: file.type, size: file.size
    });
    if (rowErr) return setBanner("error", rowErr.message);
    setBanner("ok", "Attachment uploaded.");
  }
  async function getAttachmentUrl(path) {
    const { data, error } = await sb.storage.from(ATTACHMENT_BUCKET).createSignedUrl(path, 300);
    if (error) { setBanner("error", "Could not generate a link: " + error.message); return null; }
    return data.signedUrl;
  }
  async function listAuditLog(ticketId) {
    let q = sb.from("ticket_audit_log").select("*").order("created_at", { ascending: false }).limit(300);
    if (ticketId) q = q.eq("ticket_id", ticketId);
    const { data, error } = await q;
    if (error) return [];
    return data;
  }
  async function listNotifications() {
    const { data, error } = await sb.from("notification_log").select("*").order("created_at", { ascending: false }).limit(200);
    if (error) return [];
    return data;
  }
  async function listSecurityEvents() {
    const { data, error } = await sb.from("security_events").select("*").order("created_at", { ascending: false }).limit(300);
    if (error) return [];
    return data;
  }

  /* ================= Admin: user/profile management ================= */
  async function listProfiles() {
    const { data, error } = await sb.from("profiles").select("*").order("created_at", { ascending: true });
    if (error) { setBanner("error", error.message); return []; }
    return data;
  }
  async function setProfileActive(userId, active) {
    const { error } = await sb.from("profiles").update({ active }).eq("id", userId);
    if (error) return setBanner("error", error.message);
    setBanner("ok", active ? "User enabled." : "User disabled.");
  }
  async function setProfileRole(userId, role) {
    const { error } = await sb.from("profiles").update({ role }).eq("id", userId);
    if (error) return setBanner("error", error.message);
    setBanner("ok", "Role updated.");
  }
  async function adminSendPasswordReset(email) {
    await sb.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin + window.location.pathname });
    setBanner("ok", "Password reset email sent to " + email + ".");
  }

  /* ================= Rendering ================= */
  function bannerHtml() {
    if (!state.banner || !state.banner.text) return "";
    const cls = state.banner.type === "error" ? "msg-error" : state.banner.type === "ok" ? "msg-ok" : "msg-info";
    return `<div class="msg ${cls}">${escapeHtml(state.banner.text)}</div>`;
  }

  async function render() {
    await refreshSessionAndProfile();
    let html;
    if (state.recovery) {
      html = authWrap(renderRecoveryForm());
    } else if (!state.session) {
      html = await renderAuthArea();
    } else if (state.mfa) {
      html = authWrap(renderMfaScreen());
    } else if (!state.profile) {
      html = authWrap(`<h2>Setting up your account…</h2><div class="msg msg-info">Your profile record hasn't synced yet. If this persists, ask an administrator to check the <span class="mono">on_auth_user_created</span> trigger.</div><button class="btn btn-ghost" data-action="signout">Sign out</button>`);
    } else if (state.profile.active === false) {
      html = authWrap(`<h2>Account disabled</h2><div class="msg msg-error">This account has been disabled. Contact an administrator.</div><button class="btn btn-ghost" data-action="signout">Sign out</button>`);
    } else {
      html = await renderAppShell();
    }
    root.innerHTML = html;
    bindEvents();
  }

  function authWrap(cardInner) {
    return `
    <div class="auth-shell">
      <div class="auth-side">
        <div>
          <div class="brand-mark">FORTITUDE TOTAL SECURITY</div>
          <h1>IT, CCTV &amp; Control Room Ticketing</h1>
          <p class="lede">Report and track technical faults across IT systems, CCTV cameras, electrical fencing and control-room equipment. Every case is isolated to its reporter and processed by authorized personnel only — enforced by the database, not the browser.</p>
        </div>
        <div class="foot">Row Level Security · Full audit trail · WhatsApp alerts to ${escapeHtml(CFG.WHATSAPP_RECIPIENT_DISPLAY || "")}</div>
      </div>
      <div class="auth-main"><div class="auth-card">${cardInner}</div></div>
    </div>`;
  }

  async function renderAuthArea() {
    if (state.route === "forgot") return authWrap(renderForgotForm());
    return authWrap(renderWelcomeCard());
  }
  function renderWelcomeCard() {
    const tab = state.authTab;
    return `
      <div class="tabs">
        <button class="tab-btn ${tab === "signin" ? "active" : ""}" data-action="auth-tab" data-tab="signin">Sign In</button>
        <button class="tab-btn ${tab === "signup" ? "active" : ""}" data-action="auth-tab" data-tab="signup">Sign Up</button>
      </div>
      ${bannerHtml()}
      ${tab === "signin" ? renderSignInForm() : renderSignUpForm()}
    `;
  }
  function renderSignInForm() {
    return `
      <h2>Sign in</h2>
      <div class="sub">Access your tickets and case history.</div>
      <form id="signin-form">
        <div class="field"><label for="si-email">Email</label><input id="si-email" name="email" type="email" required autocomplete="username"></div>
        <div class="field"><label for="si-pw">Password</label><input id="si-pw" name="password" type="password" required autocomplete="current-password"></div>
        <button class="btn btn-primary btn-block" type="submit">Sign in</button>
      </form>
      <div style="margin-top:14px;"><button class="link-btn" data-action="goto-forgot">Forgot password?</button></div>
    `;
  }
  function renderSignUpForm() {
    return `
      <h2>Create your account</h2>
      <div class="sub">For Fortitude staff reporting technical or control-room faults.</div>
      <form id="signup-form">
        <div class="field"><label for="su-name">Full name</label><input id="su-name" name="name" required></div>
        <div class="field"><label for="su-email">Work email</label><input id="su-email" name="email" type="email" required></div>
        <div class="field"><label for="su-phone">Phone</label><input id="su-phone" name="phone" placeholder="+255 7XX XXX XXX"></div>
        <div class="field"><label for="su-site">Site / location</label><input id="su-site" name="site" placeholder="e.g. Head Office"></div>
        <div class="field"><label for="su-pw">Password</label><input id="su-pw" name="password" type="password" required autocomplete="new-password">
          <div class="hint">At least 8 characters, including a letter and a number.</div></div>
        <div class="field"><label for="su-pw2">Confirm password</label><input id="su-pw2" name="password2" type="password" required></div>
        <button class="btn btn-primary btn-block" type="submit">Sign up</button>
      </form>
      <div class="demo-accounts">New accounts start as <b>Standard User</b>. An administrator can grant Support or Administrator access from User Management.</div>
    `;
  }
  function renderForgotForm() {
    return `
      <h2>Account recovery</h2>
      <div class="sub">Enter your email. If an account exists, you'll receive a reset link.</div>
      ${bannerHtml()}
      <form id="forgot-form">
        <div class="field"><label for="fp-email">Email</label><input id="fp-email" name="email" type="email" required></div>
        <button class="btn btn-primary btn-block" type="submit">Send reset link</button>
      </form>
      <div style="margin-top:14px;"><button class="link-btn" data-action="goto-signin">Back to sign in</button></div>
    `;
  }
  function renderRecoveryForm() {
    return `
      <h2>Set a new password</h2>
      <div class="sub">You followed a password reset link. Choose a new password below.</div>
      ${bannerHtml()}
      <form id="recovery-form">
        <div class="field"><label for="rc-pw">New password</label><input id="rc-pw" name="pw" type="password" required></div>
        <div class="field"><label for="rc-pw2">Confirm new password</label><input id="rc-pw2" name="pw2" type="password" required></div>
        <button class="btn btn-primary btn-block" type="submit">Update password</button>
      </form>
    `;
  }
  function renderMfaScreen() {
    return `
      <h2>Two-factor verification</h2>
      <div class="sub">Enter the 6-digit code from your authenticator app.</div>
      ${bannerHtml()}
      <form id="mfa-form">
        <div class="field"><label for="mfa-code">Verification code</label><input id="mfa-code" name="code" maxlength="6" required autocomplete="one-time-code"></div>
        <button class="btn btn-primary btn-block" type="submit">Verify &amp; continue</button>
      </form>
    `;
  }

  /* ---------- App shell ---------- */
  async function renderAppShell() {
    const user = state.profile;
    const nav = [];
    if (user.role === "reporter") {
      nav.push({ r: "dashboard", label: "My Tickets" });
      nav.push({ r: "create_ticket", label: "Create Ticket" });
      nav.push({ r: "profile", label: "Profile" });
    } else if (user.role === "support") {
      nav.push({ r: "ticket_management", label: "Ticket Queue" });
      nav.push({ r: "profile", label: "Profile" });
    } else {
      nav.push({ r: "admin_dashboard", label: "Dashboard" });
      nav.push({ r: "ticket_management", label: "Ticket Management" });
      nav.push({ r: "user_management", label: "User Management" });
      nav.push({ r: "audit_logs", label: "Audit Log" });
      nav.push({ r: "notification_log", label: "Notification Log" });
      nav.push({ r: "security_events", label: "Security Events" });
      nav.push({ r: "system_settings", label: "System Settings" });
      nav.push({ r: "profile", label: "Profile" });
    }
    const navHtml = nav.map(n => `<button class="nav-item ${state.route === n.r ? "active" : ""}" data-action="nav" data-route="${n.r}">${n.label}</button>`).join("");

    let body;
    switch (state.route) {
      case "dashboard": body = await renderMyDashboard(); break;
      case "create_ticket": body = renderCreateTicket(); break;
      case "ticket_details": body = await renderTicketDetails(); break;
      case "profile": body = await renderProfile(); break;
      case "ticket_management": body = await renderTicketManagement(); break;
      case "admin_dashboard": body = await renderAdminDashboard(); break;
      case "user_management": body = await renderUserManagement(); break;
      case "audit_logs": body = await renderAuditLogs(); break;
      case "notification_log": body = await renderNotificationLog(); break;
      case "security_events": body = await renderSecurityEvents(); break;
      case "system_settings": body = renderSystemSettings(); break;
      default: body = await renderMyDashboard();
    }
    const titleMap = {
      dashboard: "My Tickets", create_ticket: "Create Ticket", ticket_details: "Ticket Details",
      profile: "Profile", ticket_management: "Ticket Management", admin_dashboard: "Administrator Dashboard",
      user_management: "User Management", audit_logs: "Audit Log", notification_log: "Notification Log",
      security_events: "Security Events", system_settings: "System Settings"
    };
    return `
    <div class="shell">
      <div class="side-nav">
        <div class="brand"><div class="name">FORTITUDE TOTAL SECURITY</div><div class="tag">TICKETING CONSOLE</div></div>
        ${navHtml}
        <div class="spacer"></div>
        <div class="who">
          <div class="u-name">${escapeHtml(user.full_name)}</div>
          <div class="u-role">${ROLE_LABEL[user.role]}</div>
          <button class="btn btn-ghost btn-sm btn-block" data-action="signout">Sign out</button>
        </div>
      </div>
      <div class="main">
        <div class="topbar"><h1>${titleMap[state.route] || ""}</h1><div class="crumb">${escapeHtml(state.session.user.email)}</div></div>
        <div class="content">${bannerHtml()}${body}</div>
      </div>
    </div>`;
  }

  /* ---------- My Tickets ---------- */
  async function renderMyDashboard() {
    const tickets = await listTickets(); // RLS already scopes this to own tickets for reporters
    const openCount = tickets.filter(t => !["Resolved", "Closed"].includes(t.status)).length;
    const rows = tickets.map(t => `
      <tr class="clickable" data-action="open-ticket" data-id="${t.id}">
        <td class="tnum">${escapeHtml(t.ticket_no)}</td>
        <td>${escapeHtml(t.title)}</td>
        <td>${escapeHtml(t.category)}</td>
        <td>${priorityPill(t.priority)}</td>
        <td>${statusPill(t.status)}</td>
        <td>${fmtDate(t.updated_at)}</td>
      </tr>`).join("");
    return `
      <div class="grid-3" style="margin-bottom:20px;">
        <div class="stat-card"><div class="num">${tickets.length}</div><div class="lbl">Total tickets you've reported</div></div>
        <div class="stat-card"><div class="num">${openCount}</div><div class="lbl">Currently open</div></div>
        <div class="stat-card"><div class="num">${tickets.length - openCount}</div><div class="lbl">Resolved or closed</div></div>
      </div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
          <h3 style="margin:0;">My tickets</h3>
          <button class="btn btn-primary btn-sm" data-action="nav" data-route="create_ticket">+ Create ticket</button>
        </div>
        ${tickets.length ? `<table><thead><tr><th>Ticket #</th><th>Title</th><th>Category</th><th>Priority</th><th>Status</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table>`
        : `<div class="empty-state"><div class="big">No tickets yet</div>Report your first technical or control-room fault to get started.<br><br><button class="btn btn-primary" data-action="nav" data-route="create_ticket">Create your first ticket</button></div>`}
      </div>`;
  }

  /* ---------- Create ticket ---------- */
  function renderCreateTicket() {
    const catOpts = CATEGORIES.map(c => `<option value="${c}">${c}</option>`).join("");
    const prOpts = PRIORITIES.map(p => `<option value="${p}">${p} — ${PRIORITY_INFO[p].def}</option>`).join("");
    return `
      <div class="card content-narrow">
        <h3>Report a fault</h3>
        ${bannerHtml()}
        <form id="ticket-form">
          <div class="field"><label for="tk-category">Category</label><select id="tk-category" name="category" required><option value="">Select a category…</option>${catOpts}</select></div>
          <div class="field"><label for="tk-title">Problem title</label><input id="tk-title" name="title" maxlength="140" required placeholder="Short summary, e.g. Camera 04 offline"></div>
          <div class="field"><label for="tk-desc">Detailed description</label><textarea id="tk-desc" name="description" required placeholder="Symptoms, location, impact, and what you observed"></textarea></div>
          <div class="grid-2">
            <div class="field"><label for="tk-priority">Priority</label><select id="tk-priority" name="priority" required><option value="">Select…</option>${prOpts}</select></div>
            <div class="field"><label for="tk-location">Location</label><input id="tk-location" name="location" required placeholder="e.g. Control Room 1"></div>
          </div>
          <div class="field"><label for="tk-asset">Affected asset (recommended)</label><input id="tk-asset" name="asset_id" placeholder="Computer name, camera number, fence zone, component ID"></div>
          <button class="btn btn-primary" type="submit">Submit ticket</button>
          <button class="btn btn-ghost" type="button" data-action="nav" data-route="dashboard">Cancel</button>
        </form>
        <div class="footer-note">You can attach a photo or PDF once the ticket is created, from the ticket details page.</div>
      </div>`;
  }

  /* ---------- Ticket details ---------- */
  async function renderTicketDetails() {
    const user = state.profile;
    const ticket = await getTicket(state.activeTicketId);
    if (!ticket) {
      return `<div class="card">This ticket was not found, or you do not have access to it. If you believe this is a mistake, contact an administrator — the attempt is recorded.
        <br><br><button class="btn btn-ghost btn-sm" data-action="nav" data-route="dashboard">Back</button></div>`;
    }
    const isStaff = user.role !== "reporter";
    const [messages, attachments, profiles] = await Promise.all([listMessages(ticket.id), listAttachments(ticket.id), listProfiles().catch(() => [])]);
    const reporter = state.cache.users.find(u => u.id === ticket.reporter_id);
    const assignee = state.cache.users.find(u => u.id === ticket.assigned_to);

    const commentsHtml = messages.length ? messages.map(c => {
      const author = state.cache.users.find(u => u.id === c.author_id);
      return `<div class="comment ${c.visibility === "internal" ? "internal" : ""}"><div class="meta"><b>${escapeHtml(author ? author.full_name : "Staff")}</b> · ${fmtDate(c.created_at)}</div>${escapeHtml(c.message)}</div>`;
    }).join("") : `<div class="empty-state" style="padding:20px 0;">No feedback yet.</div>`;

    const attachHtml = attachments.length ? attachments.map(a =>
      `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);font-size:12.5px;">
        <span>${escapeHtml(a.file_name)} <span class="hint">(${Math.round(a.size / 1024)} KB)</span></span>
        <button class="btn btn-ghost btn-sm" data-action="view-attachment" data-path="${escapeHtml(a.storage_path)}">View</button>
      </div>`).join("") : `<div class="hint">No attachments.</div>`;

    const staffControls = isStaff ? `
      <div class="card">
        <h3>Case management</h3>
        <form id="manage-form">
          <div class="grid-2">
            <div class="field"><label for="mg-status">Status</label><select id="mg-status" name="status">${STATUSES.map(s => `<option value="${s}" ${s === ticket.status ? "selected" : ""}>${s}</option>`).join("")}</select></div>
            <div class="field"><label for="mg-priority">Priority</label><select id="mg-priority" name="priority">${PRIORITIES.map(p => `<option value="${p}" ${p === ticket.priority ? "selected" : ""}>${p}</option>`).join("")}</select></div>
          </div>
          <div class="field"><label for="mg-assignee">Assigned to</label>
            <select id="mg-assignee" name="assigned_to">
              <option value="">Unassigned</option>
              ${state.cache.users.filter(u => u.role === "support" || u.role === "admin").map(u => `<option value="${u.id}" ${u.id === ticket.assigned_to ? "selected" : ""}>${escapeHtml(u.full_name)} (${ROLE_LABEL[u.role]})</option>`).join("")}
            </select>
          </div>
          <div class="field"><label for="mg-resolution">Resolution notes</label><textarea id="mg-resolution" name="resolution" placeholder="Recorded when resolving or closing">${escapeHtml(ticket.resolution || "")}</textarea></div>
          <button class="btn btn-primary btn-sm" type="submit">Save changes</button>
        </form>
        <div class="divider"></div>
        <form id="note-form">
          <div class="field"><label for="note-msg">Internal note (staff only)</label><textarea id="note-msg" name="message" placeholder="Not visible to the reporter"></textarea></div>
          <button class="btn btn-ghost btn-sm" type="submit">Add internal note</button>
        </form>
        <div class="divider"></div>
        <h3 style="margin-bottom:10px;">Attachment</h3>
        <input type="file" id="mg-file" accept="image/png,image/jpeg,application/pdf">
        <button class="btn btn-ghost btn-sm" data-action="staff-upload" style="margin-top:8px;">Upload</button>
      </div>` : "";

    return `
      <div class="grid-2" style="align-items:start;">
        <div>
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;">
              <div><div class="tnum" style="font-size:15px;">${escapeHtml(ticket.ticket_no)}</div><h3 style="margin:6px 0 10px;">${escapeHtml(ticket.title)}</h3></div>
              <div style="text-align:right;">${priorityPill(ticket.priority)} ${statusPill(ticket.status)}</div>
            </div>
            <div class="kv">
              <div class="k">Category</div><div>${escapeHtml(ticket.category)}</div>
              <div class="k">Location</div><div>${escapeHtml(ticket.location) || "—"}</div>
              <div class="k">Asset</div><div>${escapeHtml(ticket.asset_id) || "—"}</div>
              ${isStaff ? `<div class="k">Reporter</div><div>${escapeHtml(reporter ? reporter.full_name : "—")}</div>` : ""}
              <div class="k">Assigned to</div><div>${assignee ? escapeHtml(assignee.full_name) : "Unassigned"}</div>
              <div class="k">Created</div><div>${fmtDate(ticket.created_at)}</div>
              <div class="k">Last updated</div><div>${fmtDate(ticket.updated_at)}</div>
            </div>
            <div class="divider"></div>
            <div style="white-space:pre-wrap;font-size:13.5px;">${escapeHtml(ticket.description)}</div>
            ${ticket.resolution ? `<div class="divider"></div><b style="font-size:12.5px;">Resolution:</b><div style="white-space:pre-wrap;font-size:13.5px;">${escapeHtml(ticket.resolution)}</div>` : ""}
            <div class="divider"></div>
            <b style="font-size:12.5px;">Attachments</b>
            ${attachHtml}
            ${!isStaff ? `<div style="margin-top:10px;"><input type="file" id="my-file" accept="image/png,image/jpeg,application/pdf"><button class="btn btn-ghost btn-sm" data-action="reporter-upload" style="margin-top:8px;">Upload</button></div>` : ""}
          </div>
          <div class="card">
            <h3>Feedback</h3>
            <div>${commentsHtml}</div>
            <div class="divider"></div>
            <form id="comment-form">
              <div class="field"><label for="cm-msg">Add feedback</label><textarea id="cm-msg" name="message" placeholder="Add an update or ask a question"></textarea></div>
              <button class="btn btn-primary btn-sm" type="submit">Post feedback</button>
            </form>
          </div>
        </div>
        <div>${staffControls}</div>
      </div>
      <button class="btn btn-ghost btn-sm" data-action="nav" data-route="${user.role === "reporter" ? "dashboard" : "ticket_management"}">← Back</button>`;
  }

  /* ---------- Staff: ticket queue ---------- */
  async function renderTicketManagement() {
    const all = await listTickets();
    if (!state.cache.users.length) state.cache.users = await listProfiles();
    const f = state.ticketFilter;
    let list = all;
    if (f.q) list = list.filter(t => t.ticket_no.toLowerCase().includes(f.q.toLowerCase()) || t.title.toLowerCase().includes(f.q.toLowerCase()));
    if (f.category) list = list.filter(t => t.category === f.category);
    if (f.priority) list = list.filter(t => t.priority === f.priority);
    if (f.status) list = list.filter(t => t.status === f.status);
    if (f.assigned === "unassigned") list = list.filter(t => !t.assigned_to);
    if (f.assigned === "mine") list = list.filter(t => t.assigned_to === state.session.user.id);

    const rows = list.map(t => {
      const assignee = state.cache.users.find(u => u.id === t.assigned_to);
      return `<tr class="clickable" data-action="open-ticket" data-id="${t.id}">
        <td class="tnum">${escapeHtml(t.ticket_no)}</td><td>${escapeHtml(t.title)}</td><td>${escapeHtml(t.category)}</td>
        <td>${priorityPill(t.priority)}</td><td>${statusPill(t.status)}</td>
        <td>${assignee ? escapeHtml(assignee.full_name) : '<span class="hint">Unassigned</span>'}</td><td>${fmtDate(t.updated_at)}</td>
      </tr>`;
    }).join("");

    return `
      <div class="card">
        <div class="toolbar">
          <div class="field grow"><label>Search</label><input id="f-q" value="${escapeHtml(f.q)}" placeholder="Ticket # or title"></div>
          <div class="field"><label>Category</label><select id="f-category"><option value="">All</option>${CATEGORIES.map(c => `<option ${f.category === c ? "selected" : ""}>${c}</option>`).join("")}</select></div>
          <div class="field"><label>Priority</label><select id="f-priority"><option value="">All</option>${PRIORITIES.map(p => `<option ${f.priority === p ? "selected" : ""}>${p}</option>`).join("")}</select></div>
          <div class="field"><label>Status</label><select id="f-status"><option value="">All</option>${STATUSES.map(s => `<option ${f.status === s ? "selected" : ""}>${s}</option>`).join("")}</select></div>
          <div class="field"><label>Assignment</label><select id="f-assigned"><option value="">All</option><option value="mine" ${f.assigned === "mine" ? "selected" : ""}>Assigned to me</option><option value="unassigned" ${f.assigned === "unassigned" ? "selected" : ""}>Unassigned</option></select></div>
          <button class="btn btn-ghost btn-sm" data-action="apply-filters">Apply</button>
        </div>
        ${list.length ? `<table><thead><tr><th>Ticket #</th><th>Title</th><th>Category</th><th>Priority</th><th>Status</th><th>Assigned</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty-state">No tickets match these filters.</div>`}
      </div>`;
  }

  /* ---------- Admin dashboard ---------- */
  async function renderAdminDashboard() {
    const tickets = await listTickets();
    const audit = await listAuditLog(null);
    if (!state.cache.users.length) state.cache.users = await listProfiles();
    const byStatus = {}; STATUSES.forEach(s => byStatus[s] = 0);
    tickets.forEach(t => byStatus[t.status] = (byStatus[t.status] || 0) + 1);
    const byPriority = {}; PRIORITIES.forEach(p => byPriority[p] = 0);
    tickets.forEach(t => byPriority[t.priority] = (byPriority[t.priority] || 0) + 1);
    const byCategory = {}; CATEGORIES.forEach(c => byCategory[c] = 0);
    tickets.forEach(t => byCategory[t.category] = (byCategory[t.category] || 0) + 1);
    const openTickets = tickets.filter(t => !["Resolved", "Closed"].includes(t.status));
    const now = Date.now();
    const aged = openTickets.filter(t => (now - new Date(t.created_at).getTime()) > 3 * 24 * 3600 * 1000).length;

    const recentAudit = audit.slice(0, 8).map(a => {
      const actor = state.cache.users.find(u => u.id === a.actor_id);
      return `<div class="log-line"><b>${escapeHtml(actor ? actor.full_name : "System")}</b> ${a.action.replace(/_/g, " ")} · ${fmtDate(a.created_at)}</div>`;
    }).join("") || `<div class="empty-state">No activity yet.</div>`;

    return `
      <div class="grid-4" style="margin-bottom:18px;">
        <div class="stat-card"><div class="num">${tickets.length}</div><div class="lbl">Total tickets</div></div>
        <div class="stat-card"><div class="num">${openTickets.length}</div><div class="lbl">Open (all statuses)</div></div>
        <div class="stat-card"><div class="num">${aged}</div><div class="lbl">Open &gt; 3 days old</div></div>
        <div class="stat-card"><div class="num">${state.cache.users.filter(u => u.active).length}</div><div class="lbl">Active users</div></div>
      </div>
      <div class="grid-3">
        <div class="card"><h3>By status</h3>${Object.entries(byStatus).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px;"><span>${k}</span><b>${v}</b></div>`).join("")}</div>
        <div class="card"><h3>By priority</h3>${Object.entries(byPriority).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;">${priorityPill(k)}<b>${v}</b></div>`).join("")}</div>
        <div class="card"><h3>By category</h3>${Object.entries(byCategory).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:12.5px;"><span>${k}</span><b>${v}</b></div>`).join("")}</div>
      </div>
      <div class="card"><h3>Recent activity</h3>${recentAudit}</div>`;
  }

  /* ---------- User management ---------- */
  async function renderUserManagement() {
    const users = await listProfiles();
    state.cache.users = users;
    const f = state.userFilter;
    let list = users;
    if (f.q) list = list.filter(u => u.full_name.toLowerCase().includes(f.q.toLowerCase()));
    if (f.role) list = list.filter(u => u.role === f.role);
    const rows = list.map(u => `
      <tr>
        <td>${escapeHtml(u.full_name)}</td>
        <td>${escapeHtml(u.site || "—")}</td>
        <td><select data-action="change-role" data-id="${u.id}" ${u.id === state.session.user.id ? "disabled" : ""}>${Object.entries(ROLE_LABEL).map(([k, v]) => `<option value="${k}" ${k === u.role ? "selected" : ""}>${v}</option>`).join("")}</select></td>
        <td>${u.active ? '<span class="badge-role">ACTIVE</span>' : '<span class="badge-disabled">DISABLED</span>'}</td>
        <td style="white-space:nowrap;">
          ${u.id !== state.session.user.id ? `<button class="btn btn-ghost btn-sm" data-action="${u.active ? "disable-user" : "enable-user"}" data-id="${u.id}">${u.active ? "Disable" : "Enable"}</button>` : ""}
          <button class="btn btn-ghost btn-sm" data-action="reset-user-pw" data-id="${u.id}">Send reset email</button>
        </td>
      </tr>`).join("");
    return `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
          <h3 style="margin:0;">Users</h3>
          <span class="hint">New accounts are created by inviting them in Supabase Auth or via self sign-up — see SETUP.md.</span>
        </div>
        <div class="toolbar">
          <div class="field grow"><label>Search</label><input id="uf-q" value="${escapeHtml(f.q)}" placeholder="Name"></div>
          <div class="field"><label>Role</label><select id="uf-role"><option value="">All</option>${Object.entries(ROLE_LABEL).map(([k, v]) => `<option value="${k}" ${f.role === k ? "selected" : ""}>${v}</option>`).join("")}</select></div>
          <button class="btn btn-ghost btn-sm" data-action="apply-user-filters">Apply</button>
        </div>
        <table><thead><tr><th>Name</th><th>Site</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  }

  /* ---------- Audit / Notifications / Security events ---------- */
  async function renderAuditLogs() {
    const audit = await listAuditLog(null);
    if (!state.cache.users.length) state.cache.users = await listProfiles();
    const rows = audit.map(a => {
      const actor = state.cache.users.find(u => u.id === a.actor_id);
      return `<div class="log-line"><span class="mono">${fmtDate(a.created_at)}</span> — <b>${escapeHtml(actor ? actor.full_name : "System")}</b> · ${a.action.replace(/_/g, " ")} ${a.ticket_id ? "· ticket " + a.ticket_id.slice(0, 8) : ""}</div>`;
    }).join("") || `<div class="empty-state">No audit records.</div>`;
    return `<div class="card"><h3>Ticket audit log</h3><p class="hint">Written automatically by database triggers on every ticket insert/update — never by client code.</p>${rows}</div>`;
  }
  async function renderNotificationLog() {
    const notifications = await listNotifications();
    const rows = notifications.map(n => `<tr><td class="mono" style="font-size:11px;">${n.ticket_id ? n.ticket_id.slice(0, 8) : "—"}</td><td>${escapeHtml(n.event_type.replace(/_/g, " "))}</td><td><span class="pill pill-low">${n.status}</span></td><td class="mono" style="font-size:11px;">${n.provider_id || "—"}</td><td>${fmtDate(n.created_at)}</td></tr>`).join("");
    return `<div class="card"><h3>WhatsApp notification delivery</h3><p class="hint">Populated by the notify-whatsapp Edge Function — the browser never calls the WhatsApp API directly.</p>
      ${notifications.length ? `<table><thead><tr><th>Ticket</th><th>Event</th><th>Status</th><th>Provider ID</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty-state">No notifications sent yet.</div>`}</div>`;
  }
  async function renderSecurityEvents() {
    const events = await listSecurityEvents();
    if (!state.cache.users.length) state.cache.users = await listProfiles();
    const rows = events.map(e => {
      const u = state.cache.users.find(x => x.id === e.user_id);
      return `<div class="log-line"><span class="mono">${fmtDate(e.created_at)}</span> — ${escapeHtml(u ? u.full_name : (e.metadata && e.metadata.email) || "Unknown")} · ${e.event_type.replace(/_/g, " ")}</div>`;
    }).join("") || `<div class="empty-state">No security events recorded yet.</div>`;
    return `<div class="card"><h3>Security events</h3><p class="hint">Login attempts, MFA verification and password changes, logged via a SECURITY DEFINER function so the browser cannot spoof someone else's events.</p>${rows}</div>`;
  }

  /* ---------- System settings ---------- */
  function renderSystemSettings() {
    return `
      <div class="card content-narrow">
        <h3>WhatsApp notifications</h3>
        <div class="kv">
          <div class="k">Recipient</div><div class="mono">${escapeHtml(CFG.WHATSAPP_RECIPIENT_DISPLAY || "")}</div>
          <div class="k">Provider</div><div>WhatsApp Business / Cloud API (configured as Edge Function secrets)</div>
          <div class="k">Trigger</div><div>Database Webhook on ticket insert/update → notify-whatsapp Edge Function</div>
        </div>
      </div>
      <div class="card content-narrow"><h3>Storage</h3><p class="hint">Attachments live in the private <span class="mono">ticket-attachments</span> bucket and are only ever accessed via short-lived signed URLs.</p></div>
      <div class="card content-narrow"><h3>Retention</h3><p class="hint">Fortitude management should approve the retention schedule for tickets, attachments, audit logs, profiles and notification records, then implement it as a scheduled job (e.g. pg_cron or an Edge Function on a schedule).</p></div>`;
  }

  /* ---------- Profile ---------- */
  async function renderProfile() {
    const user = state.profile;
    const { data: factors } = await sb.auth.mfa.listFactors().catch(() => ({ data: null }));
    const has2fa = factors && factors.totp && factors.totp.length > 0;
    const eligibleFor2fa = user.role === "admin" || user.role === "support";
    return `
      <div class="card content-narrow">
        <h3>Your profile</h3>
        <div class="kv">
          <div class="k">Name</div><div>${escapeHtml(user.full_name)}</div>
          <div class="k">Email</div><div>${escapeHtml(state.session.user.email)}</div>
          <div class="k">Phone</div><div>${escapeHtml(user.phone || "—")}</div>
          <div class="k">Site</div><div>${escapeHtml(user.site || "—")}</div>
          <div class="k">Role</div><div>${ROLE_LABEL[user.role]}</div>
          <div class="k">Account created</div><div>${fmtDate(user.created_at)}</div>
        </div>
      </div>
      <div class="card content-narrow">
        <h3>Change password</h3>${bannerHtml()}
        <form id="change-pw-form">
          <div class="field"><label for="cp-current">Current password</label><input id="cp-current" name="current" type="password" required></div>
          <div class="field"><label for="cp-new">New password</label><input id="cp-new" name="newpw" type="password" required></div>
          <div class="field"><label for="cp-new2">Confirm new password</label><input id="cp-new2" name="newpw2" type="password" required></div>
          <button class="btn btn-primary btn-sm" type="submit">Update password</button>
        </form>
      </div>
      ${eligibleFor2fa ? `
      <div class="card content-narrow">
        <h3>Two-factor authentication</h3>
        ${has2fa ? `<div class="msg msg-ok">Enabled on this account.</div>` :
          state.showEnroll2fa ? renderEnroll2faForm() :
          `<p class="hint">Required for administrator accounts, recommended for support staff.</p><button class="btn btn-primary btn-sm" data-action="start-enroll-2fa">Enable 2FA</button>`}
      </div>` : ""}`;
  }
  function renderEnroll2faForm() {
    const d = state.enroll2faData;
    return `
      <p class="hint">Scan this with your authenticator app, or enter the secret manually:</p>
      <div style="text-align:center;margin:12px 0;"><img src="${d.totp.qr_code}" alt="TOTP QR code" style="max-width:180px;"></div>
      <div class="mono" style="font-size:11px;text-align:center;word-break:break-all;margin-bottom:14px;">${escapeHtml(d.totp.secret)}</div>
      <form id="confirm-2fa-form">
        <div class="field"><label for="c2-code">Enter the 6-digit code to confirm</label><input id="c2-code" name="code" maxlength="6" required></div>
        <button class="btn btn-primary btn-sm" type="submit">Confirm &amp; enable</button>
      </form>`;
  }

  /* ================= Event binding ================= */
  function bindForm(id, handler) {
    const f = document.getElementById(id);
    if (!f) return;
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(f);
      const submitBtn = f.querySelector('button[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;
      try { await handler(fd); } finally { await render(); }
    });
  }

  function applyTicketFilters() {
    state.ticketFilter = {
      q: document.getElementById("f-q")?.value || "",
      category: document.getElementById("f-category")?.value || "",
      priority: document.getElementById("f-priority")?.value || "",
      status: document.getElementById("f-status")?.value || "",
      assigned: document.getElementById("f-assigned")?.value || ""
    };
  }
  function applyUserFilters() {
    state.userFilter = { q: document.getElementById("uf-q")?.value || "", role: document.getElementById("uf-role")?.value || "" };
  }

  function bindEvents() {
    root.querySelectorAll("[data-action]").forEach(el => {
      const action = el.getAttribute("data-action");
      if (el.tagName === "SELECT" && action === "change-role") {
        el.addEventListener("change", async () => { await setProfileRole(el.getAttribute("data-id"), el.value); await render(); });
        return;
      }
      el.addEventListener("click", async () => {
        switch (action) {
          case "auth-tab": state.authTab = el.getAttribute("data-tab"); state.banner = null; await render(); break;
          case "goto-forgot": state.route = "forgot"; state.banner = null; await render(); break;
          case "goto-signin": state.route = "welcome"; state.authTab = "signin"; state.banner = null; await render(); break;
          case "nav": state.route = el.getAttribute("data-route"); state.banner = null; await render(); break;
          case "signout": await doSignOut(); await render(); break;
          case "open-ticket": state.activeTicketId = el.getAttribute("data-id"); state.route = "ticket_details"; state.banner = null;
            if (!state.cache.users.length) state.cache.users = await listProfiles().catch(() => []);
            await render(); break;
          case "apply-filters": applyTicketFilters(); await render(); break;
          case "apply-user-filters": applyUserFilters(); await render(); break;
          case "disable-user": await setProfileActive(el.getAttribute("data-id"), false); await render(); break;
          case "enable-user": await setProfileActive(el.getAttribute("data-id"), true); await render(); break;
          case "reset-user-pw": {
            const u = state.cache.users.find(x => x.id === el.getAttribute("data-id"));
            if (u) {
              // We only have profile rows client-side (no email column in profiles by design —
              // email lives in auth.users). Ask the admin to enter it once, or extend profiles
              // with an email column if you'd rather look it up directly. See SETUP.md.
              const email = prompt("Confirm this user's email to send a password reset link:");
              if (email) await adminSendPasswordReset(email.trim());
            }
            await render(); break;
          }
          case "start-enroll-2fa": await startEnroll2fa(); await render(); break;
          case "view-attachment": {
            const url = await getAttachmentUrl(el.getAttribute("data-path"));
            if (url) window.open(url, "_blank", "noopener");
            break;
          }
          case "reporter-upload": case "staff-upload": {
            const inputId = action === "reporter-upload" ? "my-file" : "mg-file";
            const input = document.getElementById(inputId);
            if (input && input.files && input.files[0]) {
              await uploadAttachment(state.activeTicketId, input.files[0]);
              await render();
            }
            break;
          }
        }
      });
    });

    bindForm("signin-form", doSignIn);
    bindForm("signup-form", doSignUp);
    bindForm("mfa-form", doVerifyMfa);
    bindForm("forgot-form", doForgotPassword);
    bindForm("recovery-form", doCompleteRecovery);
    bindForm("change-pw-form", doChangePassword);
    bindForm("confirm-2fa-form", confirmEnroll2fa);
    bindForm("comment-form", (fd) => addMessage(state.activeTicketId, fd.get("message"), "public"));
    bindForm("note-form", (fd) => addMessage(state.activeTicketId, fd.get("message"), "internal"));
    bindForm("manage-form", (fd) => updateTicket(state.activeTicketId, {
      status: fd.get("status"), priority: fd.get("priority"),
      assigned_to: fd.get("assigned_to") || null, resolution: fd.get("resolution") || null
    }));
    bindForm("ticket-form", (fd) => createTicket({
      category: fd.get("category"), title: fd.get("title"), description: fd.get("description"),
      priority: fd.get("priority"), location: fd.get("location"), asset_id: fd.get("asset_id")
    }));
  }

  /* ================= Boot ================= */
  async function boot() {
    // Password recovery links land here as #access_token=...&type=recovery (or ?code=... for PKCE).
    const hash = window.location.hash || "";
    const search = window.location.search || "";
    if (hash.indexOf("type=recovery") !== -1 || search.indexOf("type=recovery") !== -1) {
      state.recovery = true;
    }
    sb.auth.onAuthStateChange(async (event) => {
      if (event === "PASSWORD_RECOVERY") state.recovery = true;
      if (event === "SIGNED_OUT") { state.session = null; state.profile = null; }
      await render();
    });
    await render();
  }
  boot();
})();
