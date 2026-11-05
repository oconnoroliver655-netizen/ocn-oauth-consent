import { createClient } from "https://esm.sh/@supabase/supabase-js@2.117.3?bundle";
import { CONFIG } from "./config.mjs";
import {
  isConfigured, getAuthorizationId, isOwner, authorizeDetails,
  matchingCallback, classifyOAuthCallback
} from "./guards.mjs";
import { describeSignInError } from "./auth-email-errors.mjs";

const status = document.getElementById("status");
const form = document.getElementById("signin");
const otpForm = document.getElementById("otp");
const review = document.getElementById("review");
const previous = document.getElementById("previous");
const allow = document.getElementById("approve");
const deny = document.getElementById("deny");
const check = document.getElementById("checked");

function report(message) { status.textContent = message; }

// Consent must yield an actual OAuth code+state (or an explicit denial).
// Simply returning to chatgpt.com without an authorization result causes
// the client to ask for additional access again.
function redirectToVerifiedClient(value, expectedOutcome) {
  if (!matchingCallback(value, CONFIG.approvedRedirectUri, true) ||
      classifyOAuthCallback(value, CONFIG.approvedRedirectUri) !== expectedOutcome) {
    report("Authorization callback was incomplete or mismatched. No redirect was performed. Start a fresh connection from ChatGPT.");
    return false;
  }
  window.location.assign(value);
  return true;
}

async function showAuthorization(sb, authorizationId, user) {
  if (!isOwner(user, CONFIG)) {
    form.hidden = true;
    otpForm.hidden = true;
    report("Access denied: the signed-in Supabase account is not the approved owner.");
    return;
  }

  let result;
  try {
    result = await sb.auth.oauth.getAuthorizationDetails(authorizationId);
  } catch {
    report("Unable to fetch OAuth authorization details.");
    return;
  }
  if (result.error || !result.data) {
    report("OAuth request is expired, invalid, or unavailable. Start a fresh connection from ChatGPT.");
    return;
  }
  const details = result.data;
  if (!Object.hasOwn(details, "authorization_id")) {
    if (classifyOAuthCallback(details.redirect_url, CONFIG.approvedRedirectUri) !== "approved") {
      report("Previously approved authorization returned an incomplete callback. Start a fresh connection from ChatGPT.");
      return;
    }
    report("Supabase reports prior consent. Continue in this same browser to complete the ChatGPT connection.");
    previous.hidden = false;
    document.getElementById("continue").addEventListener("click", () =>
      redirectToVerifiedClient(details.redirect_url, "approved"), { once: true });
    return;
  }

  if (!authorizeDetails(details, authorizationId, CONFIG)) {
    report("Blocked: OAuth client, user, request identifier or callback did not match the approved configuration.");
    return;
  }

  document.getElementById("app-name").textContent = String(details.client.name || "Unnamed OAuth app");
  document.getElementById("app-id").textContent = CONFIG.approvedOAuthClientId;
  document.getElementById("callback").textContent = CONFIG.approvedRedirectUri;
  document.getElementById("scopes").textContent = String(details.scope || "(not specified)");
  report("Review the identity permissions and select Allow or Deny.");
  review.hidden = false;
  check.addEventListener("change", () => { allow.disabled = !check.checked; });
  let pending = false;

  async function decide(action) {
    if (pending || (action === "allow" && !check.checked)) return;
    pending = true;
    allow.disabled = true;
    deny.disabled = true;
    report("Submitting consent decision…");
    try {
      // Supabase redirects by default; inspect the exact registered callback first.
      const answer = action === "allow"
        ? await sb.auth.oauth.approveAuthorization(authorizationId, { skipBrowserRedirect: true })
        : await sb.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
      if (answer.error || !answer.data?.redirect_url) {
        report("Consent decision failed. No redirect performed.");
        return;
      }
      redirectToVerifiedClient(answer.data.redirect_url, action === "allow" ? "approved" : "denied");
    } catch {
      report("Consent service unavailable. No redirect performed.");
    } finally {
      pending = false;
      deny.disabled = false;
      allow.disabled = !check.checked;
    }
  }
  allow.addEventListener("click", () => decide("allow"));
  deny.addEventListener("click", () => decide("deny"));
}

async function main() {
  if (!isConfigured(CONFIG)) {
    report("Authorization is not configured yet. No sign-in or permission can be granted.");
    return;
  }
  const authorizationId = getAuthorizationId(window.location.search);
  if (!authorizationId) {
    report("Missing or invalid authorization request. Start from an approved OAuth client.");
    return;
  }
  const sb = createClient(CONFIG.supabaseUrl, CONFIG.publishableKey, {
    auth: { flowType: "pkce", detectSessionInUrl: false, persistSession: true, autoRefreshToken: true }
  });
  const identity = await sb.auth.getUser();
  if (identity?.data?.user && !identity.error) {
    await showAuthorization(sb, authorizationId, identity.data.user);
    return;
  }

  form.hidden = false;
  report("Sign in with your registered email. Keep this page open while reading the code in Gmail.");
  const emailInput = document.getElementById("email");
  const send = document.getElementById("send");
  const codeInput = document.getElementById("code");
  const verify = document.getElementById("verify");
  let requestedEmail = null;
  let attempts = 0;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (send.disabled) return;
    const email = String(emailInput.value || "").trim();
    if (!email || email.length > 254) return;
    send.disabled = true; // Only one email per page; never auto-resend.
    report("Requesting a one-time email code…");
    try {
      const { error } = await sb.auth.signInWithOtp({
        email,
        options: { shouldCreateUser: false }
      });
      if (error) {
        report(describeSignInError(error));
        return;
      }
      requestedEmail = email;
      emailInput.readOnly = true;
      otpForm.hidden = false;
      report("A sign-in email was requested. Enter its numeric code below; do not follow a sign-in link or switch browsers. If the email contains only a link, the Supabase OTP mail template still needs configuring.");
      codeInput.focus();
    } catch {
      report(describeSignInError(null));
    }
  });

  otpForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!requestedEmail || verify.disabled || attempts >= 3) return;
    const token = String(codeInput.value || "").trim();
    if (!/^[0-9]{6,8}$/.test(token)) {
      report("Enter the 6–8 digit code from the email.");
      return;
    }
    verify.disabled = true;
    attempts += 1;
    report("Verifying the email code…");
    try {
      const { error } = await sb.auth.verifyOtp({ email: requestedEmail, token, type: "email" });
      codeInput.value = "";
      if (error) {
        report(attempts >= 3
          ? "Code verification failed. This page has reached its attempt limit; start a new connection later."
          : "Code verification failed or expired. Check the code and try again. No access was granted.");
        verify.disabled = attempts >= 3;
        return;
      }
      const verified = await sb.auth.getUser();
      if (verified.error || !verified.data?.user) {
        report("Email verification returned no authenticated session. No access was granted.");
        return;
      }
      form.hidden = true;
      otpForm.hidden = true;
      await showAuthorization(sb, authorizationId, verified.data.user);
    } catch {
      codeInput.value = "";
      report("Could not complete code verification. No access was granted.");
      verify.disabled = attempts >= 3;
    } finally {
      if (attempts < 3 && !otpForm.hidden) verify.disabled = false;
    }
  });
}
main().catch(() => report("Could not initialize authorization. No access granted."));
