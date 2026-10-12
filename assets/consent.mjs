import { createClient } from "https://esm.sh/@supabase/supabase-js@2.117.3?bundle";
import { CONFIG } from "./config.mjs";
import { isConfigured, getAuthorizationId, isOwner, authorizeDetails, matchingCallback, returnToConsent } from "./guards.mjs";
import { describeSignInError } from "./auth-email-errors.mjs";

const status = document.getElementById("status");
const form = document.getElementById("signin");
const review = document.getElementById("review");
const previous = document.getElementById("previous");
const allow = document.getElementById("approve");
const deny = document.getElementById("deny");
const check = document.getElementById("checked");

function report(message) { status.textContent = message; }
function redirectToVerifiedClient(value) {
  if (!matchingCallback(value, CONFIG.approvedRedirectUri, true)) {
    report("Blocked: returned callback did not match the registered OAuth client.");
    return;
  }
  window.location.assign(value);
}

async function main() {
  // Never create a Supabase client or send credentials with incomplete config.
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
    auth: { flowType: "pkce", detectSessionInUrl: true, persistSession: true, autoRefreshToken: true }
  });
  const identity = await sb.auth.getUser();
  if (!identity?.data?.user || identity.error) {
    form.hidden = false;
    report("Sign in using the account registered as the owner.");
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const email = String(document.getElementById("email").value || "").trim();
      if (!email || email.length > 254) return;
      const send = document.getElementById("send");
      send.disabled = true;
      report("Requesting a sign-in link…");
      try {
        const redirect = returnToConsent(window.location.href, authorizationId);
        const { error } = await sb.auth.signInWithOtp({
          email,
          options: { shouldCreateUser: false, emailRedirectTo: redirect }
        });
        report(error
          ? describeSignInError(error)
          : "A sign-in email was requested. Check the registered inbox and open the link in this browser. Avoid repeated requests.");
      } catch {
        report(describeSignInError(null));
      }
      // Intentionally keep this button disabled after one request per loaded page.
      // Repeated taps exhaust the project's extremely limited email quota.
    });
    return;
  }
  if (!isOwner(identity.data.user, CONFIG)) {
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
    report("OAuth request is expired, invalid, or unavailable.");
    return;
  }
  const details = result.data;
  if (!Object.hasOwn(details, "authorization_id")) {
    if (!matchingCallback(details.redirect_url, CONFIG.approvedRedirectUri, true)) {
      report("Previously granted authorization has an unexpected callback. Access denied.");
      return;
    }
    report("Supabase reports prior consent for this callback.");
    previous.hidden = false;
    document.getElementById("continue").addEventListener("click", () =>
      redirectToVerifiedClient(details.redirect_url), { once: true });
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
      // Supabase OAuth methods redirect by default in browsers. We must
      // explicitly disable that behavior to check the callback first.
      const answer = action === "allow"
        ? await sb.auth.oauth.approveAuthorization(authorizationId, { skipBrowserRedirect: true })
        : await sb.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
      if (answer.error || !answer.data?.redirect_url) {
        report("Consent decision failed. No redirect performed.");
        return;
      }
      redirectToVerifiedClient(answer.data.redirect_url);
    } catch { report("Consent service unavailable. No redirect performed."); }
    finally {
      pending = false;
      deny.disabled = false;
      allow.disabled = !check.checked;
    }
  }
  allow.addEventListener("click", () => decide("allow"));
  deny.addEventListener("click", () => decide("deny"));
}
main().catch(() => report("Could not initialize authorization. No access granted."));
