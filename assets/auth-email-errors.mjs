// Expose only fixed, non-sensitive Auth failure categories in a public consent UI.
// Never include raw GoTrue error.message, request headers, OTPs or tokens.
const KNOWN = Object.freeze({
  email_address_not_authorized: "Supabase blocked delivery to this recipient. Review the project's SMTP configuration and organization membership.",
  over_email_send_rate_limit: "Supabase has limited email sends. Do not retry now; wait for the email quota to reset or configure an approved SMTP provider.",
  over_request_rate_limit: "Too many authentication requests. Stop retrying and let the request limit reset.",
  otp_disabled: "Email one-time link sign-in is disabled in Supabase Auth configuration.",
  email_address_invalid: "Supabase rejected the email address. Review the approved owner email in project configuration.",
  email_provider_disabled: "Email sign-in is not enabled in Supabase Auth configuration.",
  unexpected_failure: "Supabase could not complete the email delivery. The project administrator must check Auth logs and SMTP."
});
export function describeSignInError(error) {
  const code = typeof error?.code === "string" ? error.code : "";
  if (Object.prototype.hasOwnProperty.call(KNOWN, code))
    return "Sign-in failed (" + code + "). " + KNOWN[code] + " No account permissions were granted.";
  if (error?.status === 429)
    return "Sign-in failed (rate_limited). Supabase is rate-limiting this request. Stop retrying until the limit resets. No account permissions were granted.";
  return "Sign-in request failed (unclassified). Do not repeatedly retry. The project administrator should inspect Supabase Auth logs and email settings. No account permissions were granted.";
}
