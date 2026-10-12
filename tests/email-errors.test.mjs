import test from "node:test";
import assert from "node:assert/strict";
import { describeSignInError } from "../assets/auth-email-errors.mjs";

test("known error codes receive distinct actionable messages", () => {
  for (const code of ["email_address_not_authorized","over_email_send_rate_limit","over_request_rate_limit","otp_disabled","email_address_invalid","email_provider_disabled","unexpected_failure"]) {
    const text = describeSignInError({ code, status: 400 });
    assert.ok(text.includes(code));
    assert.match(text, /No account permissions were granted/);
  }
});
test("HTTP 429 gets a rate-limit explanation even without a recognized code", () => {
  assert.match(describeSignInError({ code:"unknown_server_code", status:429 }), /rate_limited/);
});
test("error strings never reveal raw secret-bearing upstream message or unknown code", () => {
  const text=describeSignInError({ code:"TOKEN=private-secret",message:"private-secret email address", status:500});
  assert.doesNotMatch(text, /private-secret|TOKEN=/);
  assert.match(text,/unclassified/);
});
test("null and malformed error values fail closed", () => {
  for (const value of [null,undefined,{},false,{code:42}])
    assert.match(describeSignInError(value), /unclassified/);
});
