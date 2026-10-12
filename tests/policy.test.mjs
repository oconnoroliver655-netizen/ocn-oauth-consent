import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  isConfigured, getAuthorizationId, matchingCallback, isOwner,
  authorizeDetails, returnToConsent
} from "../assets/guards.mjs";

const ID = "f".repeat(32);
const C = {
  supabaseUrl: "https://ouxniljtjxnrkwakkvbv.supabase.co",
  publishableKey: "sb_publishable_testingExample123",
  ownerUserId: "11111111-2222-4333-8444-555555555555",
  approvedOAuthClientId: "registered-test-app",
  approvedRedirectUri: "https://chatgpt.com/connector/oauth/callback"
};
const DETAILS = {
  authorization_id: ID,
  user: {id:C.ownerUserId},
  client: {id:C.approvedOAuthClientId, name:"Verified test client"},
  redirect_uri:C.approvedRedirectUri, scope:"openid email"
};

test("site is disabled until all exact owner-controlled settings exist", () => {
  assert.equal(isConfigured(C), true);
  for (const field of ["publishableKey","ownerUserId","approvedOAuthClientId","approvedRedirectUri"]) {
    assert.equal(isConfigured({...C,[field]:"PENDING"}),false, field);
  }
  assert.equal(isConfigured({...C,supabaseUrl:"https://attacker.supabase.co"}),false);
  assert.equal(isConfigured({...C,publishableKey:"sb_secret_danger"}),false);
  assert.equal(isConfigured({...C,approvedRedirectUri:"http://localhost:1234"}),false);
});

test("authorization_id must be singular, opaque and isolated from untrusted parameters", () => {
  assert.equal(getAuthorizationId("?authorization_id="+ID),ID);
  assert.equal(getAuthorizationId("?authorization_id="+ID+"&code=pkce-test-code"),ID);
  assert.equal(getAuthorizationId("?authorization_id="+ID+"&error=access_denied"),ID);
  for (const q of ["","?authorization_id=x","?authorization_id="+ID+"&authorization_id="+ID,
    "?authorization_id="+ID+"&redirect_uri=https://evil.example","?authorization_id=%3Cscript%3E"])
    assert.equal(getAuthorizationId(q),null,q);
});

test("real owner UUID is mandatory even when an OAuth client matches", () => {
  assert.equal(isOwner({id:C.ownerUserId},C),true);
  assert.equal(isOwner({id:"other"},C),false);
  assert.equal(isOwner(null,C),false);
  assert.equal(isOwner({id:C.ownerUserId},{...C,ownerUserId:"PENDING"}),false);
});

test("authorization approval requires matching owner, app, callback and ID", () => {
  assert.equal(authorizeDetails(DETAILS,ID,C),true);
  const bad=[
    {...DETAILS,user:{id:"different-user"}},
    {...DETAILS,client:{id:"other-app"}},
    {...DETAILS,redirect_uri:"https://evil.example/oauth"},
    {...DETAILS,authorization_id:"mismatch"},
    {...DETAILS,redirect_uri:C.approvedRedirectUri+"?state=evil"},
    {authorization_id:ID}
  ];
  for(const item of bad) assert.equal(authorizeDetails(item,ID,C),false);
});

test("returned redirects may add OAuth protocol parameters but never change target", () => {
  for (const suffix of ["","?state=random&code=abc","?error=access_denied&state=s","?iss=https%3A%2F%2Fexample.org"])
    assert.equal(matchingCallback(C.approvedRedirectUri+suffix,C.approvedRedirectUri,true),true);
  for(const url of [
    "https://chatgpt.com.evil.example/connector/oauth/callback",
    "https://evil.example/connector/oauth/callback",
    "https://chatgpt.com/connector/oauth/callback/subpath",
    "http://chatgpt.com/connector/oauth/callback",
    "javascript:alert(1)",C.approvedRedirectUri+"?next=https://evil.example",
    C.approvedRedirectUri+"#fragment","https://user:pass@chatgpt.com/connector/oauth/callback"
  ]) assert.equal(matchingCallback(url,C.approvedRedirectUri,true),false,url);
});

test("consent URL survives passwordless email sign-in without leaking fragments", () => {
  const url = returnToConsent("https://example.github.io/oauth/consent/?foo=1#secret",ID);
  assert.equal(url,"https://example.github.io/oauth/consent/?authorization_id="+ID);
  assert.throws(()=>returnToConsent("http://example.com/",ID));
  assert.throws(()=>returnToConsent("https://example.com/","bad"));
});

test("public config pins only verified owner UUID and leaves OAuth client disabled", () => {
  const conf=readFileSync(new URL("../assets/config.mjs",import.meta.url),"utf8");
  assert.match(conf,/ownerUserId:\s*"[0-9a-f-]{36}"/i);
  assert.doesNotMatch(conf,/PENDING_VERIFIED_OWNER_UUID/);
  assert.match(conf,/PENDING_APPROVED_CLIENT_ID/);
  assert.match(conf,/PENDING_REGISTERED_CALLBACK_HTTPS_URL/);
  assert.doesNotMatch(conf,/sb_secret_|service_role|sk_[A-Za-z0-9]{16,}/);
});

test("browser decision path has explicit user choice and no default auto-redirect", () => {
  const js=readFileSync(new URL("../assets/consent.mjs",import.meta.url),"utf8");
  assert.match(js,/approveAuthorization\(authorizationId, \{ skipBrowserRedirect: true \}\)/);
  assert.match(js,/denyAuthorization\(authorizationId, \{ skipBrowserRedirect: true \}\)/);
  assert.match(js,/check\.checked/);
  assert.match(js,/shouldCreateUser: false/);
  assert.match(js,/identity\.data\.user/);
  assert.match(js,/matchingCallback\(value, CONFIG\.approvedRedirectUri/);
  assert.doesNotMatch(js,/innerHTML\s*=|eval\(|document\.write\(/);
});

test("consent HTML exposes no credentials or unsolicited network forms", () => {
  const html=readFileSync(new URL("../oauth/consent/index.html",import.meta.url),"utf8");
  assert.match(html,/Content-Security-Policy/);
  assert.match(html,/referrer" content="no-referrer"/);
  assert.doesNotMatch(html,/Runtime API Key:|service_role|sb_secret_|password type="text"/);
});
