// Review-only WebCrypto and trusted fetch mocks. No real bearer, service key,
// outbound network, Supabase SQL, Windows tool, or production deployment.
import { authorizeOwnerRequest } from "./index.ts";
import { createReviewServerVerifier, REVIEW_ORIGIN, REVIEW_RESOURCE } from "./trusted-verifier.ts";
function check(value: unknown, explanation: string): asserts value {
  if (!value) throw new Error(explanation);
}
const owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const client = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const session = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const now = 1800000000;
const claims = {
  iss: REVIEW_ORIGIN + "/auth/v1", aud: REVIEW_RESOURCE,
  sub: owner, client_id: client, role: "authenticated",
  session_id: session, iat: now - 60, exp: now + 300,
  scope: "openid email",
};
const fakeServiceKey = "local-unit-test-key-never-used-in-production";
const b64url = (bytes: Uint8Array) =>
  btoa(Array.from(bytes, c => String.fromCharCode(c)).join(""))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
const jsonPart = (obj: object) => b64url(new TextEncoder().encode(JSON.stringify(obj)));
async function signedFixture(payload: object = claims) {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  const signed = jsonPart({ alg: "ES256", kid: "fixture-1" }) + "." + jsonPart(payload);
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, keys.privateKey, new TextEncoder().encode(signed)));
  return {
    token: signed + "." + b64url(signature),
    jwks: { keys: [{ ...publicJwk, kid: "fixture-1" }] },
  };
}
function stubFetch(jwks: unknown, options?: {
  consent?: boolean; jwksStatus?: number; oversize?: boolean; reject?: boolean;
}) {
  const requests: Array<{ url: string; method: string; headers: Headers; body: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input), headers = new Headers(init?.headers);
    requests.push({ url, method: init?.method || "GET", headers, body: String(init?.body || "") });
    if (options?.reject) throw new Error("Simulated upstream outage");
    check(init?.redirect === "error", "redirects must be disabled");
    check(init?.signal !== undefined, "requests must have an explicit timeout");
    if (url === REVIEW_ORIGIN + "/auth/v1/.well-known/jwks.json") {
      check(init?.method === "GET", "JWKS must use GET");
      check(!headers.has("authorization") && !headers.has("apikey"), "secrets sent to JWKS!");
      if (options?.oversize) {
        return new Response("x".repeat(16_385), {
          headers: { "content-type": "application/json" },
        });
      }
      return Response.json(jwks, { status: options?.jwksStatus ?? 200 });
    }
    if (url === REVIEW_ORIGIN + "/rest/v1/rpc/ocn_owner_oauth_session_active") {
      check(init?.method === "POST", "consent RPC must use POST");
      check(headers.get("apikey") === fakeServiceKey &&
        headers.get("authorization") === "Bearer " + fakeServiceKey, "missing server-only credential");
      const p = JSON.parse(String(init?.body));
      check(p.p_owner === owner && p.p_client === client && p.p_session === session,
        "wrong owner/client/session passed to RPC");
      return Response.json(options?.consent !== false);
    }
    throw new Error("Unexpected outbound endpoint: " + url);
  };
  return { requests, fetchImpl };
}
function adapter(fetchImpl: typeof fetch, binding: (resource: string) => Promise<boolean>) {
  return createReviewServerVerifier({
    expectedOwner: owner, expectedClient: client, serviceRoleKey: fakeServiceKey,
    resourceBindingActive: binding,
    fetchImpl,
  });
}

Deno.test("trusted fixed JWKS + real ES256 + bound session RPC verify, without device calls", async () => {
  const fixture = await signedFixture();
  const mock = stubFetch(fixture.jwks);
  let bindingCalls = 0;
  const verifier = adapter(mock.fetchImpl, async resource => {
    bindingCalls++;
    return resource === REVIEW_RESOURCE;
  });
  check(await authorizeOwnerRequest("Bearer " + fixture.token, verifier, now), "valid signed owner denied");
  check(bindingCalls === 1, "new resource binding not checked");
  check(mock.requests.length === 2, "expected only JWKS and session read");
});

Deno.test("old Render binding or revoked consent prevents authorization", async () => {
  const fixture = await signedFixture();
  const refused = stubFetch(fixture.jwks);
  const falseBinding = adapter(refused.fetchImpl, async () => false);
  check(!await authorizeOwnerRequest("Bearer " + fixture.token, falseBinding, now),
    "old-only binding accepted");
  check(refused.requests.length === 1, "consent RPC called despite absent new-resource binding");
  const revoked = stubFetch(fixture.jwks, { consent: false });
  const verified = adapter(revoked.fetchImpl, async resource => resource === REVIEW_RESOURCE);
  check(!await authorizeOwnerRequest("Bearer " + fixture.token, verified, now),
    "revoked consent accepted");
  check(revoked.requests.length === 2, "revocation RPC missing");
});

Deno.test("bad JWKS, unsupported response, oversize and upstream failure fail closed", async () => {
  const fixture = await signedFixture();
  for (const [label, opts, jwks] of [
    ["wrong JWKS", {}, { keys: [] }],
    ["HTTP 500", { jwksStatus: 500 }, fixture.jwks],
    ["oversize response", { oversize: true }, fixture.jwks],
    ["offline JWKS", { reject: true }, fixture.jwks],
  ] as Array<[string, Parameters<typeof stubFetch>[1], unknown]>) {
    const mock = stubFetch(jwks, opts);
    let bindingCalled = false;
    const verifier = adapter(mock.fetchImpl, async () => { bindingCalled = true; return true; });
    check(!await authorizeOwnerRequest("Bearer " + fixture.token, verifier, now),
      "fail open: " + label);
    check(!bindingCalled && mock.requests.length === 1, "consent reached after JWKS failure: " + label);
  }
});

Deno.test("no valid server-side identity, bad audience and denied resource callback fail closed", async () => {
  const fixture = await signedFixture();
  const mock = stubFetch(fixture.jwks);
  for (const bad of [
    { ...claims, aud: "https://ocn-mcp-ping-canary.onrender.com" },
    { ...claims, client_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
    { ...claims, sub: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" },
  ]) {
    const badFixture = await signedFixture(bad);
    const badMock = stubFetch(badFixture.jwks);
    check(!await authorizeOwnerRequest("Bearer " + badFixture.token,
      adapter(badMock.fetchImpl, async () => true), now), "invalid identity accepted");
    check(badMock.requests.length === 1, "private RPC called after wrong identity");
  }
  const refuseBinding = adapter(mock.fetchImpl, async () => { throw new Error("binding RPC offline"); });
  check(!await authorizeOwnerRequest("Bearer " + fixture.token, refuseBinding, now),
    "offline binding check accepted");
});

Deno.test("review adapter rejects missing server credentials and malformed owner", () => {
  const mock = stubFetch({ keys: [] });
  for (const cfg of [
    { expectedOwner: "bad-id", expectedClient: client, serviceRoleKey: fakeServiceKey },
    { expectedOwner: owner, expectedClient: client, serviceRoleKey: "" },
  ]) {
    let rejected = false;
    try {
      createReviewServerVerifier({
        ...cfg, resourceBindingActive: async () => true, fetchImpl: mock.fetchImpl,
      });
    } catch {
      rejected = true;
    }
    check(rejected, "missing owner binding or service key accepted");
  }
});
