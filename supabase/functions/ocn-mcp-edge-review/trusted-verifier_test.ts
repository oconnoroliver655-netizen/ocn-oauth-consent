// REVIEW-ONLY trusted-network contract tests. No production secrets, tokens,
// Windows tools, external network or database changes.
import { authorizeOwnerRequest } from "./index.ts";
import { createReviewServerVerifier, REVIEW_ORIGIN, REVIEW_RESOURCE } from "./trusted-verifier.ts";
function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
const owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const client = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const session = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const now = 1800000000;
const payload = {
  iss: REVIEW_ORIGIN + "/auth/v1", aud: REVIEW_RESOURCE,
  sub: owner, client_id: client, role: "authenticated",
  session_id: session, iat: now - 60, exp: now + 300, scope: "openid email",
};
const fakeKey = "fixture-only-service-role-key-not-production";
const b64url = (bytes: Uint8Array) =>
  btoa(Array.from(bytes, x => String.fromCharCode(x)).join(""))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
const segment = (obj: object) => b64url(new TextEncoder().encode(JSON.stringify(obj)));
async function signedFixture(claims: object = payload) {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const toSign = segment({ alg: "ES256", kid: "fixture-key" }) + "." + segment(claims);
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, pair.privateKey,
    new TextEncoder().encode(toSign)));
  return { token: toSign + "." + b64url(sig), jwks: { keys: [{ ...pub, kid: "fixture-key" }] } };
}
interface MockOptions {
  admitted?: boolean;
  jwksStatus?: number;
  rpcStatus?: number;
  oversized?: boolean;
  offline?: "jwks" | "rpc";
  badRpcJson?: boolean;
}
function fakeNetwork(jwks: unknown, options: MockOptions = {}) {
  const calls: Array<{ url: string; method: string; body: string }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = String(init?.body ?? "");
    calls.push({ url, method, body });
    assert(init?.redirect === "error", "redirects must be forbidden");
    assert(init?.cache === "no-store", "cache must be disabled");
    assert(init?.signal, "bounded timeout required");
    if (url === REVIEW_ORIGIN + "/auth/v1/.well-known/jwks.json") {
      assert(method === "GET", "JWKS must use GET");
      assert(!headers.has("apikey") && !headers.has("authorization"),
        "server secret leaked to public JWKS");
      if (options.offline === "jwks") throw new Error("Offline JWKS");
      if (options.oversized)
        return new Response("x".repeat(16_385), {
          headers: { "content-type": "application/json" },
        });
      return Response.json(jwks, { status: options.jwksStatus ?? 200 });
    }
    if (url === REVIEW_ORIGIN +
      "/rest/v1/rpc/ocn_owner_oauth_resource_session_active") {
      assert(method === "POST", "server RPC requires POST");
      assert(headers.get("apikey") === fakeKey &&
        headers.get("authorization") === "Bearer " + fakeKey,
        "missing server-only RPC credential");
      assert(headers.get("content-type") === "application/json",
        "RPC must send JSON");
      const args = JSON.parse(body);
      assert(Object.keys(args).sort().join() ===
        ["p_client", "p_owner", "p_resource", "p_session"].join(),
        "unexpected RPC parameters");
      assert(args.p_owner === owner && args.p_client === client &&
        args.p_session === session && args.p_resource === REVIEW_RESOURCE,
        "incorrect owner/client/session/resource sent to RPC");
      if (options.offline === "rpc") throw new Error("Offline RPC");
      if (options.badRpcJson)
        return Response.json({ authorized: true });
      return Response.json(options.admitted !== false, { status: options.rpcStatus ?? 200 });
    }
    throw new Error("Unexpected outbound request: " + url);
  };
  return { fetchImpl, calls };
}
function verifier(fetchImpl: typeof fetch, serviceKey = fakeKey) {
  return createReviewServerVerifier({
    expectedOwner: owner, expectedClient: client, serviceRoleKey: serviceKey, fetchImpl,
  });
}

Deno.test("real ES256 plus fixed JWKS and atomic four-field RPC verifies an Edge session", async () => {
  const fixture = await signedFixture();
  const network = fakeNetwork(fixture.jwks);
  assert(await authorizeOwnerRequest("Bearer " + fixture.token,
    verifier(network.fetchImpl), now), "signed resource-bound session wrongly rejected");
  assert(network.calls.length === 2, "expected exactly JWKS and atomic authorization RPC");
});

Deno.test("server rejects disabled binding / revoked consent / absent session via false RPC", async () => {
  const fixture = await signedFixture();
  const network = fakeNetwork(fixture.jwks, { admitted: false });
  assert(!await authorizeOwnerRequest("Bearer " + fixture.token,
    verifier(network.fetchImpl), now), "false RPC was accepted");
  assert(network.calls.length === 2, "missing atomic resource/consent RPC");
});

Deno.test("untrusted JWKS, HTTP failure, oversize and offline JWKS fail closed", async () => {
  const fixture = await signedFixture();
  const matrix: Array<[string, unknown, MockOptions]> = [
    ["no signing key", { keys: [] }, {}],
    ["HTTP failure", fixture.jwks, { jwksStatus: 500 }],
    ["oversized stream", fixture.jwks, { oversized: true }],
    ["upstream network error", fixture.jwks, { offline: "jwks" }],
  ];
  for (const [label, keys, opts] of matrix) {
    const network = fakeNetwork(keys, opts);
    assert(!await authorizeOwnerRequest("Bearer " + fixture.token,
      verifier(network.fetchImpl), now), label + " failed open");
    assert(network.calls.length === 1, label + " reached private RPC after JWKS failure");
  }
});

Deno.test("wrong signed owner, client, audience, session and expiry fail before RPC", async () => {
  const invalid = [
    { ...payload, aud: "https://ocn-mcp-ping-canary.onrender.com" },
    { ...payload, sub: "ffffffff-ffff-4fff-8fff-ffffffffffff" },
    { ...payload, client_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
    { ...payload, session_id: "not-a-uuid" },
    { ...payload, exp: now - 120 },
  ];
  for (const claims of invalid) {
    const fixture = await signedFixture(claims);
    const network = fakeNetwork(fixture.jwks);
    assert(!await authorizeOwnerRequest("Bearer " + fixture.token,
      verifier(network.fetchImpl), now), "invalid identity authorized");
    assert(network.calls.length === 1, "wrong identity reached resource/session RPC");
  }
});

Deno.test("RPC offline, non-boolean data and HTTP error fail closed", async () => {
  const fixture = await signedFixture();
  for (const opts of [
    { offline: "rpc" as const }, { badRpcJson: true }, { rpcStatus: 403 },
  ]) {
    const network = fakeNetwork(fixture.jwks, opts);
    assert(!await authorizeOwnerRequest("Bearer " + fixture.token,
      verifier(network.fetchImpl), now), "untrusted RPC result accepted");
    assert(network.calls.length === 2, "RPC path was not exercised");
  }
});

Deno.test("bad server owner/client or missing service key are refused", () => {
  const network = fakeNetwork({ keys: [] });
  for (const config of [
    { expectedOwner: "bad-id", expectedClient: client, serviceRoleKey: fakeKey },
    { expectedOwner: owner, expectedClient: "bad-id", serviceRoleKey: fakeKey },
    { expectedOwner: owner, expectedClient: client, serviceRoleKey: "" },
  ]) {
    let failed = false;
    try {
      createReviewServerVerifier({ ...config, fetchImpl: network.fetchImpl });
    } catch {
      failed = true;
    }
    assert(failed, "bad review server configuration unexpectedly accepted");
  }
});
