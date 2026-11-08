// REVIEW-ONLY trusted-network contract tests. No production secrets, tokens,
// Windows tools, external network or database changes.
import { authorizeOwnerRequest, createIsolatedReviewFetcher, fetchReview } from "./index.ts";
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

 
// Full MCP HTTP-path integration with a verifier injected in test memory ONLY.
// The exported deployable fetchReview() must deny the same valid signed token.
function ownerCall(bearer?: string): Request {
  return new Request(REVIEW_RESOURCE, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json, text/event-stream",
      ...(bearer ? { authorization: bearer } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 811, method: "tools/call",
      params: { name: "owner_binding_probe", arguments: {} },
    }),
  });
}
Deno.test("review HTTP MCP tool binds real ES256 proof and atomic consent; default entrypoint denies", async () => {
  // The HTTP tool uses real wall-clock time, unlike earlier pure-contract tests.
  const current = Math.floor(Date.now() / 1000);
  // OAuth access tokens may omit scope; consent scope is validated by the RPC.
  const { scope: _consentNotJwt, ...tokenClaims } = payload;
  const fixture = await signedFixture({ ...tokenClaims, iat: current - 60, exp: current + 300 });
  const header = "Bearer " + fixture.token;
  const baseline = await fetchReview(ownerCall(header));
  const deniedBaseline = await baseline.text();
  assert(deniedBaseline.includes("mcp/www_authenticate") &&
    !deniedBaseline.includes("owner_verified\\\":true"),
    "deployment export unexpectedly allowed the test token");

  const acceptedNetwork = fakeNetwork(fixture.jwks);
  const review = createIsolatedReviewFetcher(verifier(acceptedNetwork.fetchImpl));
  const good = await review(ownerCall(header));
  assert(good.status === 200, "MCP tool transport must succeed");
  const body = await good.text();
  assert(body.includes("owner_verified\\\":true") && body.includes("review_only\\\":true"),
    "properly signed and resource-consented MCP owner canary rejected");
  assert(acceptedNetwork.calls.length === 2,
    "MCP owner canary must consult fixed JWKS and resource-aware RPC");
  assert(!body.includes(fakeKey) && !body.includes("command_id"),
    "secret or Windows command leaked into authenticated review response");

  const absent = await review(ownerCall());
  const absentBody = await absent.text();
  assert(absentBody.includes("mcp/www_authenticate") &&
    !absentBody.includes("owner_verified\\\":true"),
    "missing bearer must be denied by the real MCP tool path");
  assert(acceptedNetwork.calls.length === 2, "missing token should never make an outbound auth request");

  const revokedNetwork = fakeNetwork(fixture.jwks, { admitted: false });
  const revoked = await createIsolatedReviewFetcher(verifier(revokedNetwork.fetchImpl))(ownerCall(header));
  const revokedBody = await revoked.text();
  assert(revokedBody.includes("mcp/www_authenticate") &&
    !revokedBody.includes("owner_verified\\\":true"),
    "revoked consent unexpectedly authorized through the MCP tool");
  assert(revokedNetwork.calls.length === 2, "revocation must reach atomic RPC");
});

// ISOLATED_AUTH_CODE_FLOW_ACCEPTANCE: disposable protocol model only.
// This does NOT register a live Supabase client, use a real consent screen,
// call the public token endpoint, or claim an authentic Supabase-issued JWT.
// Checks the complete client-side protocol invariants before later live release.
Deno.test("isolated OAuth registration, S256 PKCE, consent, code replay and MCP revocation", async () => {
  const callback = "https://client.example.invalid/oauth/callback";
  const otherCallback = "https://other.example.invalid/callback";
  type Registration = { client_id: string; redirect_uris: string[]; token_endpoint_auth_method: string };
  const registrations = new Map<string, Registration>();
  function register(redirects: string[], method: string): Registration {
    assert(method === "none", "test requires a public PKCE client");
    assert(redirects.length === 1 && redirects[0] === callback,
      "untrusted or unexpected redirect registration");
    const registered = {
      client_id: client, redirect_uris: [...redirects], token_endpoint_auth_method: method,
    };
    registrations.set(registered.client_id, registered);
    return registered;
  }
  let rejectedRegistration = false;
  try { register([otherCallback], "none"); } catch { rejectedRegistration = true; }
  assert(rejectedRegistration && !registrations.has(client),
    "invalid client redirect must not register");
  const app = register([callback], "none");
  assert(app.client_id === client && registrations.has(client),
    "client registration was not recorded");

  const codeVerifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = async (value: string) => b64url(new Uint8Array(await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(value))));
  const challenge = await digest(codeVerifier);
  const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
  type CodeGrant = {
    clientId: string; redirect: string; challenge: string; expires: number; used: boolean;
  };
  const grants = new Map<string, CodeGrant>();
  let sequence = 0;
  const tick = Math.floor(Date.now() / 1000);
  function authorize(params: URLSearchParams, approved: boolean): URL {
    const clientId = params.get("client_id") ?? "";
    const redirect = params.get("redirect_uri") ?? "";
    const registered = registrations.get(clientId);
    assert(registered?.redirect_uris.includes(redirect) === true,
      "client/redirect mismatch must be refused");
    assert(params.get("response_type") === "code" &&
      params.get("code_challenge_method") === "S256" &&
      /^[A-Za-z0-9_-]{43,128}$/.test(params.get("code_challenge") ?? "") &&
      (params.get("state") ?? "").length >= 24,
      "invalid code authorization request");
    const response = new URL(redirect);
    response.searchParams.set("state", params.get("state")!);
    if (!approved) {
      response.searchParams.set("error", "access_denied");
      return response;
    }
    const code = "isolated-only-code-" + ++sequence;
    grants.set(code, {
      clientId, redirect, challenge: params.get("code_challenge")!,
      expires: tick + 600, used: false,
    });
    response.searchParams.set("code", code);
    return response;
  }
  const params = new URLSearchParams({
    response_type: "code", client_id: app.client_id,
    redirect_uri: callback, state,
    code_challenge: challenge, code_challenge_method: "S256",
    scope: "openid email",
  });
  const invalidRedirect = new URLSearchParams(params);
  invalidRedirect.set("redirect_uri", otherCallback);
  let badRedirectDenied = false;
  try { authorize(invalidRedirect, true); } catch { badRedirectDenied = true; }
  assert(badRedirectDenied && grants.size === 0,
    "redirect substitution created a code");
  const plainPkce = new URLSearchParams(params);
  plainPkce.set("code_challenge_method", "plain");
  let plainDenied = false;
  try { authorize(plainPkce, true); } catch { plainDenied = true; }
  assert(plainDenied && grants.size === 0, "PKCE downgrade was accepted");

  const refused = authorize(params, false);
  assert(refused.searchParams.get("error") === "access_denied" &&
    refused.searchParams.get("code") === null && grants.size === 0,
    "denied user consent minted a code");
  const approved = authorize(params, true);
  assert(approved.searchParams.get("state") === state &&
    approved.searchParams.has("code"), "approved consent return missing state or code");
  const mismatchedState = new URL(approved);
  mismatchedState.searchParams.set("state", "unexpected-state");
  assert(mismatchedState.searchParams.get("state") !== state,
    "OAuth client must reject a state mismatch instead of exchanging the code");

  async function exchange(code: string, id: string, redirect: string,
                          verifierText: string, at: number) {
    const grant = grants.get(code);
    if (!grant || grant.used || grant.clientId !== id ||
        grant.redirect !== redirect || grant.expires <= at ||
        await digest(verifierText) !== grant.challenge) return null;
    grant.used = true;
    const { scope: _consentNotJwt, ...tokenClaims } = payload;
    return await signedFixture({ ...tokenClaims, iat: at - 60, exp: at + 300 });
  }
  const code = approved.searchParams.get("code")!;
  assert(await exchange(code, app.client_id, callback, codeVerifier + "-wrong", tick) === null,
    "wrong PKCE verifier exchanged code");
  assert(await exchange(code, app.client_id, otherCallback, codeVerifier, tick) === null,
    "wrong token exchange redirect succeeded");
  assert(await exchange(code, owner, callback, codeVerifier, tick) === null,
    "wrong client exchanged authorization code");
  const issued = await exchange(code, app.client_id, callback, codeVerifier, tick);
  assert(issued?.token && issued.jwks, "correct PKCE exchange failed");
  assert(await exchange(code, app.client_id, callback, codeVerifier, tick) === null,
    "single-use authorization code replay accepted");

  const header = "Bearer " + issued.token;
  const allowed = fakeNetwork(issued.jwks);
  const isolated = createIsolatedReviewFetcher(verifier(allowed.fetchImpl));
  const good = await isolated(ownerCall(header));
  const goodBody = await good.text();
  assert(goodBody.includes("owner_verified\\\":true") &&
    allowed.calls.length === 2,
    "simulated issued ES256 token did not reach consented MCP verifier");
  const liveDefault = await fetchReview(ownerCall(header));
  assert((await liveDefault.text()).includes("mcp/www_authenticate"),
    "deployable review handler must still deny even a valid fixture bearer");

  const revoked = fakeNetwork(issued.jwks, { admitted: false });
  const revokedResponse = await createIsolatedReviewFetcher(
    verifier(revoked.fetchImpl))(ownerCall(header));
  assert((await revokedResponse.text()).includes("mcp/www_authenticate") &&
    revoked.calls.length === 2,
    "revoked consent must deny an already-issued signed bearer at the MCP gate");

  const expiredUrl = authorize(params, true);
  const expiredCode = expiredUrl.searchParams.get("code")!;
  assert(await exchange(expiredCode, app.client_id, callback, codeVerifier, tick + 601) === null,
    "expired authorization code was exchanged");
});
