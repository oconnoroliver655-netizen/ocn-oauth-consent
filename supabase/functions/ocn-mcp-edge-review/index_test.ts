// Isolated, fake verifier/consent only. No secrets, live JWT, Windows or SQL.
import { fetchReview, authorizeOwnerRequest, verifyEs256Jwt, type OwnerClaims, type OwnerVerifier } from "./index.ts";

function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
const origin = "https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review";
const resource = origin;
const issuer = "https://ouxniljtjxnrkwakkvbv.supabase.co/auth/v1";
const time = 1800000000;
const owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const client = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const session = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const claims: OwnerClaims = {
  iss: issuer, aud: resource, sub: owner, client_id: client,
  role: "authenticated", session_id: session, iat: time - 60,
  nbf: time - 60, exp: time + 300, scope: "openid email",
};
function verifier(current: OwnerClaims | null, consent = true): OwnerVerifier {
  return {
    expectedOwner: owner, expectedClient: client,
    verifyBearer: async token => token === "signed-stub" ? current : null,
    sessionActive: async () => consent,
  };
}
function rpc(method: string, params: Record<string, unknown>, authorization?: string) {
  return new Request(origin, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json, text/event-stream",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }),
  });
}

Deno.test("health endpoint exposes only harmless review status", async () => {
  const response = await fetchReview(new Request(origin + "/healthz"));
  check(response.status === 200, "health response should be 200");
  const obj = await response.json();
  check(obj.healthy === true && obj.privileged === false && obj.review_only === true,
    "review health contract");
});
Deno.test("out-of-scope routes and untrusted origins fail closed", async () => {
  const res = await fetchReview(new Request(origin + "/secrets"));
  check(res.status === 404, "unexpected route must be unavailable");
  const forged = await fetchReview(new Request("https://evil.invalid/functions/v1/ocn-mcp-edge-review"));
  check(forged.status === 404, "untrusted origin must be unavailable");
});
// Official Supabase middleware matches the metadata suffix at ANY depth.
// The review entrypoint must fence routes before middleware and never expose
// resource metadata at an unrelated path, even though metadata is public.
Deno.test("OAuth metadata suffix is inaccessible outside the exact MCP resource path", async () => {
  for (const suffix of [
    "/secrets/oauth-protected-resource",
    "/healthz/oauth-protected-resource",
    "/oauth-protected-resource/oauth-protected-resource",
  ]) {
    for (const method of ["GET", "OPTIONS"]) {
      const result = await fetchReview(new Request(origin + suffix, { method }));
      check(result.status === 404, method + " unrelated metadata suffix was accepted: " + suffix);
      check(!(await result.text()).includes("authorization_servers"),
        "metadata leaked at an unexpected route");
    }
  }
  for (const otherOrigin of [
    "http://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review",
    "https://ouxniljtjxnrkwakkvbv.supabase.co:444/functions/v1/ocn-mcp-edge-review",
  ]) {
    const result = await fetchReview(new Request(otherOrigin + "/oauth-protected-resource"));
    check(result.status === 404, "unexpected alternate origin served OAuth metadata");
  }
  const wrongMethod = await fetchReview(
    new Request(origin + "/oauth-protected-resource", { method: "POST" }));
  check(wrongMethod.status === 404,
    "non-GET/OPTIONS metadata request bypassed the exact endpoint router");
});

Deno.test("OAuth metadata remains canonical under untrusted request hints and CORS preflight", async () => {
  const url = origin + "/oauth-protected-resource?resource=https%3A%2F%2Fevil.invalid";
  const result = await fetchReview(new Request(url, {
    headers: {
      "x-forwarded-host": "evil.invalid",
      "x-forwarded-proto": "http",
      "authorization": "Bearer attacker-provided",
    },
  }));
  check(result.status === 200, "valid metadata route unavailable");
  const metadata = await result.json();
  check(metadata.resource === resource &&
    Array.isArray(metadata.authorization_servers) &&
    metadata.authorization_servers.length === 1 &&
    metadata.authorization_servers[0] === issuer,
    "untrusted request hints altered the advertised resource or issuer");
  const preflight = await fetchReview(new Request(origin + "/oauth-protected-resource", {
    method: "OPTIONS",
    headers: {
      "origin": "https://client.example.invalid",
      "access-control-request-method": "GET",
    },
  }));
  check(preflight.ok, "official middleware did not honor metadata CORS preflight");
  check(preflight.headers.has("access-control-allow-origin"),
    "metadata preflight lacks expected permissive CORS");
});

Deno.test("tool-level OAuth challenge points to the exact discoverable resource metadata", async () => {
  const result = await fetchReview(rpc("tools/call", {
    name: "owner_binding_probe", arguments: {},
  }, "Bearer attacker-provided"));
  const body = await result.text();
  check(body.includes("mcp/www_authenticate") && body.includes("resource_metadata") &&
    body.includes(resource + "/oauth-protected-resource"),
    "invalid private bearer did not advertise the canonical metadata URL");
  check(body.includes("error_description") && body.includes("invalid_token"),
    "tool-level challenge lacks actionable OAuth error and description");
  check(!body.includes("owner_verified") && !body.includes("command_id") &&
    !body.includes("service_role"),
    "private challenge leaked owner identity or privileged implementation");
});

Deno.test("MCP discovery exposes only safe canaries; private canary declares OAuth", async () => {
  const res = await fetchReview(rpc("tools/list", {}));
  check(res.ok, "MCP tools/list failed: " + res.status);
  const body = await res.text();
  check(body.includes('"ping"') && body.includes('"owner_binding_probe"'),
    "review canaries missing");
  check(body.includes('"oauth2"'), "private canary must declare OAuth");
  for (const forbidden of ["submit_windows_operation", "owner_auth_probe", "browser_connect", "file_write"]) {
    check(!body.includes(forbidden), "privileged tool leaked: " + forbidden);
  }
});
Deno.test("public MCP ping returns a protocol response without device access", async () => {
  const res = await fetchReview(rpc("tools/call", { name: "ping", arguments: {} }));
  check(res.ok, "public ping transport failed: " + res.status);
  const body = await res.text();
  check(body.includes("pong") && body.includes("true"), "public ping result missing");
  check(!body.includes("command_id"), "canary must not create Windows command IDs");
});

Deno.test("official OAuth metadata uses exact path resource and Supabase Auth issuer", async () => {
  const res = await fetchReview(new Request(origin + "/oauth-protected-resource"));
  check(res.status === 200, "protected-resource metadata missing: " + res.status);
  const obj = await res.json();
  check(obj.resource === resource, "resource mismatch");
  check(Array.isArray(obj.authorization_servers) && obj.authorization_servers.length === 1 &&
    obj.authorization_servers[0] === issuer, "issuer mismatch");
});
Deno.test("private review tool refuses both missing and fabricated bearer", async () => {
  for (const token of [undefined, "Bearer signed-stub"]) {
    const res = await fetchReview(rpc("tools/call", { name: "owner_binding_probe", arguments: {} }, token));
    const body = await res.text();
    check(body.includes("mcp/www_authenticate"), "missing MCP OAuth challenge");
    check(body.includes("invalid_token"), "missing invalid_token in challenge");
    check(!body.includes('owner_verified":true'), "owner probe improperly authorized");
    check(!body.includes("command_id"), "private probe caused a Windows dispatch");
  }
});
Deno.test("no verification dependency always denies - decoded strings are never trusted", async () => {
  check(!await authorizeOwnerRequest("Bearer signed-stub", undefined, time), "missing verifier allowed");
  check(!await authorizeOwnerRequest("Bearer signed-stub", verifier(null), time), "unsigned claims allowed");
  check(!await authorizeOwnerRequest("not-bearer", verifier(claims), time), "malformed bearer allowed");
});

Deno.test("strict verified claims require exact issuer/resource/owner/client and session consent", async () => {
  check(await authorizeOwnerRequest("Bearer signed-stub", verifier(claims), time), "valid synthetic contract denied");
  // Upstream supabase/auth PR #2894 (OPEN, not deployed) proposes
  // aud=["authenticated",resource], rather than this review hook's string.
  for (const audience of [
    ["authenticated", resource], [resource, "authenticated"],
  ]) {
    check(await authorizeOwnerRequest("Bearer signed-stub",
      verifier({ ...claims, aud: audience }), time),
      "exact dual-audience form unexpectedly rejected");
  }
  for (const [label, badAudience] of [
    ["default Supabase audience only", "authenticated"],
    ["only default in array", ["authenticated"]],
    ["only resource in array", [resource]],
    ["wrong resource in pair", ["authenticated", "https://ocn-mcp-ping-canary.onrender.com"]],
    ["extra resource", ["authenticated", resource, "https://evil.invalid"]],
    ["duplicate resource", ["authenticated", resource, resource]],
    ["two wrong resource indicators", ["https://old.invalid", "https://evil.invalid"]],
    ["empty array", []],
  ] as Array<[string, OwnerClaims["aud"]]>) {
    check(!await authorizeOwnerRequest("Bearer signed-stub",
      verifier({ ...claims, aud: badAudience }), time),
      "unexpected JWT audience authorized: " + label);
  }
  for (const [name, change] of [
    ["wrong issuer", { iss: "https://evil.invalid" }],
    ["old Render resource", { aud: "https://ocn-mcp-ping-canary.onrender.com" }],
    ["wrong owner", { sub: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
    ["wrong client", { client_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }],
    ["wrong role", { role: "anon" }],
    ["bad session", { session_id: "not-a-uuid" }],
    ["expired token", { exp: time - 45 }],
    ["future token", { iat: time + 90, exp: time + 120 }],
    ["too long token", { exp: time + 5000 }],
  ] as Array<[string, Partial<OwnerClaims>]>) {
    check(!await authorizeOwnerRequest("Bearer signed-stub", verifier({ ...claims, ...change }), time),
      "accepted " + name);
  }
  // Official Supabase OAuth access JWT examples omit the optional "scope"
  // claim. Grant scopes are enforced inside the trusted consent database RPC.
  const withoutJwtScope = { ...claims };
  delete withoutJwtScope.scope;
  check(await authorizeOwnerRequest("Bearer signed-stub", verifier(withoutJwtScope), time),
    "scope-free signed issuer/client/resource token rejected before consent RPC");
  check(!await authorizeOwnerRequest("Bearer signed-stub", verifier(claims, false), time),
    "revoked/absent consent allowed");
});


// Real WebCrypto P-256 signing fixtures. Keys are generated ephemerally
// inside this isolated test; no project key, bearer or private secret is used.
const base64url = (bytes: Uint8Array): string =>
  btoa(Array.from(bytes, b => String.fromCharCode(b)).join(""))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
const segment = (value: object) => base64url(new TextEncoder().encode(JSON.stringify(value)));
async function keyFixture() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, jwks: { keys: [{ ...jwk, kid: "test-key" }] } };
}
async function signedJwt(
  privateKey: CryptoKey, payload: object, header: object = { alg: "ES256", kid: "test-key" }
) {
  const message = segment(header) + "." + segment(payload);
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(message)));
  return message + "." + base64url(signature);
}

Deno.test("real ES256 signature verifies against trusted JWKS and exact owner binding", async () => {
  const { privateKey, jwks } = await keyFixture();
  const token = await signedJwt(privateKey, claims);
  const verified = await verifyEs256Jwt(token, jwks);
  check(verified?.aud === resource && verified?.client_id === client, "signed claims not verified");
  const signedVerifier: OwnerVerifier = {
    expectedOwner: owner, expectedClient: client,
    verifyBearer: jwt => verifyEs256Jwt(jwt, jwks),
    sessionActive: async (who, sid, app) => who === owner && sid === session && app === client,
  };
  check(await authorizeOwnerRequest("Bearer " + token, signedVerifier, time),
    "cryptographically signed, consented token should pass review contract");
  const withoutScope = { ...claims };
  delete withoutScope.scope;
  const signedWithoutScope = await signedJwt(privateKey, withoutScope);
  check(await authorizeOwnerRequest("Bearer " + signedWithoutScope, signedVerifier, time),
    "official-shaped ES256 OAuth access JWT without scope must use RPC consent");
  const noConsent = { ...signedVerifier, sessionActive: async () => false };
  check(!await authorizeOwnerRequest("Bearer " + token, noConsent, time),
    "signature must not bypass server-side revocation");
  const upstreamShape = await signedJwt(privateKey, {
    ...claims, aud: ["authenticated", resource],
  });
  const upstreamVerified = await verifyEs256Jwt(upstreamShape, jwks);
  check(Array.isArray(upstreamVerified?.aud) &&
    upstreamVerified.aud.length === 2 &&
    upstreamVerified.aud[0] === "authenticated" &&
    upstreamVerified.aud[1] === resource,
    "upstream proposed JWT audience array not cryptographically verified");
  check(await authorizeOwnerRequest("Bearer " + upstreamShape, signedVerifier, time),
    "real ES256 upstream-style audience array must be accepted after consent");
  check(!await authorizeOwnerRequest("Bearer " + upstreamShape, noConsent, time),
    "upstream-style dual-audience signed token bypassed revoked consent");
});

Deno.test("real ES256 rejects tampering, wrong key/kid, wrong algorithm and supplied key", async () => {
  const { privateKey, jwks } = await keyFixture();
  const original = await signedJwt(privateKey, claims);
  const parts = original.split(".");
  const tampered = parts[0] + "." + segment({ ...claims, aud: "https://evil.invalid" }) +
    "." + parts[2];
  check(await verifyEs256Jwt(tampered, jwks) === null, "payload tampering accepted");
  const { jwks: unrelated } = await keyFixture();
  check(await verifyEs256Jwt(original, unrelated) === null, "wrong signing key accepted");
  const changedKid = await signedJwt(privateKey, claims, { alg: "ES256", kid: "unknown-key" });
  check(await verifyEs256Jwt(changedKid, jwks) === null, "unknown key identifier accepted");
  const unsupported = await signedJwt(privateKey, claims, { alg: "HS256", kid: "test-key" });
  check(await verifyEs256Jwt(unsupported, jwks) === null, "algorithm confusion accepted");
  const injected = await signedJwt(privateKey, claims, {
    alg: "ES256", kid: "test-key", jwk: jwks.keys[0],
  });
  check(await verifyEs256Jwt(injected, jwks) === null, "token-provided JWK accepted");
  check(await verifyEs256Jwt(original, { keys: [jwks.keys[0], jwks.keys[0]] }) === null,
    "ambiguous JWKS key id accepted");
  check(await verifyEs256Jwt(parts[0] + "." + parts[1] + ".", jwks) === null,
    "missing signature accepted");
  check(await verifyEs256Jwt(original + ".extra", jwks) === null,
    "excess JWT segments accepted");
  const oldAudience = await signedJwt(privateKey, {
    ...claims, aud: "https://ocn-mcp-ping-canary.onrender.com",
  });
  const signedVerifier: OwnerVerifier = {
    expectedOwner: owner, expectedClient: client,
    verifyBearer: jwt => verifyEs256Jwt(jwt, jwks),
    sessionActive: async () => true,
  };
  check(!await authorizeOwnerRequest("Bearer " + oldAudience, signedVerifier, time),
    "validly signed OLD Render audience must not authorize Edge resource");
});
