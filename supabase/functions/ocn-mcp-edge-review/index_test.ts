// Isolated, fake verifier/consent only. No secrets, live JWT, Windows or SQL.
import { fetchReview, authorizeOwnerRequest, type OwnerClaims, type OwnerVerifier } from "./index.ts";

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
    ["missing openid scope", { scope: "email" }],
  ] as Array<[string, Partial<OwnerClaims>]>) {
    check(!await authorizeOwnerRequest("Bearer signed-stub", verifier({ ...claims, ...change }), time),
      "accepted " + name);
  }
  check(!await authorizeOwnerRequest("Bearer signed-stub", verifier(claims, false), time),
    "revoked/absent consent allowed");
});
