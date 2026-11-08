// REVIEW ONLY, NOT DEPLOYED: Supabase Edge MCP OAuth resource compatibility.
// No real owner verifier, user session, device access, dispatch, or model trigger.
// Resource metadata is provided by the official Supabase middleware, not a
// handwritten discovery endpoint. The private canary intentionally FAILS CLOSED.
import { createMcpHandler, McpServer } from "npm:@modelcontextprotocol/server@2.0.0";
import { pipeline } from "npm:@supabase/middleware@1.0.0";
import { withOAuthProtectedResource } from "npm:@supabase/server@1.6.0";
import { z } from "npm:zod@4.3.6";

const ORIGIN = "https://ouxniljtjxnrkwakkvbv.supabase.co";
const FUNCTION_PATH = "/functions/v1/ocn-mcp-edge-review";
const RESOURCE = ORIGIN + FUNCTION_PATH;
const ISSUER = ORIGIN + "/auth/v1";
const SESSION = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER_CHALLENGE =
  'Bearer resource_metadata="' + RESOURCE +
  '/oauth-protected-resource", error="invalid_token", error_description="Verified owner OAuth session required"';

// Contract for the next, separately-reviewed integration with the existing
// signed ES256 validator and revocation/consent RPC. Never accept a decoded
// JWT payload as verified. Only verifyBearer may supply authenticated claims.
export interface OwnerClaims {
  iss: string;
  aud: string;
  sub: string;
  client_id: string;
  role: string;
  session_id: string;
  iat: number;
  nbf?: number;
  exp: number;
  scope?: string;
}
export interface OwnerVerifier {
  expectedOwner: string;
  expectedClient: string;
  verifyBearer: (token: string) => Promise<OwnerClaims | null>;
  sessionActive: (owner: string, session: string, client: string) => Promise<boolean>;
}
// Crypto-only verification primitive derived from the existing production
// validator policy. The JWKS must be supplied by a trusted server-side source;
// NEVER fetch jwks_uri/jwk/x5u/jku from an untrusted JWT header.
// Returning claims does not authorize an operation: the separate owner/session
// gate still binds issuer, resource, owner, client, expiry and revocation.
export async function verifyEs256Jwt(
  jwt: string,
  trustedJwks: { keys: Array<JsonWebKey & { kid?: string; use?: string; alg?: string }> },
): Promise<OwnerClaims | null> {
  try {
    if (typeof jwt !== "string" || jwt.length === 0 || jwt.length > 8192)
      return null;
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const decode = (part: string, maxBytes: number): Uint8Array => {
      if (!part || part.length > maxBytes * 2 || !/^[A-Za-z0-9_-]+$/.test(part))
        throw new Error("Invalid base64url");
      const str = atob(part.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - part.length % 4) % 4));
      if (str.length > maxBytes) throw new Error("Oversize JWT part");
      return Uint8Array.from(str, char => char.charCodeAt(0));
    };
    const parse = (part: string, maxBytes: number): Record<string, unknown> => {
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true })
        .decode(decode(part, maxBytes)));
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("Invalid JWT object");
      return value;
    };
    const header = parse(parts[0], 2048);
    const payload = parse(parts[1], 4096);
    if (header.alg !== "ES256" || typeof header.kid !== "string" ||
        !header.kid || header.kid.length > 128 ||
        "jwk" in header || "jku" in header || "x5u" in header ||
        "crit" in header) return null;
    const signature = decode(parts[2], 128);
    if (signature.length !== 64 || !trustedJwks ||
        !Array.isArray(trustedJwks.keys)) return null;
    const keys = trustedJwks.keys.filter(key =>
      key && key.kid === header.kid && key.kty === "EC" &&
      key.crv === "P-256" && (key.alg === undefined || key.alg === "ES256") &&
      (key.use === undefined || key.use === "sig") && !("d" in key) &&
      (!key.key_ops || key.key_ops.includes("verify")));
    if (keys.length !== 1) return null;
    const key = await crypto.subtle.importKey(
      "jwk", keys[0], { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const signed = new TextEncoder().encode(parts[0] + "." + parts[1]);
    if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" },
        key, signature, signed)) return null;
    return payload as unknown as OwnerClaims;
  } catch {
    return null;
  }
}

export async function authorizeOwnerRequest(
  header: string | null, verifier?: OwnerVerifier, nowSeconds = Math.floor(Date.now() / 1000)
): Promise<boolean> {
  // Deliberately NO production verifier is wired. All live/private calls deny.
  if (!verifier || !verifier.expectedOwner || !verifier.expectedClient ||
      !header || !/^Bearer [A-Za-z0-9._~-]+$/.test(header) || header.length > 8200)
    return false;
  try {
    const claims = await verifier.verifyBearer(header.slice(7));
    if (!claims || claims.iss !== ISSUER || claims.aud !== RESOURCE ||
        claims.sub !== verifier.expectedOwner ||
        claims.client_id !== verifier.expectedClient || claims.role !== "authenticated" ||
        typeof claims.session_id !== "string" || !SESSION.test(claims.session_id) ||
        !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
        claims.exp <= claims.iat || claims.exp - claims.iat > 3600 ||
        claims.exp <= nowSeconds - 30 || claims.iat > nowSeconds + 30 ||
        (claims.nbf !== undefined &&
         (!Number.isSafeInteger(claims.nbf) || claims.nbf > nowSeconds + 30)) ||
        typeof claims.scope !== "string" ||
        !["openid", "email"].every(s => claims.scope!.split(/\s+/).includes(s))) return false;
    return await verifier.sessionActive(claims.sub, claims.session_id, claims.client_id) === true;
  } catch {
    return false;
  }
}

function mcpHandler(request: Request) {
  return createMcpHandler(() => {
    const server = new McpServer({ name: "ocn-mcp-edge-review", version: "0.0.2" });
    server.registerTool("ping", {
      description: "Public read-only protocol canary. No device or account access.",
      inputSchema: z.object({}),
      _meta: { securitySchemes: [{ type: "noauth" }] },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    }, () => ({
      content: [{ type: "text", text: JSON.stringify({ pong: true, privileged: false }) }],
      structuredContent: { pong: true, privileged: false },
    }));
    // Exposes NO user data. The future verified auth adapter is absent, so
    // even a forged/well-formed bearer can never promote to owner access here.
    server.registerTool("owner_binding_probe", {
      description: "Review-only OAuth challenge. No Windows or account access.",
      inputSchema: z.object({}),
      _meta: { securitySchemes: [{ type: "oauth2", scopes: ["openid", "email"] }] },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    }, async () => {
      const allowed = await authorizeOwnerRequest(request.headers.get("authorization"));
      if (!allowed) return {
        isError: true,
        content: [{ type: "text", text: "Owner OAuth verifier not connected in review build" }],
        _meta: { "mcp/www_authenticate": [BEARER_CHALLENGE] },
      };
      return {
        // Unreachable in this review: no verifier provided.
        content: [{ type: "text", text: '{"owner_verified":true,"review_only":true}' }],
      };
    });
    return server;
  });
}

// Official path-aware OAuth resource metadata / WWW-Authenticate middleware.
// It does NOT authorize a user by itself: the private tool remains fail-closed.
const resourceMiddleware = pipeline(
  [withOAuthProtectedResource({
    resourceServer: RESOURCE,
    authorizationServer: ISSUER,
  })],
  async (req) => {
    const url = new URL(req.url);
    if (url.pathname === FUNCTION_PATH + "/healthz" && req.method === "GET") {
      return new Response(JSON.stringify({ healthy: true, privileged: false, review_only: true }), {
        status: 200, headers: {
          "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
        },
      });
    }
    if (url.pathname !== FUNCTION_PATH) {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404, headers: { "content-type": "application/json; charset=utf-8" },
      });
    }
    return mcpHandler(req).fetch(req);
  },
);

export async function fetchReview(request: Request): Promise<Response> {
  // Prevent forged public origin/issuer metadata in the review function.
  if (new URL(request.url).origin !== ORIGIN) {
    return new Response("Not found", { status: 404 });
  }
  return resourceMiddleware(request);
}

export default { fetch: fetchReview };
