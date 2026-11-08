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
