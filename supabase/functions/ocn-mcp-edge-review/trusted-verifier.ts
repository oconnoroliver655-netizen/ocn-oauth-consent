/**
 * ISOLATED REVIEW CONTRACT ONLY — not imported by the deployed MCP handler.
 * Public Supabase JWKS read + owner/session consent RPC, with an additional
 * mandatory NEW resource-binding check. No device tools, tokens or secrets.
 *
 * The current production ocn_owner_oauth_session_active RPC has a binding
 * for the OLD Render audience. It cannot on its own prove an Edge audience
 * is authorized. Do not wire this adapter until a trusted server-side exact
 * resource-binding check exists and passes.
 */
import { verifyEs256Jwt, type OwnerVerifier } from "./index.ts";

export const REVIEW_ORIGIN = "https://ouxniljtjxnrkwakkvbv.supabase.co";
export const REVIEW_RESOURCE = REVIEW_ORIGIN + "/functions/v1/ocn-mcp-edge-review";
const JWKS_URL = REVIEW_ORIGIN + "/auth/v1/.well-known/jwks.json";
const CONSENT_URL = REVIEW_ORIGIN + "/rest/v1/rpc/ocn_owner_oauth_session_active";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
type ReadOnlyFetch = typeof fetch;

export interface ReviewServerDependencies {
  expectedOwner: string;
  expectedClient: string;
  /** Inject on the server ONLY; never embed this value in logs or client JS. */
  serviceRoleKey: string;
  /** Must attest exact REVIEW_RESOURCE, not just existence of old Render consent. */
  resourceBindingActive: (audience: string) => Promise<boolean>;
  fetchImpl: ReadOnlyFetch;
}

async function boundedJson(response: Response, maxBytes: number): Promise<unknown> {
  if (!response.ok || response.redirected ||
      !/^application\/json(?:\s*;|\s*$)/i.test(response.headers.get("content-type") || "")) {
    throw new Error("Bad server response");
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) ||
      Number(contentLength) > maxBytes)) throw new Error("Oversize JSON");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Missing body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > maxBytes) throw new Error("Oversize stream");
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

/**
 * Returns a verifier with NO ability to perform Windows operations.
 * Caller must separately validate exact issuer/audience/owner/client/time/scope
 * via authorizeOwnerRequest(). All upstream errors and revocations deny.
 */
export function createReviewServerVerifier(config: ReviewServerDependencies): OwnerVerifier {
  if (!UUID.test(config.expectedOwner) || !UUID.test(config.expectedClient) ||
      !config.serviceRoleKey || config.serviceRoleKey.length < 10 ||
      !config.fetchImpl || !config.resourceBindingActive) {
    throw new Error("Invalid review server-side dependencies");
  }
  return {
    expectedOwner: config.expectedOwner,
    expectedClient: config.expectedClient,
    async verifyBearer(token) {
      try {
        const response = await config.fetchImpl(JWKS_URL, {
          method: "GET",
          headers: { accept: "application/json" },
          redirect: "error",
          cache: "no-store",
          signal: AbortSignal.timeout(3500),
        });
        const raw = await boundedJson(response, 16_384);
        if (!raw || typeof raw !== "object" || !("keys" in raw) ||
            !Array.isArray(raw.keys) || raw.keys.length > 16) return null;
        return await verifyEs256Jwt(token, raw as {
          keys: Array<JsonWebKey & { kid?: string; use?: string; alg?: string }>
        });
      } catch {
        return null;
      }
    },
    async sessionActive(who, session, client) {
      if (who !== config.expectedOwner || client !== config.expectedClient ||
          !UUID.test(session)) return false;
      try {
        // Required: current production RPC still checks the OLD binding.
        if ((await config.resourceBindingActive(REVIEW_RESOURCE)) !== true) return false;
        const result = await config.fetchImpl(CONSENT_URL, {
          method: "POST",
          headers: {
            apikey: config.serviceRoleKey,
            authorization: "Bearer " + config.serviceRoleKey,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            p_owner: who, p_session: session, p_client: client,
          }),
          redirect: "error",
          cache: "no-store",
          signal: AbortSignal.timeout(3500),
        });
        return (await boundedJson(result, 32)) === true;
      } catch {
        return false;
      }
    },
  };
}
