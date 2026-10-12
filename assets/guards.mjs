// Public, dependency-free checks. Authentication and machine permissions
// are enforced by Supabase Auth and the separate private MCP resource server.
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const AUTH_ID = /^[A-Za-z0-9_-]{16,512}$/;
const CALLBACK_PARAMS = new Set(["code", "state", "iss", "error", "error_description", "error_uri"]);

export function isConfigured(config) {
  if (!config || typeof config !== "object") return false;
  if (config.supabaseUrl !== "https://ouxniljtjxnrkwakkvbv.supabase.co") return false;
  if (typeof config.publishableKey !== "string" ||
      !/^sb_publishable_[a-zA-Z0-9_-]{10,}$/.test(config.publishableKey)) return false;
  if (typeof config.ownerUserId !== "string" || !UUID.test(config.ownerUserId)) return false;
  if (typeof config.approvedOAuthClientId !== "string" ||
      !/^[a-zA-Z0-9_.:-]{8,200}$/.test(config.approvedOAuthClientId)) return false;
  try {
    const u = new URL(config.approvedRedirectUri);
    return u.protocol === "https:" && !u.username && !u.password && !u.search &&
      !u.hash && u.pathname.startsWith("/") && u.hostname !== "localhost";
  } catch { return false; }
}

export function getAuthorizationId(search) {
  if (typeof search !== "string") return null;
  const p = new URLSearchParams(search);
  const all = p.getAll("authorization_id");
  if (all.length !== 1 || !AUTH_ID.test(all[0])) return null;
  // Supabase email PKCE callbacks may append code/error fields to the
  // original consent URL. Never trust these as an OAuth client callback.
  const loginParams = new Set(["authorization_id", "code", "error", "error_code", "error_description"]);
  if ([...p.keys()].some(k => !loginParams.has(k))) return null;
  return all[0];
}

export function matchingCallback(value, approved, allowOAuthParams = true) {
  if (typeof value !== "string" || typeof approved !== "string") return false;
  try {
    const u = new URL(value);
    const pinned = new URL(approved);
    if (u.protocol !== "https:" || pinned.protocol !== "https:" ||
        u.username || u.password || u.hash || pinned.search || pinned.hash ||
        u.origin !== pinned.origin || u.pathname !== pinned.pathname) return false;
    if (!allowOAuthParams && u.search) return false;
    for (const key of u.searchParams.keys()) if (!CALLBACK_PARAMS.has(key)) return false;
    return true;
  } catch { return false; }
}

export function isOwner(user, config) {
  return Boolean(isConfigured(config) && user && typeof user === "object" &&
    user.id === config.ownerUserId);
}

export function authorizeDetails(details, authorizationId, config) {
  return isConfigured(config) && details && typeof details === "object" &&
    details.authorization_id === authorizationId &&
    details.user?.id === config.ownerUserId &&
    details.client?.id === config.approvedOAuthClientId &&
    matchingCallback(details.redirect_uri, config.approvedRedirectUri, false);
}

export function returnToConsent(currentUrl, authorizationId) {
  if (!AUTH_ID.test(authorizationId)) throw Error("Invalid authorization ID");
  const url = new URL(currentUrl);
  if (url.protocol !== "https:") throw Error("HTTPS required");
  url.hash = "";
  url.search = "";
  url.searchParams.set("authorization_id", authorizationId);
  return url.toString();
}
