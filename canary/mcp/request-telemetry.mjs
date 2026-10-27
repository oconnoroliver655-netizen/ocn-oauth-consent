import {randomUUID} from "node:crypto";

// Log only bounded, non-sensitive metadata. Paths outside this list, URL
// queries, request bodies, authorization and cookie headers are never emitted.
const ROUTES = new Map([
  ["/healthz", "healthz"],
  ["/mcp", "mcp"],
  ["/mcp-oauth", "mcp-oauth"],
  ["/mcp-ci-guard", "mcp-ci-guard"],
  ["/.well-known/oauth-protected-resource", "oauth-resource-metadata"],
]);
const METHODS = new Set(["GET", "POST", "HEAD", "OPTIONS"]);
const RENDER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function createRequestTelemetry({
  clock = () => Date.now(),
  write = line => console.log(line),
  limitPerMinute = 180,
} = {}) {
  if (!Number.isSafeInteger(limitPerMinute) || limitPerMinute < 1 || limitPerMinute > 6000)
    throw new TypeError("Invalid request log rate limit");
  let windowStart = clock();
  let emitted = 0;
  let suppressed = 0;

  const safeWrite = object => {
    // Logging can never be allowed to break the request handler.
    try { write(JSON.stringify(object)); } catch { /* best effort only */ }
  };
  const record = (entry, now) => {
    if (now < windowStart || now - windowStart >= 60_000) {
      if (suppressed) safeWrite({event:"ocn_http_log_suppressed",count:suppressed});
      windowStart = now;
      emitted = 0;
      suppressed = 0;
    }
    if (emitted >= limitPerMinute) { suppressed++; return; }
    emitted++;
    safeWrite(entry);
  };

  return function observeRequest(req, res) {
    const start = clock();
    const rawPath = typeof req.url === "string" ? req.url.split("?")[0] : "";
    const route = ROUTES.get(rawPath) ?? "other";
    const method = METHODS.has(req.method) ? req.method : "OTHER";
    const rawRenderId = req.headers?.["rndr-id"];
    const renderId = typeof rawRenderId === "string" && RENDER_ID.test(rawRenderId) ? rawRenderId : null;
    const traceId = randomUUID();
    let finished = false;

    const finalize = completion => {
      if (finished) return;
      finished = true;
      const now = clock();
      record({
        event:"ocn_http_request",
        trace_id:traceId,
        render_request_id:renderId,
        route,
        method,
        status_code:Number.isInteger(res.statusCode) && res.statusCode >= 100 && res.statusCode <= 599
          ? res.statusCode : null,
        duration_ms:Math.min(600_000,Math.max(0,now - start)),
        completion,
      },now);
    };
    res.once("finish",() => finalize("finished"));
    res.once("close",() => finalize(res.writableFinished ? "finished" : "aborted"));
  };
}
