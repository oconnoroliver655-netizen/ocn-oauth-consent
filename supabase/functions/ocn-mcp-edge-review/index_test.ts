// Isolated, NO network credentials, SQL, Windows queue, or real MCP connection.
import { fetchReview } from "./index.ts";

function check(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
const origin = "https://review-only.invalid/functions/v1/ocn-mcp-edge-review";
function rpc(method: string, params: Record<string, unknown>) {
  return new Request(origin, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json, text/event-stream",
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
Deno.test("out-of-scope routes fail closed", async () => {
  const res = await fetchReview(new Request(origin + "/secrets"));
  check(res.status === 404, "unexpected route must be unavailable");
});
Deno.test("MCP discovery exposes only ping, never an owner/device operation", async () => {
  const res = await fetchReview(rpc("tools/list", {}));
  check(res.ok, "MCP tools/list failed: " + res.status);
  const body = await res.text();
  check(body.includes('"ping"'), "public ping missing");
  for (const forbidden of ["submit_windows_operation", "owner_auth_probe", "browser_connect", "file_write"]) {
    check(!body.includes(forbidden), "privileged tool leaked: " + forbidden);
  }
});
Deno.test("MCP public ping returns a protocol response without any device access", async () => {
  const res = await fetchReview(rpc("tools/call", { name: "ping", arguments: {} }));
  check(res.ok, "public ping transport failed: " + res.status);
  const body = await res.text();
  check(body.includes("pong") && body.includes("true"), "public ping result missing");
  check(!body.includes("command_id"), "canary must not create Windows command IDs");
});
