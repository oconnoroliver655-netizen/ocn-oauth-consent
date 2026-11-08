// Review-only Supabase Edge ingress canary. NO OAuth grants, Windows control,
// durable state, project scheduler, secret handling, or production deployment.
// This file demonstrates only the official, stateless streamable-HTTP MCP ping.
import { createMcpHandler, McpServer } from "npm:@modelcontextprotocol/server@2.0.0";
import { z } from "npm:zod@4.3.6";

const FUNCTION_PATH = "/functions/v1/ocn-mcp-edge-review";

function mcpHandler() {
  return createMcpHandler(() => {
    const server = new McpServer({ name: "ocn-mcp-edge-review", version: "0.0.1" });
    server.registerTool("ping", {
      description: "Public read-only protocol canary. No device or account access.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    }, () => ({
      content: [{ type: "text", text: JSON.stringify({ pong: true, privileged: false }) }],
      structuredContent: { pong: true, privileged: false },
    }));
    return server;
  });
}

const protocol = mcpHandler();
export async function fetchReview(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === FUNCTION_PATH + "/healthz" && request.method === "GET") {
    return new Response(JSON.stringify({ healthy: true, privileged: false, review_only: true }), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }
  if (url.pathname !== FUNCTION_PATH) {
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404, headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  // The official SDK enforces the JSON-RPC/MCP protocol and transport headers.
  // This review deliberately does NOT register private operations or authentication.
  return await protocol.fetch(request);
}

export default { fetch: fetchReview };
