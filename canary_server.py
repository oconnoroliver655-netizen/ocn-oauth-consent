"""Public, credential-free MCP HTTPS routing CANARY.

Deployed only from the public staging branch. No Supabase connection, no
Windows agent, no OAuth issuer, no privileged operation and no secrets.
This is NOT the owner-authorized MCP implementation in private Draft PR #522.
"""
from __future__ import annotations

import json
import os
import re
from wsgiref.simple_server import make_server

PROTOCOL = "2025-06-18"
MAX_BYTES = 8192
MAX_ID_LENGTH = 80
ALLOWED_METHODS = frozenset({"initialize", "ping", "tools/list", "tools/call", "notifications/initialized"})


def rpc_error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def response(request):
    if type(request) is not dict or request.get("jsonrpc") != "2.0":
        return 400, rpc_error(None, -32600, "Invalid JSON-RPC request")
    rpc_id = request.get("id")
    if rpc_id is not None and (type(rpc_id) not in (str, int) or
                               type(rpc_id) is str and len(rpc_id) > MAX_ID_LENGTH):
        return 400, rpc_error(None, -32600, "Invalid JSON-RPC id")
    method = request.get("method")
    params = request.get("params", {})
    if not isinstance(method, str) or method not in ALLOWED_METHODS or type(params) is not dict:
        return 200, rpc_error(rpc_id, -32601, "Unknown method")
    if method == "notifications/initialized":
        if rpc_id is not None:
            return 400, rpc_error(rpc_id, -32600, "Notification must not have request id")
        return 202, None
    if rpc_id is None:
        return 400, rpc_error(None, -32600, "Request id required")
    if method == "initialize":
        if params.get("protocolVersion") != PROTOCOL:
            return 200, rpc_error(rpc_id, -32602, "Protocol version unavailable")
        result = {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "ocn-public-https-canary", "version": "0.0.1"},
            "instructions": "Transport test only. No Windows, OAuth, filesystem, terminal or administrator access.",
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{
            "name": "ping",
            "description": "Static network canary only; does not contact any computer.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        }]}
    else:
        if params.get("name") != "ping" or params.get("arguments", {}) != {}:
            return 200, rpc_error(rpc_id, -32602, "Only static ping is supported")
        result = {"content": [{"type": "text", "text": '{"pong":true,"privileged":false}'}],
                  "structuredContent": {"pong": True, "privileged": False},
                  "isError": False}
    return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def app(environ, start_response):
    path, method = environ.get("PATH_INFO", ""), environ.get("REQUEST_METHOD", "")
    origin = environ.get("HTTP_ORIGIN")
    if origin:
        return send(start_response, 403, {"error": "Browser origins disabled"})
    if path == "/healthz":
        if method != "GET":
            return send(start_response, 405, {"error": "Method not allowed"})
        return send(start_response, 200, {"ready": True, "privileged": False, "service": "ocn-mcp-canary"})
    if path != "/mcp":
        return send(start_response, 404, {"error": "Not found"})
    if method != "POST":
        return send(start_response, 405, {"error": "MCP requires POST"})
    if environ.get("CONTENT_TYPE", "").split(";")[0].lower() != "application/json":
        return send(start_response, 415, {"error": "JSON only"})
    accept = environ.get("HTTP_ACCEPT", "").lower()
    if "application/json" not in accept or "text/event-stream" not in accept:
        return send(start_response, 406, {"error": "JSON and event-stream both required"})
    length = environ.get("CONTENT_LENGTH", "")
    if not length.isdecimal() or len(length) > 6 or int(length) > MAX_BYTES:
        return send(start_response, 413, {"error": "Invalid or oversized content length"})
    body = environ["wsgi.input"].read(int(length))
    if len(body) != int(length):
        return send(start_response, 400, rpc_error(None, -32700, "Body truncated"))
    try:
        request = json.loads(body)
    except (UnicodeError, ValueError):
        return send(start_response, 400, rpc_error(None, -32700, "Parse error"))
    status, result = response(request)
    return send(start_response, status, result)


def send(start_response, status, obj):
    text = {200:"OK", 202:"Accepted", 400:"Bad Request", 403:"Forbidden",
            404:"Not Found", 405:"Method Not Allowed", 406:"Not Acceptable",
            413:"Content Too Large", 415:"Unsupported Media Type"}[status]
    body = b"" if obj is None else json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = [("Cache-Control", "no-store"),
               ("X-Content-Type-Options", "nosniff"),
               ("Content-Length", str(len(body)))]
    if body:
        headers.append(("Content-Type", "application/json; charset=utf-8"))
    start_response(f"{status} {text}", headers)
    return [body]


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    if port <= 0 or port > 65535:
        raise SystemExit("Invalid port")
    with make_server("0.0.0.0", port, app) as server:
        server.serve_forever()
