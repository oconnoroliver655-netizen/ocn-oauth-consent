import io
import json
import unittest

from canary_server import MAX_BYTES, PROTOCOL, app, response


class CanaryTests(unittest.TestCase):
    def call(self, path="/mcp", method="POST", rpc=None, *, accept="application/json, text/event-stream",
             content_type="application/json", origin=None, body=None):
        raw = body if body is not None else json.dumps(rpc if rpc is not None else {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list"
        }).encode()
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(raw)), "HTTP_ACCEPT": accept, "wsgi.input": io.BytesIO(raw)
        }
        if origin:
            environ["HTTP_ORIGIN"] = origin
        captured = []
        def start_response(status, headers):
            captured.append((status, headers))
        output = b"".join(app(environ, start_response))
        self.assertEqual(len(captured),1)
        code = int(captured[0][0][:3])
        return code, json.loads(output) if output else None

    def test_health_has_no_privileges(self):
        code, result = self.call(path="/healthz", method="GET")
        self.assertEqual(code,200)
        self.assertFalse(result["privileged"])

    def test_ping_lists_single_static_tool(self):
        code, result = self.call()
        self.assertEqual(code,200)
        self.assertEqual([t["name"] for t in result["result"]["tools"]], ["ping"])
        self.assertNotIn("powershell", str(result).lower())

    def test_initialize_fixed_version(self):
        code, r = self.call(rpc={"jsonrpc":"2.0","id":3,"method":"initialize",
                                 "params":{"protocolVersion":PROTOCOL}})
        self.assertEqual(code,200)
        self.assertEqual(r["result"]["protocolVersion"],PROTOCOL)

    def test_unsupported_version_denied(self):
        code, r = self.call(rpc={"jsonrpc":"2.0","id":3,"method":"initialize",
                                 "params":{"protocolVersion":"unknown"}})
        self.assertEqual(r["error"]["code"],-32602)

    def test_anonymous_tool_call_is_only_ping(self):
        code, r = self.call(rpc={"jsonrpc":"2.0","id":3,"method":"tools/call",
                                 "params":{"name":"ping","arguments":{}}})
        self.assertEqual(code,200)
        self.assertEqual(r["result"]["structuredContent"],{"pong":True,"privileged":False})
        for name in ("powershell","desktop","owner","health"):
            _, r = self.call(rpc={"jsonrpc":"2.0","id":3,"method":"tools/call",
                                  "params":{"name":name,"arguments":{}}})
            self.assertIn("error",r)

    def test_fake_tool_arguments_rejected(self):
        _, r = self.call(rpc={"jsonrpc":"2.0","id":3,"method":"tools/call",
                              "params":{"name":"ping","arguments":{"command":"shutdown"}}})
        self.assertEqual(r["error"]["code"],-32602)

    def test_web_browser_origin_rejected(self):
        code, r = self.call(origin="https://attacker.example")
        self.assertEqual(code,403)

    def test_content_type_and_accept_enforced(self):
        self.assertEqual(self.call(content_type="text/plain")[0],415)
        self.assertEqual(self.call(accept="application/json")[0],406)

    def test_large_body_denied(self):
        self.assertEqual(self.call(body=b" "*(MAX_BYTES+1))[0],413)

    def test_invalid_json_or_arrays_rejected(self):
        self.assertEqual(self.call(body=b"{bad")[0],400)
        _, r=self.call(rpc=[{"jsonrpc":"2.0","id":1,"method":"ping"}])
        self.assertEqual(r["error"]["code"],-32600)

    def test_notifications_not_responded_to(self):
        code, r=self.call(rpc={"jsonrpc":"2.0","method":"notifications/initialized"})
        self.assertEqual((code,r),(202,None))

    def test_get_mcp_denied(self):
        self.assertEqual(self.call(method="GET")[0],405)


if __name__ == "__main__":
    unittest.main()
