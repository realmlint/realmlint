"""A stand-in for the realmlint portal's /v1/terraform-state endpoint, for
testing the terraform-state action in CI. Accepts the token "test-token" and
a gzipped state with keycloak/keycloak resources."""
import gzip
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        if self.path != "/v1/terraform-state":
            return self.reply(404, {"error": "not found"})
        if self.headers.get("Authorization") != "Bearer test-token":
            return self.reply(401, {"error": "invalid agent token"})
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        state = json.loads(body)
        resources = [r for r in state["values"]["root_module"]["resources"] if r["type"].startswith("keycloak_")]
        if not resources:
            return self.reply(422, {"error": "the state has no keycloak/keycloak resources"})
        realms = sorted({r["values"].get("realm_id") or r["values"].get("realm") for r in resources})
        self.reply(201, {"status": "stored", "resources": len(resources), "realms": realms})

    def reply(self, code, doc):
        data = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
