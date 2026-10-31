# Tiny mock Jenkins for testing: python3 mock_jenkins.py 8099
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
PLUGINS = [dict(shortName="git", longName="Git", version="3.0.0", active=True, hasUpdate=True),
           dict(shortName="script-security", longName="Script Security", version="1.50", active=True, hasUpdate=True),
           dict(shortName="credentials", longName="Credentials", version="2.1.0", active=True, hasUpdate=True),
           dict(shortName="nonexistent-plugin", longName="X", version="1.0", active=False, hasUpdate=False)]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.headers.get("Authorization"): self.send_response(401); self.end_headers(); return
        if self.path.startswith("/pluginManager") and len(sys.argv) > 3: self.send_response(403); self.end_headers(); return
        b = json.dumps({"plugins": PLUGINS} if self.path.startswith("/pluginManager") else {}).encode()
        self.send_response(200); self.send_header("X-Jenkins", sys.argv[2] if len(sys.argv) > 2 else "2.300")
        self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
