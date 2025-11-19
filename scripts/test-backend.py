#!/usr/bin/env python3
"""
Backend HTTP simple pour tests E2E WebSec.
Lance un serveur HTTP avec quelques endpoints de test.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time

class TestBackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Test Backend</h1><p>WebSec E2E Test Server</p>")

        elif self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "healthy", "timestamp": time.time()}
            self.wfile.write(json.dumps(response).encode())

        elif self.path.startswith("/api/users"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            users = [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"},
                {"id": 3, "name": "Charlie"}
            ]
            self.wfile.write(json.dumps(users).encode())

        elif self.path == "/slow":
            # Endpoint lent pour tester les timeouts
            time.sleep(2)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Slow response")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        if self.path == "/api/login":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {
                "success": True,
                "token": "fake-jwt-token-12345",
                "user": {"id": 1, "username": "testuser"}
            }
            self.wfile.write(json.dumps(response).encode())

        elif self.path == "/api/echo":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Log personnalisé
        print(f"[Backend] {self.address_string()} - {format % args}")

def run_server(port=3000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, TestBackendHandler)
    print(f"✅ Test backend listening on port {port}")
    print(f"   Endpoints disponibles:")
    print(f"   - GET  /")
    print(f"   - GET  /api/health")
    print(f"   - GET  /api/users")
    print(f"   - GET  /slow")
    print(f"   - POST /api/login")
    print(f"   - POST /api/echo")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Backend arrêté")
        httpd.shutdown()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    run_server(port)
