from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        now = datetime.now(timezone.utc).isoformat()
        print(
            f"{now} client={self.client_address[0]} "
            f"path={self.path}",
            flush=True,
        )

        if self.path == "/health":
            status = 200
            body = {"status": "ok", "timestamp": now}
        else:
            status = 200
            body = {"message": "Protected lab server", "timestamp": now}

        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
