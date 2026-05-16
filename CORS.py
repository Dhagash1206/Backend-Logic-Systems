
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# CORS Configuration
CORS_CONFIG = {
    "allowed_origins": [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://yourdomain.com",       # Replace with your domain
    ],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allowed_headers": [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
    ],
    "expose_headers": ["Content-Length", "X-Request-Id"],
    "allow_credentials": True,
    "max_age": 86400,                   # Preflight cache: 24 hours
}


# Exceptions
class CORSForbiddenError(Exception):
    """Raised when an origin is not in the allowlist."""


# CORS Handler
class CORSHandler(BaseHTTPRequestHandler):

    # suppress default request logs (we handle manually)
    def log_message(self, format, *args):
        logger.info("Request: %s", format % args)


    # CORS Core

    def _get_origin(self) -> Optional[str]:
        return self.headers.get("Origin")

    def _is_origin_allowed(self, origin: Optional[str]) -> bool:
        if not origin:
            return True                 # Non-browser requests (e.g. curl)
        return origin in CORS_CONFIG["allowed_origins"]

    def _apply_cors_headers(self):
        """
        Apply CORS response headers.
        Dynamically mirrors the request origin if allowed (avoids wildcard
        which is incompatible with credentials).
        """
        origin = self._get_origin()

        if not self._is_origin_allowed(origin):
            logger.warning("Blocked origin: %s", origin)
            raise CORSForbiddenError(f"Origin not allowed: {origin}")

        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")             # Cache safety

        if CORS_CONFIG["allow_credentials"]:
            self.send_header("Access-Control-Allow-Credentials", "true")

        self.send_header(
            "Access-Control-Expose-Headers",
            ", ".join(CORS_CONFIG["expose_headers"])
        )

    def _apply_preflight_headers(self):
        """Extra headers only for OPTIONS preflight responses."""
        self.send_header(
            "Access-Control-Allow-Methods",
            ", ".join(CORS_CONFIG["allowed_methods"])
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            ", ".join(CORS_CONFIG["allowed_headers"])
        )
        self.send_header(
            "Access-Control-Max-Age",
            str(CORS_CONFIG["max_age"])
        )


    # Response Helpers

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self._apply_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str):
        self._send_json(status, {"error": message})

    def _read_body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None


    # HTTP Methods

    def do_OPTIONS(self):
        """Handle CORS preflight request."""
        try:
            self.send_response(204)           # No Content
            self._apply_cors_headers()
            self._apply_preflight_headers()
            self.end_headers()
            logger.info("Preflight OK for origin: %s", self._get_origin())
        except CORSForbiddenError as e:
            self.send_response(403)
            self.end_headers()

    def do_GET(self):
        try:
            if self.path == "/api/health":
                self._send_json(200, {"status": "ok"})

            elif self.path == "/api/data":
                self._send_json(200, {"message": "Hello from pure Python CORS server!"})

            else:
                self._send_error(404, "Route not found.")

        except CORSForbiddenError as e:
            self._send_error(403, str(e))
        except Exception as e:
            logger.error("Unhandled error: %s", e)
            self._send_error(500, "Internal server error.")

    def do_POST(self):
        try:
            if self.path == "/api/echo":
                body = self._read_body()
                if body is None:
                    self._send_error(400, "Invalid or missing JSON body.")
                    return
                self._send_json(200, {"echo": body})

            else:
                self._send_error(404, "Route not found.")

        except CORSForbiddenError as e:
            self._send_error(403, str(e))
        except Exception as e:
            logger.error("Unhandled error: %s", e)
            self._send_error(500, "Internal server error.")


# Server Entry Point
def run(host: str = "0.0.0.0", port: int = 8000):
    server = HTTPServer((host, port), CORSHandler)
    logger.info("Server running on http://%s:%d", host, port)
    logger.info("Allowed origins: %s", CORS_CONFIG["allowed_origins"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server.")
        server.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    run(port=port)