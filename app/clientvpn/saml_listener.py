"""One-shot loopback listener that receives the SAMLResponse from the browser.

The listener only exists between StartLogin and the first valid POST (or a
timeout). It accepts exactly one well-formed request; the daemon performs the
binding checks (Destination / InResponseTo) on the value we pass along.
"""

import http.server
import threading
import urllib.parse

from gi.repository import GLib

HOST = "127.0.0.1"
PORT = 35001
MAX_BODY = 512 * 1024  # form-encoded base64 response, generous upper bound
MAX_RESPONSE = 256 * 1024  # must match the daemon's saml.MaxResponseSize

_DONE_PAGE = b"""<!doctype html><meta charset="utf-8"><title>Client VPN</title>
<style>body{font-family:sans-serif;display:grid;place-items:center;height:90vh;color:#333}
@media(prefers-color-scheme:dark){body{background:#222;color:#eee}}</style>
<p>Login received. You can close this tab and return to Client VPN.</p>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "client-vpn"
    sys_version = ""
    timeout = 10  # per-connection socket timeout

    def log_message(self, fmt, *args):  # never log request contents
        pass

    def _reply(self, code, body=b"", ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._reply(405, b"POST expected\n")

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET

    def do_POST(self):
        listener = self.server.listener
        if listener.consumed:
            return self._reply(410, b"Login already completed\n")
        if urllib.parse.urlsplit(self.path).path != "/":
            return self._reply(404, b"Not found\n")
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            return self._reply(415, b"Unsupported content type\n")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(411, b"Length required\n")
        if length <= 0 or length > MAX_BODY:
            return self._reply(413, b"Request too large\n")
        body = self.rfile.read(length)
        try:
            form = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=8)
        except (UnicodeDecodeError, ValueError):
            return self._reply(400, b"Malformed form\n")
        values = form.get("SAMLResponse", [])
        if len(values) != 1 or not values[0] or len(values[0]) > MAX_RESPONSE:
            return self._reply(400, b"SAMLResponse missing\n")
        listener.consumed = True
        self._reply(200, _DONE_PAGE, "text/html; charset=utf-8")
        GLib.idle_add(listener._deliver, values[0])


class _Server(http.server.HTTPServer):
    # SO_REUSEADDR lets a retry bind while old connections sit in TIME_WAIT;
    # on Linux it does not allow a second live listener on the port.
    allow_reuse_address = True
    request_queue_size = 4
    timeout = 1


class SamlListener:
    """Call start(); on_response(str) or on_error(str) fires on the main loop."""

    def __init__(self, on_response, on_error, timeout_s=180):
        self._on_response = on_response
        self._on_error = on_error
        self._timeout_s = timeout_s
        self._server = None
        self._timeout_id = 0
        self.consumed = False

    def start(self):
        try:
            self._server = _Server((HOST, PORT), _Handler)
        except OSError as e:
            raise RuntimeError(f"Port {PORT} is busy; is another login in progress? ({e.strerror})") from e
        self._server.listener = self
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
        self._timeout_id = GLib.timeout_add_seconds(self._timeout_s, self._expire)

    def stop(self):
        if self._timeout_id:
            GLib.source_remove(self._timeout_id)
            self._timeout_id = 0
        if self._server:
            server, self._server = self._server, None
            server.shutdown()  # waits at most one poll interval
            server.server_close()

    def _expire(self):
        self._timeout_id = 0
        if not self.consumed:
            self.consumed = True
            self.stop()
            self._on_error("Login timed out")
        return GLib.SOURCE_REMOVE

    def _deliver(self, value):
        self.stop()
        self._on_response(value)
        return GLib.SOURCE_REMOVE
