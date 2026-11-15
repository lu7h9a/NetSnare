"""Dashboard server: serves exactly dashboard.html and alerts.json.

Replaces `python3 -m http.server`, which served the whole repository
(packets.jsonl, .git/) and accepted any Host header, so a web page could
read it through DNS rebinding. This server answers only two paths, only to
a Host of 127.0.0.1, localhost or [::1] on its own port, and never as root.

Usage: python3 serve.py [port]       (binds 127.0.0.1, default port 8000)
"""
import http.server
import os
import pwd
import sys

ROUTES = {
    "/": ("dashboard.html", "text/html; charset=utf-8"),
    "/dashboard.html": ("dashboard.html", "text/html; charset=utf-8"),
    "/alerts.json": (os.path.join("www", "alerts.json"), "application/json"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NetSnare"
    sys_version = ""

    def _allowed_host(self):
        port = self.server.server_address[1]
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def do_GET(self):
        if not self._allowed_host():
            self.send_error(421, "Misdirected Request")
            return
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            self.send_error(404)
            return
        path, ctype = route
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def log_request(self, code="-", size="-"):
        pass   # the dashboard polls every 2 s; log only errors

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))


def drop_privileges():
    if os.geteuid() != 0:
        return
    name = os.environ.get("SUDO_USER") or "nobody"
    if name == "root":
        name = "nobody"
    pw = pwd.getpwnam(name)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "8000"
    if not arg.isdigit() or not 1 <= int(arg) <= 65535:
        sys.exit(f"serve.py: port must be a number from 1 to 65535, got {arg!r}")
    # The working directory is kept after dropping root, so files stay
    # reachable even if a parent directory is closed to the new user.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", int(arg)), Handler)
    drop_privileges()
    print(f"NetSnare dashboard: http://127.0.0.1:{arg}/dashboard.html", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
