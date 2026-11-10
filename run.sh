#!/bin/bash
# NetWraith one-command launcher.
#
# Starts the HTTP server (for dashboard.html) in the background and the
# sniffer in the foreground, so you see ALERT lines printed live in this
# terminal. Everything stays in the terminal — no separate tabs needed.
#
# Usage: ./run.sh [port]        (default port 8000)
#   Ctrl-C stops the sniffer AND the HTTP server together.

set -euo pipefail
cd "$(dirname "$0")"

PORT="${1:-8000}"

if [ "$EUID" -ne 0 ]; then
  echo "NetWraith needs root to open a raw socket for the sniffer."
  echo "Re-run as: sudo ./run.sh"
  exit 1
fi

# find the real (non-root) user, so the HTTP server + dashboard files
# stay owned sanely and the URL printed below is accurate
REAL_USER="${SUDO_USER:-$(whoami)}"

echo "=== NetWraith ==="
echo "Dashboard: http://127.0.0.1:${PORT}/dashboard.html"
echo "Starting HTTP server (background) and sniffer (foreground, Ctrl-C stops both)..."
echo

# Start the dashboard's HTTP server in the background, as the invoking
# user if possible (not root), bound to localhost only.
if [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$SUDO_USER" python3 -m http.server --bind 127.0.0.1 "$PORT" \
    > /tmp/netwraith_http.log 2>&1 &
else
  python3 -m http.server --bind 127.0.0.1 "$PORT" \
    > /tmp/netwraith_http.log 2>&1 &
fi
HTTP_PID=$!

cleanup() {
  echo
  echo "Stopping HTTP server (pid $HTTP_PID)..."
  kill "$HTTP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Sniffer runs in the foreground: its print() ALERT lines show here directly.
python3 sniffer.py
