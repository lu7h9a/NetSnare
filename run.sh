#!/bin/bash
# NetSnare one-command launcher.
#
# Starts the dashboard server (serve.py) in the background and the sniffer
# in the foreground, so you see ALERT lines printed live in this terminal.
# Both drop root after start-up: they run as the user who called sudo, or
# as nobody when run by root directly (for example from systemd).
#
# Usage: sudo ./run.sh [port]        (default port 8000)
#   Ctrl-C stops the sniffer AND the dashboard server together.

set -euo pipefail
cd "$(dirname "$0")"

PORT="${1:-8000}"
case "$PORT" in
  ''|*[!0-9]*) echo "run.sh: port must be a number, got '$PORT'"; exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "run.sh: port must be from 1 to 65535"; exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "NetSnare needs root to open a raw socket for the sniffer."
  echo "Re-run as: sudo ./run.sh"
  exit 1
fi

echo "=== NetSnare ==="
echo "Dashboard: http://127.0.0.1:${PORT}/dashboard.html"
echo "Starting the dashboard server (background) and sniffer (foreground, Ctrl-C stops both)..."
echo

# The server's output stays in this terminal; no log file in a shared /tmp.
python3 serve.py "$PORT" &
HTTP_PID=$!

cleanup() {
  echo
  echo "Stopping the dashboard server (pid $HTTP_PID)..."
  kill "$HTTP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 0.5
if ! kill -0 "$HTTP_PID" 2>/dev/null; then
  echo "run.sh: the dashboard server did not start (port ${PORT} in use?)"
  exit 1
fi

# Sniffer runs in the foreground: its print() ALERT lines show here directly.
python3 sniffer.py
