#!/bin/bash
# NetSnare attack harness — runs ONE bounded SYN flood trial against 127.0.0.1
# and reports real packets-on-wire vs. what the sniffer caught.
# Usage: ./tests/attack.sh <trial-number> [port] [data-size]

set -euo pipefail
cd "$(dirname "$0")/.."

TRIAL="${1:?usage: attack.sh <trial-number> [port] [data-size]}"
PORT="${2:-80}"
DSIZE="${3:-0}"
DURATION=5
LOGFILE=$(mktemp /tmp/hping_trial_XXXXXX.log)

sudo -v   # authenticate BEFORE the timed window, so no password pause happens mid-measurement

echo "=== Trial $TRIAL: port=$PORT data=$DSIZE duration=${DURATION}s ==="

before=$(grep "lo:" /proc/net/dev | awk '{print $2}')
echo "lo packets before: $before"

sudo timeout "$DURATION" hping3 -S -p "$PORT" -d "$DSIZE" --flood 127.0.0.1 \
  > "$LOGFILE" 2>&1 || true
cat "$LOGFILE"

after=$(grep "lo:" /proc/net/dev | awk '{print $2}')
echo "lo packets after:  $after"
echo "lo packets during this trial: $((after - before))"

sent=$(grep -oP '^\d+(?= packets transmitted)' "$LOGFILE" || echo "?")
echo "hping3 reported sent: $sent"

echo "--- current sniffer alert count (requires sniffer.py already running) ---"
if [ -f www/alerts.json ]; then
  python3 -c "import json; d=json.load(open('www/alerts.json')); print('alerts so far:', len(d['alerts'])); print('stats:', d['stats'])"
else
  echo "www/alerts.json not found — is sniffer.py running?"
fi

echo "=== Trial $TRIAL done ==="
