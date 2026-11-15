#!/bin/bash
# Start the 9dasand72 Proof Gatekeeper agent + public HTTPS tunnel.
# Usage: ./run.sh   (run with setsid so it survives the launching session:
#                    setsid ./run.sh > run.log 2>&1 < /dev/null &)
# Loads .env if present. Writes the public URL to endpoint.txt.
#
# Tunnel: localhost.run (free SSH reverse tunnel, no account).
# cloudflared was tried first and is BLOCKED here: the sandbox egress proxy
# returns 403 for api.trycloudflare.com, and localtunnel hangs (it ignores
# the proxy env, and direct egress is blocked). localhost.run works because
# its SSH endpoint is reachable via CONNECT through the egress proxy
# (see proxy_cmd.sh). The assigned *.app.lhr.life domain ROTATES when the
# tunnel restarts — re-register the endpoint in the dashboard if it changes.
set -u
cd "$(dirname "$0")"

# Load .env (simple KEY=VALUE lines, no interpolation)
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

PORT="${PORT:-3000}"
mkdir -p logs
chmod +x proxy_cmd.sh 2>/dev/null || true

# --- agent server ---
if ! curl -fsS --max-time 5 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
  setsid node server.mjs > logs/server.log 2>&1 < /dev/null &
  echo "server started (pid $!)"
else
  echo "server already up on :${PORT}"
fi

# Wait for health
for _ in 1 2 3 4 5 6 7 8 9 10; do
  curl -fsS --max-time 5 "http://localhost:${PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --max-time 5 "http://localhost:${PORT}/health" || { echo "server did not become healthy"; exit 1; }

# --- localhost.run tunnel (SSH reverse tunnel via egress proxy) ---
if ! pgrep -f "nokey@localhost.run" >/dev/null 2>&1; then
  setsid ssh -o ProxyCommand="$PWD/proxy_cmd.sh %h %p" \
    -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ConnectTimeout=20 \
    -R "80:localhost:${PORT}" nokey@localhost.run > logs/lhr.log 2>&1 < /dev/null &
  echo "tunnel started (pid $!)"
else
  echo "tunnel already running"
fi

# Wait for the public URL to appear in the tunnel log, then record it.
# Assigned line looks like: "<hex>.app.lhr.life tunneled with tls termination, https://<hex>.app.lhr.life"
URL=""
for _ in $(seq 1 30); do
  URL=$(grep -oE 'https://[a-zA-Z0-9-]+\.app\.lhr\.life' logs/lhr.log | head -1)
  [ -n "$URL" ] && break
  sleep 2
done

if [ -n "$URL" ]; then
  echo "$URL" > endpoint.txt
  echo "PUBLIC ENDPOINT: $URL"
  echo "health: $URL/health"
else
  echo "tunnel URL not found yet — check logs/lhr.log"
  exit 1
fi
