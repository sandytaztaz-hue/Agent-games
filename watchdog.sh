#!/bin/bash
# Watchdog for the 9dasand72 Proof Gatekeeper agent.
# Run every 5 min via cron, or manually: ./watchdog.sh
# Restarts the server and/or tunnel if either is down, and refreshes endpoint.txt.
# NOTE: the tunnel (localhost.run via ssh) needs the sandbox egress proxy env
# (https_proxy) to be present when this runs — interactive sessions have it;
# if you run this from cron, export the proxy vars in the crontab.
# (Known limitation: localhost.run free domains ROTATE on every tunnel restart.
# If the tunnel restarts, the public URL changes and the endpoint must be
# re-registered in the Agent Games dashboard.)
set -u
cd "$(dirname "$0")"
# Egress proxy vars (needed by the localhost.run SSH tunnel). Cron workers
# don't inherit them, so load from proxy.env (chmod 600, gitignored).
# NOTE: ambient proxy credentials ROTATE per run — prefer the ambient env
# and only fall back to proxy.env when ambient is unset, otherwise the
# stored (stale) credentials break the tunnel (seen 2026-11-15: every
# restart failed with "Connection closed by UNKNOWN port 65535").
if [ -z "${https_proxy:-}" ] && [ -f proxy.env ]; then set -a; . ./proxy.env; set +a; fi
if [ -f .env ]; then set -a; . ./.env; set +a; fi
PORT="${PORT:-3000}"
mkdir -p logs
NEED_RUN=0

if ! curl -fsS --max-time 5 "http://localhost:${PORT}/health" >/dev/null 2>&1; then
  echo "$(date -Is) server down — restarting" >> logs/watchdog.log
  pkill -f "node server.mjs" 2>/dev/null; sleep 1
  setsid node server.mjs > logs/server.log 2>&1 < /dev/null &
  NEED_RUN=1
fi

if ! pgrep -f "nokey@localhost.run" >/dev/null 2>&1; then
  echo "$(date -Is) tunnel down — restarting" >> logs/watchdog.log
  setsid ssh -o ProxyCommand="$PWD/proxy_cmd.sh %h %p" \
    -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ConnectTimeout=20 \
    -R "80:localhost:${PORT}" nokey@localhost.run > logs/lhr.log 2>&1 < /dev/null &
  NEED_RUN=1
fi

if [ "$NEED_RUN" = "1" ]; then
  sleep 25
  URL=$(grep -oE 'https://[a-zA-Z0-9-]+\.app\.lhr\.life' logs/lhr.log | head -1)
  if [ -n "$URL" ]; then
    echo "$URL" > endpoint.txt
    echo "$(date -Is) endpoint now $URL (re-register in dashboard if it changed)" >> logs/watchdog.log
  fi
fi
