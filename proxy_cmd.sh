#!/bin/bash
# ProxyCommand helper for ssh: CONNECT to $1:$2 through the sandbox egress proxy.
# Reads the proxy URL from the environment (https_proxy). Never prints credentials.
# Used by run.sh / watchdog.sh to reach localhost.run:22 from inside the VM.
host="$1"
port="$2"
url="${https_proxy:-${HTTPS_PROXY:-${http_proxy:-}}}"
if [ -z "$url" ]; then
  echo "proxy_cmd: no https_proxy in environment" >&2
  exit 1
fi
rest="${url#*://}"
auth="${rest%%@*}"
hostport="${rest#*@}"
proxyhost="${hostport%%:*}"
proxyport="${hostport##*:}"
exec socat - "PROXY:${proxyhost}:${host}:${port},proxyport=${proxyport},proxyauth=${auth}"
