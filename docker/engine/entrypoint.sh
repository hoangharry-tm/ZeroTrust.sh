#!/bin/sh
# ZeroTrust.sh engine entrypoint — runs inside the Docker container.
# Sets up environment variables and delegates to the engine binary.
set -e

# Default to host-loopback for Joern if not configured
export JOERN_URL="${JOERN_URL:-http://127.0.0.1:8080}"

# Default Ollama URL: try host.docker.internal first, fall back to local inference
if [ -z "$OLLAMA_URL" ]; then
    if curl -sf --max-time 1 http://host.docker.internal:11434 >/dev/null 2>&1; then
        export OLLAMA_URL="http://host.docker.internal:11434"
    else
        export OLLAMA_URL="http://127.0.0.1:11434"
    fi
fi

# Ensure state directory exists
mkdir -p /home/zt/.zerotrust

exec /usr/local/bin/zerotrust --native "$@"
