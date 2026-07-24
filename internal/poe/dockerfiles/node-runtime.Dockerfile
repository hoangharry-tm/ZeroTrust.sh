# PoE sandbox — Node runtime, grey-box: the caller supplies a single, bundled
# JS artifact (--poe-artifact) — e.g. an esbuild/webpack single-file output
# with dependencies inlined. No compile step, no node_modules tree.
#
# Isolation is enforced by internal/poe/sandbox.go's `docker run` flags, not here:
#   --security-opt seccomp=docker/sandbox/seccomp-profile.json
#   --network <per-scan internal network>  --read-only
#   --user 65534:65534  --memory 512m --cpus 1.0

FROM node:22-alpine
RUN addgroup -g 65534 nobody 2>/dev/null || true \
    && adduser -u 65534 -G nobody -D nobody 2>/dev/null || true
WORKDIR /app
COPY app.js /app/app.js
USER nobody
EXPOSE 8080
ENTRYPOINT ["node", "/app/app.js"]
