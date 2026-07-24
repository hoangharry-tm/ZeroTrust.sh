# PoE sandbox — Go/native runtime, grey-box: the caller supplies an
# already-built static binary (--poe-artifact). No compile step — this is
# just enough userland to run a statically-linked executable as non-root.
#
# Isolation is enforced by internal/poe/sandbox.go's `docker run` flags, not here:
#   --security-opt seccomp=docker/sandbox/seccomp-profile.json
#   --network <per-scan internal network>  --read-only
#   --user 65534:65534  --memory 512m --cpus 1.0

FROM alpine:3.20
RUN addgroup -g 65534 nobody 2>/dev/null || true \
    && adduser -u 65534 -G nobody -D nobody 2>/dev/null || true
WORKDIR /app
COPY app /app/app
USER nobody
EXPOSE 8080
ENTRYPOINT ["/app/app"]
