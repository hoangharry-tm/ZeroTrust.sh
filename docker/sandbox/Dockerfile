# Approach 3 PoE sandbox — builds a container from the analyzed codebase source.
# This Dockerfile is a template; the Red Team Agent generates the actual build
# context at runtime from the target codebase.
#
# Minimum isolation requirements (enforced via docker run flags, not here):
#   --security-opt seccomp=seccomp-profile.json
#   --network none
#   --read-only
#   --user 65534:65534
#   --memory 512m --cpus 1.0
FROM eclipse-temurin:21-jre-alpine AS base

RUN addgroup -g 65534 nobody && adduser -u 65534 -G nobody -D nobody 2>/dev/null || true

WORKDIR /app

USER nobody

CMD ["echo", "sandbox: no entrypoint configured"]
