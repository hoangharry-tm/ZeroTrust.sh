# PoE sandbox — Java runtime, grey-box: the caller supplies an already-built
# jar (--poe-artifact); this Dockerfile only packages and runs it, no compile.
#
# Isolation is enforced by internal/poe/sandbox.go's `docker run` flags, not here:
#   --security-opt seccomp=docker/sandbox/seccomp-profile.json
#   --network <per-scan internal network>  --read-only
#   --user 65534:65534  --memory 512m --cpus 1.0

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -g 65534 nobody && adduser -u 65534 -G nobody -D nobody 2>/dev/null || true
WORKDIR /app
COPY app.jar /app/app.jar
USER nobody
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
