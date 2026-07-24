# PoE sandbox — Python runtime, grey-box: the caller supplies a single,
# already-built app script (--poe-artifact); no compile step.
#
# MVP scope: single-file artifacts only. The most common lightweight web
# frameworks are pre-installed so a self-contained Flask/FastAPI script runs
# without a separate requirements.txt step — arbitrary pip dependencies are a
# follow-up, not in scope here.
#
# Isolation is enforced by internal/poe/sandbox.go's `docker run` flags, not here:
#   --security-opt seccomp=docker/sandbox/seccomp-profile.json
#   --network <per-scan internal network>  --read-only
#   --user 65534:65534  --memory 512m --cpus 1.0

FROM python:3.12-alpine
RUN pip install --no-cache-dir flask fastapi uvicorn requests \
    && addgroup -g 65534 nobody 2>/dev/null || true \
    && adduser -u 65534 -G nobody -D nobody 2>/dev/null || true
WORKDIR /app
COPY app.py /app/app.py
USER nobody
EXPOSE 8080
ENTRYPOINT ["python3", "/app/app.py"]
