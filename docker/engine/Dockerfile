# syntax=docker/dockerfile:1
# ZeroTrust.sh engine image — bundles all heavy dependencies.
# Built by CI and pushed to ghcr.io/hoangharry-tm/zerotrust-engine.
# The thin CLI (cmd/zt) pulls and orchestrates this image.
#
# Joern is installed from GitHub releases (not Docker Hub — no official Joern image exists).
# OpenGrep and ast-grep are similarly pulled as pre-built binaries from their release pages.

# Stage 0: Joern installation
FROM eclipse-temurin:21-jre-alpine AS joern-install

ARG JOERN_VERSION=v4.0.559

RUN apk add --no-cache curl unzip ca-certificates && \
    curl -fsSL "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli.zip" \
    -o /tmp/joern-cli.zip && \
    mkdir -p /opt/joern && \
    unzip -q /tmp/joern-cli.zip -d /opt/joern && \
    rm /tmp/joern-cli.zip && \
    mv /opt/joern/joern-cli/* /opt/joern/ && \
    rmdir /opt/joern/joern-cli && \
    ln -s /opt/joern/joern-server /usr/local/bin/joern-server

# Stage 1: Python worker
FROM python:3.13-alpine AS python-base

RUN apk add --no-cache gcc musl-dev curl && \
    curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

COPY worker/ /tmp/worker/
WORKDIR /tmp/worker
RUN uv sync --no-dev && \
    rm -rf /tmp/worker

WORKDIR /

# Stage 2: Runtime image
FROM eclipse-temurin:21-jre-alpine

ARG ENGINE_BINARY=build/zerotrust
ARG JOERN_VERSION=v4.0.559

RUN apk add --no-cache curl ca-certificates && \
    addgroup -g 1000 zt && \
    adduser -u 1000 -G zt -D -h /home/zt zt

# Copy Joern from stage 0
COPY --from=joern-install /opt/joern /opt/joern
COPY --from=joern-install /usr/local/bin/joern-server /usr/local/bin/joern-server
ENV JOERN_PATH=/opt/joern

# Copy Python worker + venv from stage 1
COPY --from=python-base /usr/local/lib/python3.13 /usr/local/lib/python3.13
COPY --from=python-base /usr/local/bin /usr/local/bin

# Install OpenGrep (musllinux binary for Alpine) and ast-grep
RUN OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v1.22.0/opengrep_musllinux_x86" && \
    ASTGREP_URL="https://github.com/ast-grep/ast-grep/releases/latest/download/ast-grep-x86_64-unknown-linux-musl.tar.gz" && \
    curl -fsSL "$OPENGREP_URL" -o /usr/local/bin/opengrep && \
    chmod +x /usr/local/bin/opengrep && \
    curl -fsSL "$ASTGREP_URL" | tar xz -C /usr/local/bin/

# Copy engine binary (injected at build time by CI)
COPY --chown=zt:zt $ENGINE_BINARY /usr/local/bin/zerotrust

# Copy rules
COPY rules/ /opt/zerotrust/rules/

COPY docker/engine/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER zt
WORKDIR /home/zt

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["scan"]
