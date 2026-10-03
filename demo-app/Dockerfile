# ===========================================================================
# XPRisk demo application
#
# This image is the scan target for Trivy. Build it, then let XPRisk assess it:
#
#   docker build -t xprisk-demo-app:latest .
#   docker run --rm -p 5000:5000 xprisk-demo-app:latest
#   curl.exe http://127.0.0.1:5000/health
#
# Security posture of this Dockerfile
# ----------------------------------
# This is the *baseline* image for Phase 2 and is written with reasonable
# hardening: a pinned base, a multi-stage build, a non-root user and a
# HEALTHCHECK. Phase 3 adds a deliberately weakened variant in
# `Dockerfile.vulnerable` so that Checkov and Trivy have a controlled test case
# whose findings are attributable to a known cause.
# ===========================================================================

# --- Stage 1: dependency resolution ---------------------------------------
# Dependencies are installed in their own stage so that the build toolchain and
# pip's own dependency tree are discarded before the runtime image is built.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY app/requirements.txt ./requirements.txt

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

# --- Stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="XPRisk Demo Application" \
      org.opencontainers.image.description="Scan target for the XPRisk framework" \
      org.opencontainers.image.version="0.1.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DEMO_HOST=0.0.0.0 \
    DEMO_PORT=5000 \
    DEMO_SCENARIO=clean \
    DEMO_ENVIRONMENT=development

# Run as an unprivileged user rather than root.
RUN groupadd --system --gid 1001 xprisk \
    && useradd --system --uid 1001 --gid xprisk --no-create-home xprisk

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=xprisk:xprisk app/ ./app/

USER xprisk

EXPOSE 5000

# Uses the interpreter already present in the image, so no curl or wget needs
# to be installed just to support a health probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "app.main"]