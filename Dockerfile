# A1 Agent Guardrail Gateway — container image for Cloud Run (asia-southeast1).
#
# Multi-stage (D4): the builder resolves the locked dependency set into a virtualenv and is
# the only stage that ever carries a build toolchain (git, for the pinned git+https commons
# references). The runtime stage copies that virtualenv into a clean slim base, so no
# compiler, no git and no pip cache reach production.
#
# Builds with the [gcp] extra so the running container can hit Model Armor + DLP.
# Override the entrypoint / GUARDRAIL_PROFILE=local to run without GCP.

# --------------------------------------------------------------------------- builder
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# git is needed only while pip resolves the git+https commons pins (hex-service-kit,
# pii-kit). It stays in this stage and never reaches the runtime image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV"

# Install dependencies first for better layer caching. Locked, reproducible install:
# the committed lockfile pins every transitive dep; install the package itself with
# --no-deps so the lock stays authoritative (matches CI and pip-audit).
COPY pyproject.toml README.md ./
COPY requirements-gcp.lock ./
COPY src ./src
COPY config ./config

RUN pip install -r requirements-gcp.lock \
 && pip install --no-deps .

# --------------------------------------------------------------------------- runtime
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    GUARDRAIL_PROFILE=gcp

WORKDIR /app

# Only the resolved virtualenv and the runtime config cross the stage boundary: no build
# toolchain, no pip cache, no source tree.
COPY --from=builder /opt/venv /opt/venv
COPY config ./config

# Drop privileges.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

# Container-level liveness, alongside the Cloud Run startup / liveness probes in
# infra/terraform/main.tf, so a plain `docker run` is healthchecked too.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/healthz',timeout=2)" || exit 1

# Cloud Run sends $PORT; honour it. uvicorn binds 0.0.0.0 inside the container.
CMD ["sh", "-c", "uvicorn guardrail_gateway.api.app:app --host 0.0.0.0 --port ${PORT}"]
