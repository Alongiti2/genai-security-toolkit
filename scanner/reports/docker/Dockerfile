# docker/Dockerfile
# GenAI Security Assessment Toolkit — Container Definition
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College
#
# Security hardening applied:
# - Non-root user execution
# - Minimal base image (slim)
# - No-cache pip install
# - Explicit COPY (no wildcard)
# - Read-only filesystem ready

FROM python:3.11-slim

LABEL maintainer="Delphin A. Zaki <delphinzaki@gmail.com>"
LABEL description="GenAI Security Assessment Toolkit"
LABEL version="1.0"
LABEL org.opencontainers.image.source="https://github.com/Alongiti2/genai-security-toolkit"

# ── Security: create non-root user ───────────────────────────
RUN useradd --create-home \
            --shell /bin/bash \
            --uid 1001 \
            scanner

# ── Set working directory ─────────────────────────────────────
WORKDIR /app

# ── Install dependencies first (layer caching) ───────────────
COPY requirements.txt .
RUN pip install --no-cache-dir \
                --upgrade pip \
                -r requirements.txt

# ── Copy application source ───────────────────────────────────
COPY scanner/ ./scanner/
COPY main.py .

# ── Create reports output directory ──────────────────────────
RUN mkdir -p /app/reports && \
    chown -R scanner:scanner /app

# ── Security: switch to non-root user ────────────────────────
USER scanner

# ── Health check ─────────────────────────────────────────────
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=5s \
            --retries=3 \
            CMD python -c "import scanner.owasp_genai_top10; print('OK')" || exit 1

# ── Default entrypoint ────────────────────────────────────────
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
