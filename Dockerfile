# ── Builder stage: install Python dependencies ──────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage: slim image with non-root user ────────────────
FROM python:3.11-slim

ARG SOURCE_COMMIT
RUN test "${#SOURCE_COMMIT}" -eq 40 && case "$SOURCE_COMMIT" in *[!0-9a-fA-F]*) exit 1 ;; esac
ENV SOURCE_COMMIT=${SOURCE_COMMIT}

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 appuser && \
    useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash appuser

COPY --from=builder /install /usr/local

WORKDIR /app
COPY server/ ./server/
COPY .env.example ./.env.example

RUN chown -R appuser:appuser /app
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001:10001

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8080"]
