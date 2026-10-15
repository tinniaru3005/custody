# Custody: FastAPI backend + built React console in one image.
#   docker build -t custody .
#   docker run -p 8000:8000 -e CUSTODY_FALKORDB_URL=redis://host:6379 custody

# ---- 1. build the UI ------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. backend -----------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY custody ./custody
COPY scripts ./scripts
RUN pip install ".[warden]" "falkordblite>=0.10"
COPY --from=ui /ui/dist ./frontend/dist
ENV CUSTODY_STATIC_DIR=/app/frontend/dist
RUN useradd --create-home custody
USER custody
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
CMD ["sh", "-c", "uvicorn custody.api.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
