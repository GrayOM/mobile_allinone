FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
COPY backend/ backend/
COPY scripts/ scripts/
COPY rules/ rules/
COPY --from=frontend /app/frontend/dist frontend/dist
RUN pip install --no-cache-dir .
ENV MSW_HOST=127.0.0.1 \
    MSW_PORT=8765 \
    MSW_DATA_DIR=/data \
    MSW_AUTO_OPEN_BROWSER=false
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:' + __import__('os').environ['MSW_PORT'] + '/healthz', timeout=3).read()" || exit 1
CMD ["sh", "-c", "exec python -m uvicorn backend.app.main:app --host 0.0.0.0 --port \"$MSW_PORT\""]
