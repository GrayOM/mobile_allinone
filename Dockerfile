FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY backend/ backend/
COPY scripts/ scripts/
COPY rules/ rules/
COPY --from=frontend /app/frontend/dist frontend/dist
RUN pip install --no-cache-dir .
ENV MSW_HOST=0.0.0.0 \
    MSW_PORT=8765 \
    MSW_DATA_DIR=/data \
    MSW_AUTO_OPEN_BROWSER=false
VOLUME ["/data"]
EXPOSE 8765
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8765"]
