FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml config.yaml ./
COPY content_hub ./content_hub

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    useradd --create-home --shell /bin/bash hubuser && \
    mkdir -p /app/workspace && \
    chown -R hubuser:hubuser /app

USER hubuser

EXPOSE 8080

CMD ["python3", "-m", "content_hub.server", "--config", "config.yaml", "--serve"]
