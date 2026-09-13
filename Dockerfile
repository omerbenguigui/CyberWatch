FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERWATCH_ENV=production \
    CYBERWATCH_DATABASE_PATH=/app/data/cyberwatch.db

WORKDIR /app

RUN addgroup --system cyberwatch && adduser --system --ingroup cyberwatch cyberwatch

COPY pyproject.toml README.md ./
COPY app ./app
COPY scripts ./scripts
RUN pip install --no-cache-dir .

RUN mkdir -p /app/data && chown -R cyberwatch:cyberwatch /app
USER cyberwatch

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

