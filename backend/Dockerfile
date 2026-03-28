FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt
RUN addgroup --system ironclad \
 && adduser --system --ingroup ironclad --no-create-home ironclad
COPY app/ ./app/
RUN mkdir -p /app/logs \
 && chown -R ironclad:ironclad /app/logs
USER ironclad
EXPOSE 8080
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "4", "--bind", "0.0.0.0:8080", "--timeout", "120", "--keep-alive", "5", "--log-level", "info", "--access-logfile", "-", "--error-logfile", "-"]
