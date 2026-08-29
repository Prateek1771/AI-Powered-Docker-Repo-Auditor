FROM python:3.12-slim

RUN adduser --system --no-create-home --group appuser

WORKDIR /app

COPY --chown=appuser:appuser app.py .

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python", "-c", "import sys; sys.exit(0)"]

CMD ["python", "app.py"]
