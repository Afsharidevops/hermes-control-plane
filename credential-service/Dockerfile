FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN useradd --system --uid 10001 --create-home hermes
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
RUN mkdir -p /data && chown -R hermes:hermes /data /app
USER 10001:10001
EXPOSE 8082
CMD ["uvicorn", "hermes_credential_service.main:app", "--host", "0.0.0.0", "--port", "8082"]
