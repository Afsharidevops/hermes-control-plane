FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git skopeo && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10020 hermes && useradd --uid 10020 --gid 10020 --create-home hermes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
RUN mkdir -p /data && chown -R 10020:10020 /data /app
USER 10020:10020
EXPOSE 8800
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=5 CMD ["python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8800/health', timeout=3)"]
CMD ["uvicorn","hermes_control_plane.main:app","--host","0.0.0.0","--port","8800"]
