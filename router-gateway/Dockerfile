FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
RUN groupadd --gid 10021 hermes && useradd --uid 10021 --gid 10021 --create-home hermes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
RUN mkdir -p /data && chown -R 10021:10021 /data /app
USER 10021:10021
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=5 CMD ["python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=3)"]
CMD ["uvicorn","router_gateway.main:app","--host","0.0.0.0","--port","8090"]
