FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates ipmitool \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10022 hermes \
    && useradd --uid 10022 --gid 10022 --create-home hermes \
    && mkdir -p /var/lib/hermes-provider /credentials/ssh /credentials/infrastructure \
    && chown -R 10022:10022 /var/lib/hermes-provider /credentials/ssh /credentials/infrastructure
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY playbooks ./playbooks
USER 10022:10022
EXPOSE 8810
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=5 CMD ["python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8810/health', timeout=3)"]
CMD ["uvicorn","hermes_node_agent.main:app","--host","0.0.0.0","--port","8810"]
