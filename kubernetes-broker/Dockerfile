FROM python:3.12-slim
ARG TARGETARCH
ARG KUBECTL_V1_33=v1.33.13
ARG KUBECTL_V1_34=v1.34.10
ARG KUBECTL_V1_35=v1.35.6
ARG KUBECTL_V1_36=v1.36.2
ARG KUBECTL_BOOTSTRAP_MINOR=1.34
ARG HELM_VERSION=v4.2.2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src HOME=/tmp/hermes HELM_CACHE_HOME=/tmp/hermes/helm/cache HELM_CONFIG_HOME=/tmp/hermes/helm/config HELM_DATA_HOME=/tmp/hermes/helm/data HERMES_KUBECTL_ROOT=/opt/hermes/kubectl HERMES_KUBECTL_BOOTSTRAP=/usr/local/bin/kubectl HERMES_KUBECTL_SELECTION_MODE=exact-preferred HERMES_DYNAMIC_KUBECTL_ENABLED=true
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar gzip \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/hermes/kubectl/1.33 /opt/hermes/kubectl/1.34 /opt/hermes/kubectl/1.35 /opt/hermes/kubectl/1.36 \
 && curl -fsSLo /opt/hermes/kubectl/1.33/kubectl "https://dl.k8s.io/release/${KUBECTL_V1_33}/bin/linux/${TARGETARCH}/kubectl" \
 && curl -fsSLo /opt/hermes/kubectl/1.34/kubectl "https://dl.k8s.io/release/${KUBECTL_V1_34}/bin/linux/${TARGETARCH}/kubectl" \
 && curl -fsSLo /opt/hermes/kubectl/1.35/kubectl "https://dl.k8s.io/release/${KUBECTL_V1_35}/bin/linux/${TARGETARCH}/kubectl" \
 && curl -fsSLo /opt/hermes/kubectl/1.36/kubectl "https://dl.k8s.io/release/${KUBECTL_V1_36}/bin/linux/${TARGETARCH}/kubectl" \
 && chmod 0755 /opt/hermes/kubectl/*/kubectl \
 && ln -s "/opt/hermes/kubectl/${KUBECTL_BOOTSTRAP_MINOR}/kubectl" /usr/local/bin/kubectl \
 && curl -fsSLo /tmp/helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
 && tar -xzf /tmp/helm.tgz -C /tmp \
 && mv "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm \
 && chmod 0755 /usr/local/bin/helm \
 && rm -rf /tmp/helm.tgz "/tmp/linux-${TARGETARCH}"
RUN groupadd --gid 10023 hermes && useradd --uid 10023 --gid 10023 --create-home hermes
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
RUN mkdir -p /credentials/kubeconfigs /tmp/hermes && chown -R 10023:10023 /app /tmp/hermes
USER 10023:10023
EXPOSE 8830
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=5 CMD ["python","-c","import urllib.request; urllib.request.urlopen('http://127.0.0.1:8830/health', timeout=3)"]
CMD ["uvicorn","hermes_kubernetes_broker.main:app","--host","0.0.0.0","--port","8830"]
