FROM golang:1.22 AS osv_builder

ARG OSV_VERSION=1.7.2
RUN GOBIN=/out go install github.com/google/osv-scanner/cmd/osv-scanner@v${OSV_VERSION}

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
  && rm -rf /var/lib/apt/lists/*

COPY --from=osv_builder /out/osv-scanner /usr/local/bin/osv-scanner
RUN chmod +x /usr/local/bin/osv-scanner

ARG VULNAPI_VERSION=0.8.10
RUN curl -fsSL -o /tmp/vulnapi.deb \
    https://github.com/cerberauth/vulnapi/releases/download/v${VULNAPI_VERSION}/vulnapi_${VULNAPI_VERSION}_linux_amd64.deb \
  && apt-get update && apt-get install -y --no-install-recommends /tmp/vulnapi.deb \
  && rm /tmp/vulnapi.deb \
  && rm -rf /var/lib/apt/lists/*

ARG NUCLEI_VERSION=3.2.1
RUN curl -fsSL -o /tmp/nuclei.zip \
    https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip \
  && unzip /tmp/nuclei.zip -d /usr/local/bin \
  && rm /tmp/nuclei.zip \
  && chmod +x /usr/local/bin/nuclei \
  && nuclei -update-templates

COPY worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN pip install --no-cache-dir wapiti3

COPY worker/app /app/app
COPY shared /app/shared

CMD ["python", "-m", "app.main"]
