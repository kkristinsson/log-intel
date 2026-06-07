FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmaxminddb0 \
    systemd \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY log_intel ./log_intel
COPY config ./config

RUN pip install --no-cache-dir .

ENV LOG_INTEL_DATA_DIR=/data
ENV DATA_DIR=/data
ENV LOG_INTEL_SQLITE_PATH=/data/events.sqlite
ENV LOG_INTEL_GEOIP_MMDB_PATH=/geoip/dbip-city-lite.mmdb
ENV LOG_INTEL_HTTP_HOST=0.0.0.0
ENV LOG_INTEL_HTTP_PORT=9088
ENV LOG_INTEL_SYSLOG_UDP_PORT=514
ENV LOG_INTEL_SYSLOG_TCP_PORT=514
ENV APP_NAME=log-intel

EXPOSE 514/udp 514/tcp 9088/tcp

CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "8", "--timeout", "600", "-b", "0.0.0.0:9088", "--access-logfile", "-", "--error-logfile", "-", "log_intel.wsgi:application"]
