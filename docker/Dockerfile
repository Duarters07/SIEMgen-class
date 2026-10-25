# SIEMgen — realistic synthetic security logs, written as native log files.
#
#   docker compose up            (from the repository root; see docker-compose.yml)
#
# The container runs as an unprivileged user and writes ONLY to /logs, which the
# compose file bind-mounts to ./logs on the host so any collector can tail it.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEMGEN_OUT=/logs \
    SIEMGEN_CONFIG=/app/config/classroom.yaml

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY siemgen ./siemgen
COPY config ./config
RUN pip install --no-cache-dir . \
    && mkdir -p /logs \
    && chmod 0777 /logs

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Starts as root only to take ownership of the bind-mounted /logs, then drops to
# PUID:PGID (default 1000:1000) via setpriv before running the generator.
VOLUME ["/logs"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
