# ---- stage 1: fetch + compile YARA rules (needs network; final image scans offline) ----
FROM python:3.12-slim-bookworm AS rules
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY scanner/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN git clone --depth 1 https://github.com/Yara-Rules/rules /src/yara-rules \
 && git clone --depth 1 https://github.com/Neo23x0/signature-base /src/signature-base
COPY scanner/compile_rules.py /tmp/compile_rules.py
RUN python /tmp/compile_rules.py

# ---- stage 2: scanner ----
FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends clamav clamav-freshclam p7zip-full libmagic1 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Bake the signature DB into the image so scans run with no network access.
RUN sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true \
 && freshclam --quiet

COPY scanner/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd -m -u 10001 scanner
COPY --from=rules /opt/rules.yarc /opt/rules.yarc
COPY scanner/scan.py scanner/checks.py /app/
USER scanner
WORKDIR /app
ENTRYPOINT ["python", "-I", "/app/scan.py"]
