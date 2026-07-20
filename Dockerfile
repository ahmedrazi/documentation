# NX-OS Compliance Checker -- minimal image for the single-box deployment.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="nxos-compliance-checker" \
      org.opencontainers.image.description="Automated NX-OS security compliance auditing with NDJSON/Splunk output"

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY policy/ ./policy/

# Configs and output are provided/collected via bind mounts at runtime.
VOLUME ["/configs", "/output"]

ENTRYPOINT ["python3", "src/nxos_compliance_checker.py"]
# Default: scan mounted configs, emit NDJSON for Splunk into the shared volume.
CMD ["--config-dir", "/configs", "--policy", "policy/nxos_policy.yaml", \
     "--format", "ndjson", "--output", "/output/compliance.ndjson"]
