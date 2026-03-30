#!/bin/bash
# Startup script for the Cobra Scenario 9 GCP compute instance.
# Installs Docker and runs a vulnerable ping web app container.
# Optionally installs the Cortex XDR agent (when includeAgent is enabled).
#
# SAFETY GUARD: This script will only run on the expected GCP instance.
# If the hostname does not match, the script exits immediately.

EXPECTED_HOSTNAME="cobra-scenario-9-instance"
CURRENT_HOSTNAME=$(hostname)

if [ "$CURRENT_HOSTNAME" != "$EXPECTED_HOSTNAME" ]; then
    echo "ERROR: Hostname mismatch. Expected '$EXPECTED_HOSTNAME', got '$CURRENT_HOSTNAME'."
    echo "This script is intended to run only on the Cobra Scenario 9 GCP instance."
    echo "Exiting to prevent accidental execution on a local or unrelated machine."
    exit 1
fi

set -e

# Redirect all stdout and stderr to a log file for debugging
LOG_FILE="/var/log/cobra-startup-script.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== Cobra Scenario 9 startup script started at $(date -u) ==="

# Install dependencies
apt-get update -y
apt-get install -y docker.io unzip

# __AGENT_INSTALL_BLOCK__

# Start Docker
systemctl start docker
systemctl enable docker

# Create the application directory
mkdir -p /opt/ping-app

# Write the vulnerable Flask application
cat > /opt/ping-app/app.py << 'FLASK_APP'
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    address = request.args.get('address', '')
    if not address:
        return jsonify({
            'error': 'Missing required parameter: address',
            'usage': 'GET /ping?address=<target>'
        }), 400

    # INTENTIONALLY VULNERABLE - No input sanitization
    # This allows OS command injection via the address parameter
    result = subprocess.Popen(
        f'ping -c 4 {address}',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = result.communicate()
    return jsonify({
        'command': f'ping -c 4 {address}',
        'stdout': stdout.decode('utf-8', errors='replace'),
        'stderr': stderr.decode('utf-8', errors='replace'),
        'returncode': result.returncode
    })

@app.route('/', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
FLASK_APP

# Write the Dockerfile
cat > /opt/ping-app/Dockerfile << 'DOCKERFILE'
FROM python:3.12-slim

RUN apt-get update && apt-get install -y iputils-ping curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask

WORKDIR /app
COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
DOCKERFILE

# Build and run the container
cd /opt/ping-app
docker build -t cobra-ping-app .
docker run -d \
    --name cobra-ping-app \
    --restart always \
    -p 8080:8080 \
    cobra-ping-app

echo "=== Cobra Scenario 9 startup script completed at $(date -u) ==="
echo "Log file: $LOG_FILE"
echo "Docker container status: $(docker ps --filter name=cobra-ping-app --format '{{.Status}}')"
