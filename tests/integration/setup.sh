#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

echo "=== Generating integration test certificates ==="

mkdir -p "${CERTS_DIR}"

# CA for ncapd client auth (mTLS)
echo "[1/4] Generating client CA..."
openssl genrsa -out "${CERTS_DIR}/ncapd-client-ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "${CERTS_DIR}/ncapd-client-ca.key" \
    -sha256 -days 3650 -out "${CERTS_DIR}/ncapd-client-ca.crt" \
    -subj "/CN=ncapd-client-ca" 2>/dev/null

# ncapd server TLS cert
echo "[2/4] Generating ncapd server certificate..."
openssl genrsa -out "${CERTS_DIR}/ncapd-server.key" 2048 2>/dev/null
openssl req -new -key "${CERTS_DIR}/ncapd-server.key" \
    -out "${CERTS_DIR}/ncapd-server.csr" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "${CERTS_DIR}/ncapd-server.csr" \
    -CA "${CERTS_DIR}/ncapd-client-ca.crt" \
    -CAkey "${CERTS_DIR}/ncapd-client-ca.key" \
    -CAcreateserial -out "${CERTS_DIR}/ncapd-server.crt" \
    -days 3650 -sha256 \
    -copy_extensions copyall 2>/dev/null

# ncapd client cert (for mTLS tests)
echo "[3/4] Generating ncapd client certificate..."
openssl genrsa -out "${CERTS_DIR}/ncapd-client.key" 2048 2>/dev/null
openssl req -new -key "${CERTS_DIR}/ncapd-client.key" \
    -out "${CERTS_DIR}/ncapd-client.csr" \
    -subj "/CN=ncapd-test-client" 2>/dev/null
openssl x509 -req -in "${CERTS_DIR}/ncapd-client.csr" \
    -CA "${CERTS_DIR}/ncapd-client-ca.crt" \
    -CAkey "${CERTS_DIR}/ncapd-client-ca.key" \
    -CAcreateserial -out "${CERTS_DIR}/ncapd-client.crt" \
    -days 3650 -sha256 2>/dev/null

# mock-grpc server TLS cert
echo "[4/4] Generating mock-grpc server certificate..."
openssl genrsa -out "${CERTS_DIR}/mock-grpc-server.key" 2048 2>/dev/null
openssl req -new -key "${CERTS_DIR}/mock-grpc-server.key" \
    -out "${CERTS_DIR}/mock-grpc-server.csr" \
    -subj "/CN=mock-grpc" \
    -addext "subjectAltName=DNS:mock-grpc,DNS:localhost,IP:127.0.0.1" 2>/dev/null
openssl x509 -req -in "${CERTS_DIR}/mock-grpc-server.csr" \
    -CA "${CERTS_DIR}/ncapd-client-ca.crt" \
    -CAkey "${CERTS_DIR}/ncapd-client-ca.key" \
    -CAcreateserial -out "${CERTS_DIR}/mock-grpc-server.crt" \
    -days 3650 -sha256 \
    -copy_extensions copyall 2>/dev/null

# Cleanup temp files
rm -f "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*.srl

chmod 644 "${CERTS_DIR}"/*.key

echo "=== Certificates generated in ${CERTS_DIR} ==="
ls -la "${CERTS_DIR}"

echo ""
echo "=== Building Docker images ==="

echo "[1/2] Building ncapd image..."
docker build -t ncapd-integration:latest -f "${SCRIPT_DIR}/../../Dockerfile" "${SCRIPT_DIR}/../.."

echo "[2/2] Building mock-grpc image..."
docker build -t ncapd-mock-grpc:latest -f "${SCRIPT_DIR}/mock_grpc/Dockerfile" "${SCRIPT_DIR}/../.."

echo "=== Docker images built ==="
docker images | grep -E "ncapd-integration|ncapd-mock-grpc"
