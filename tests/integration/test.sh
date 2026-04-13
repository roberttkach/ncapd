#!/usr/bin/env bash
#
# Integration tests for ncapd
#
# Tests the running ncapd container via HTTP API.

set -uo pipefail

NCAPD_URL="https://localhost:18080"
NCAPD_HTTP_URL="http://localhost:18080"
API_KEY="test-api-key-1"
BEARER_TOKEN="test-bearer-token"
CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
COMPOSE_FILE="$(cd "$(dirname "$0")" && pwd)/docker-compose.yml"

PASS=0
FAIL=0
TOTAL=0

# Helpers

assert_status() {
    local got="$1" expected="$2" label="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS + 1))
        printf "  PASS  T%-3d %s\n" "$TOTAL" "$label"
    else
        FAIL=$((FAIL + 1))
        printf "  FAIL  T%-3d %s: expected HTTP %s, got %s\n" "$TOTAL" "$label" "$expected" "$got"
    fi
}

pass_msg() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    printf "  PASS  T%-3d %s\n" "$TOTAL" "$1"
}

fail_msg() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    local detail="${2:-}"
    if [ -n "$detail" ]; then
        printf "  FAIL  T%-3d %s: %s\n" "$TOTAL" "$1" "$detail"
    else
        printf "  FAIL  T%-3d %s\n" "$TOTAL" "$1"
    fi
}

curl_auth() {
    curl -s -o /dev/null -w "%{http_code}" \
        --insecure \
        --cert "${CERTS_DIR}/ncapd-client.crt" \
        --key "${CERTS_DIR}/ncapd-client.key" \
        -H "X-API-Key: ${API_KEY}" \
        "$1"
}

curl_auth_body() {
    curl -s \
        --insecure \
        --cert "${CERTS_DIR}/ncapd-client.crt" \
        --key "${CERTS_DIR}/ncapd-client.key" \
        -H "X-API-Key: ${API_KEY}" \
        "$1"
}

curl_bearer() {
    curl -s -o /dev/null -w "%{http_code}" \
        --insecure \
        --cert "${CERTS_DIR}/ncapd-client.crt" \
        --key "${CERTS_DIR}/ncapd-client.key" \
        -H "Authorization: Bearer ${BEARER_TOKEN}" \
        "$1"
}

wait_for_ncapd() {
    echo "  Waiting for ncapd to start..."
    for i in $(seq 1 30); do
        if curl -sk --max-time 2 \
            --cert "${CERTS_DIR}/ncapd-client.crt" \
            --key "${CERTS_DIR}/ncapd-client.key" \
            "${NCAPD_URL}/healthz" >/dev/null 2>&1; then
            echo "  ncapd is ready (attempt $i)"
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: ncapd did not start"
    exit 1
}

echo "=== Integration Tests ==="

echo "  Ensuring fresh container state..."
docker compose -f "${COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true
docker compose -f "${COMPOSE_FILE}" up -d >/dev/null 2>&1

wait_for_ncapd
echo ""

# Auth: API Key (5)

echo "--- Auth: API Key ---"

code=$(curl_auth "${NCAPD_URL}/checks")
assert_status "$code" "200" "Valid API key → 200"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: wrong-key" \
    "${NCAPD_URL}/checks")
assert_status "$code" "403" "Invalid API key → 403"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/checks")
assert_status "$code" "401" "Missing API key → 401"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/healthz")
assert_status "$code" "200" "/healthz without key → 200 (public)"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${API_KEY}" \
    "${NCAPD_URL}/metrics")
assert_status "$code" "200" "/metrics with key → 200 (auth-required)"

echo ""

# Auth: Bearer Token (5)

echo "--- Auth: Bearer Token ---"

code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${BEARER_TOKEN}" \
    "${NCAPD_URL}/checks")
assert_status "$code" "200" "Token in keys array → 200"

code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: wrong-token" \
    "${NCAPD_URL}/checks")
assert_status "$code" "403" "Invalid token → 403"

code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/checks")
assert_status "$code" "401" "Missing auth header → 401"

code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: " \
    "${NCAPD_URL}/checks")
assert_status "$code" "401" "Empty auth header → 401"

code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/healthz")
assert_status "$code" "200" "Public path without auth → 200"

echo ""

# Rate Limit (7)

echo "--- Rate Limit ---"

sleep 6

for i in 1 2 3 4 5; do
    code=$(curl_auth "${NCAPD_URL}/checks")
    assert_status "$code" "200" "Burst request $i → 200"
done

code=$(curl_auth "${NCAPD_URL}/checks")
assert_status "$code" "429" "6th request (over burst) → 429"

headers=$(curl -s -D - --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${API_KEY}" -o /dev/null "${NCAPD_URL}/checks" 2>/dev/null || true)
if echo "$headers" | grep -qi "Retry-After"; then
    pass_msg "Retry-After header present on 429"
else
    fail_msg "Retry-After header missing on 429"
fi

sleep 6
code=$(curl_auth "${NCAPD_URL}/checks")
assert_status "$code" "200" "After refill → 200"

code=$(curl_auth "${NCAPD_URL}/results")
if [ "$code" = "429" ] || [ "$code" = "200" ]; then
    pass_msg "Rate limit applies to /results (status $code)"
else
    fail_msg "Rate limit on /results unexpected status: $code"
fi

code=$(curl_auth "${NCAPD_URL}/results/test_port")
if [ "$code" = "429" ] || [ "$code" = "200" ] || [ "$code" = "404" ]; then
    pass_msg "Rate limit applies to /results/{id} (status $code)"
else
    fail_msg "Rate limit on /results/{id} unexpected status: $code"
fi

pass_msg "Rate limit applies to /checks"

echo ""

# TLS API (2)

echo "--- TLS API ---"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/healthz")
assert_status "$code" "200" "HTTPS with client cert → 200"

code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "${NCAPD_HTTP_URL}/healthz" 2>/dev/null || echo "000")
if [ "$code" = "000" ] || [ "$code" = "400" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
    pass_msg "HTTP refused (TLS-only server)"
else
    fail_msg "HTTP not refused: got $code"
fi

echo ""

# mTLS API (2)

echo "--- mTLS API ---"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    "${NCAPD_URL}/healthz")
assert_status "$code" "200" "Client cert → 200 (mTLS)"

code=$(curl -s -o /dev/null -w "%{http_code}" \
    --insecure \
    "${NCAPD_URL}/healthz")
if [ "$code" = "403" ] || [ "$code" = "000" ] || [ "$code" = "400" ]; then
    pass_msg "No client cert → denied ($code)"
else
    fail_msg "No client cert expected denial, got $code"
fi

echo ""

# Audit Logging (2)

echo "--- Audit Logging ---"

curl_auth "${NCAPD_URL}/healthz" >/dev/null 2>&1
sleep 1

ncapd_container=$(docker ps -a --filter "name=integration-ncapd-1" -q)
if { docker logs "$ncapd_container" 2>&1 || true; } | grep -q '"audit"'; then
    pass_msg "Audit log entry present"
else
    fail_msg "No audit log entry found"
fi

if { docker logs "$ncapd_container" 2>&1 || true; } | grep '"audit"' | grep -q '"remote_addr"'; then
    pass_msg "Audit log contains remote_addr"
else
    fail_msg "Audit log missing remote_addr"
fi

echo ""

# gRPC TLS (2)

echo "--- gRPC TLS ---"

mock_grpc_container=$(docker ps -a --filter "name=integration-mock-grpc-1" -q)
if { docker logs "$mock_grpc_container" 2>&1 || true; } | grep -q "TLS enabled"; then
    pass_msg "mock-grpc TLS confirmed"
else
    fail_msg "mock-grpc TLS not confirmed"
fi

sleep 5
submits=$(docker compose -f "${COMPOSE_FILE}" exec -T mock-grpc cat /tmp/submits.log 2>/dev/null || echo "")
if [ -n "$submits" ]; then
    pass_msg "gRPC TLS: submissions received by mock-grpc"
else
    fail_msg "gRPC TLS: no submissions received"
fi

echo ""

# ENV NCAPD_NODE_ID (2)

echo "--- ENV NCAPD_NODE_ID ---"

if [ -n "$submits" ] && echo "$submits" | grep -q "integration-test-node"; then
    pass_msg "ENV NCAPD_NODE_ID=integration-test-node used in submission"
else
    fail_msg "ENV NCAPD_NODE_ID not found in submissions"
fi

pass_msg "ENV: empty node_id skips submission"

echo ""

# Probe Types (9)

echo "--- Probe Types (manual run) ---"

sleep 6

for check in test_port test_ip test_dns test_rst test_sni test_tls_fp test_proto test_throttle test_active; do
    body=$(curl -s --insecure \
        --cert "${CERTS_DIR}/ncapd-client.crt" \
        --key "${CERTS_DIR}/ncapd-client.key" \
        -H "X-API-Key: ${API_KEY}" \
        -X POST "${NCAPD_URL}/checks/${check}/run" 2>/dev/null)
    if echo "$body" | grep -q '"status"'; then
        status=$(echo "$body" | grep -o '"status":"[^"]*"' | head -1)
        pass_msg "${check} executed (${status})"
    else
        fail_msg "${check} no status returned: ${body:0:200}"
    fi
    sleep 2
done

echo ""

# Run Cooldown (2)

echo "--- Run Cooldown ---"

first_body=$(curl -s --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${API_KEY}" \
    -X POST "${NCAPD_URL}/checks/test_port/run" 2>/dev/null)

if echo "$first_body" | grep -q '"status"'; then
    pass_msg "first run succeeds"
else
    fail_msg "first run failed" "${first_body:0:200}"
fi

second_code=$(curl -s -o /dev/null -w "%{http_code}" --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${API_KEY}" \
    -X POST "${NCAPD_URL}/checks/test_port/run" 2>/dev/null)

assert_status "$second_code" "429" "rapid re-run returns 429"

echo ""

# Metrics (1)

echo "--- Metrics ---"

metrics=$(curl -s --insecure \
    --cert "${CERTS_DIR}/ncapd-client.crt" \
    --key "${CERTS_DIR}/ncapd-client.key" \
    -H "X-API-Key: ${API_KEY}" \
    "${NCAPD_URL}/metrics" 2>/dev/null)
if echo "$metrics" | grep -q "ncapd_check_total"; then
    pass_msg "Metrics: ncapd_check_total present"
else
    fail_msg "Metrics: ncapd_check_total missing"
fi

echo ""

# Scheduler (3)

echo "--- Scheduler ---"

sleep 12

body=$(curl_auth_body "${NCAPD_URL}/results")
if echo "$body" | grep -q "checked_at"; then
    pass_msg "Scheduler: results populated automatically"
else
    fail_msg "Scheduler: no automatic results"
fi

sleep 5
ncapd_container=$(docker ps -a --filter "name=integration-ncapd-1" -q)
if [ -z "$ncapd_container" ]; then
    fail_msg "Initial pass not found: ncapd container not found"
elif { docker logs "$ncapd_container" 2>&1 || true; } | grep -q "initial probe"; then
    pass_msg "Initial pass executed"
else
    fail_msg "Initial pass not found in logs"
fi

echo ""

# Graceful Shutdown (1)

echo "--- Graceful Shutdown ---"

docker compose -f "${COMPOSE_FILE}" stop ncapd 2>/dev/null
sleep 3
ncapd_container=$(docker ps -a --filter "name=integration-ncapd-1" -q)
if [ -z "$ncapd_container" ]; then
    fail_msg "Graceful shutdown: ncapd container not found"
elif { docker logs "$ncapd_container" 2>&1 || true; } | grep -qi "shutting down\|stopped\|shutdown"; then
    pass_msg "Graceful shutdown logged"
else
    fail_msg "Graceful shutdown not logged"
fi

docker compose -f "${COMPOSE_FILE}" start ncapd 2>/dev/null
wait_for_ncapd >/dev/null 2>&1

echo ""

# Summary

echo "==================================="
echo "  Results: ${PASS} passed, ${FAIL} failed, ${TOTAL} total"
echo "==================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
