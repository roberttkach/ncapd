# ncapd — Network Connectivity and Probing Daemon

ncapd is a specialized daemon for monitoring and analyzing network interactions. The service performs periodic probes
against target hosts, detects network interference (DNS filtering, RST injection, SNI inspection, TLS fingerprinting,
throttling), and delivers results to a central master system via gRPC.

ncapd operates as a **gRPC client agent only** — it requires a master server implementing the
`ncapd.ProbeService.Submit` RPC to receive results.

---

## Architecture

```
┌────────────────────────────────────────────────┐
│                  ncapd Agent                   │
│                                                │
│  ┌──────────┐   ┌──────────┐   ┌────────────┐  │
│  │Scheduler │──▶│ Adapters │──▶│ In-Memory  │  │
│  │ (cron)   │   │ (probes) │   │ Results    │  │
│  └──────────┘   └──────────┘   └─────┬──────┘  │
│                                      │         │
│  HTTP API ◀──────────┐    gRPC ──────┘         │
│  (status, metrics,   │    (submit to           │
│   manual run)        │     master server)      │
└──────────────────────┼─────────────────────────┘
                       │
              ┌────────▼────────┐
              │  Master Server  │
              │  (external)     │
              │  ProbeService   │
              └─────────────────┘
```

### Components

| Component         | Description                                                                      |
|-------------------|----------------------------------------------------------------------------------|
| **Core**          | Probe dispatcher, result aggregation (`internal/core`)                           |
| **Scheduler**     | Cron-based planner via `robfig/cron` (`internal/scheduler`)                      |
| **Adapters**      | Pluggable probe modules — `net`, `tls`, `http` (`internal/adapter`)              |
| **Master Client** | gRPC client for batch submission to external master (`internal/adapter/master`)  |
| **HTTP API**      | REST interface for manual execution, results, and Prometheus metrics (`pkg/api`) |

### Probe Types

| Type                 | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| `port_blocking`      | TCP port availability via dial.                                    |
| `ip_blocking`        | Connectivity check against specific IP.                            |
| `dns_filtering`      | DNS resolution; detects NXDOMAIN / no-result.                      |
| `rst_injection`      | Detects RST injection during TCP connect.                          |
| `sni_inspection`     | Full TLS handshake with SNI; detects SNI-based blocking.           |
| `tls_fingerprint`    | TLS handshake with Chrome cipher suite; fingerprint-only blocking. |
| `protocol_detection` | Dual probe (HTTPS vs gRPC URL); detects DPI protocol filtering.    |
| `throttling`         | HTTP Range request; flags throughput below 10 KB/s.                |
| `active_probing`     | Fetches fallback URL; verifies HTML content vs block page.         |

---

## Project Structure

| Path                  | Description                                    |
|-----------------------|------------------------------------------------|
| `cmd/checker/`        | Application entrypoint                         |
| `internal/core/`      | Core types, Dispatcher, service, error helpers |
| `internal/adapter/`   | Probe adapters and master gRPC client          |
| `internal/scheduler/` | Cron-based check scheduler                     |
| `internal/config/`    | JSON configuration parsing                     |
| `internal/validate/`  | Input validation and SSRF prevention           |
| `pkg/api/`            | HTTP REST server                               |
| `proto/`              | `.proto` definitions and generated gRPC code   |
| `config/`             | Example configuration files                    |

---

## Configuration

ncapd is configured via a JSON file, passed through the `-config` flag.

```bash
./bin/ncapd -config config/example.json
```

### Prerequisites Before Launch

1. **Register `node_id`** — the master system must recognize the node identifier.
2. **Set `master_addr`** — gRPC address of the master server (leave empty to disable submission).
3. **Define checks** — each check requires a unique `id`, `type`, `target`, and `schedule`.

### Core Parameters

| Parameter            | Default         | Description                                                                |
|----------------------|-----------------|----------------------------------------------------------------------------|
| `server.addr`        | `:8080`         | HTTP API listen address.                                                   |
| `server.master_addr` | `""` (disabled) | gRPC address of the master server.                                         |
| `server.node_id`     | `""`            | Node identifier reported to master. Overridden by `NCAPD_NODE_ID` env var. |
| `log.level`          | `info`          | Log level (`debug`, `info`, `warn`, `error`).                              |
| `scheduler.enabled`  | `true`          | Enable periodic check execution.                                           |

> **Environment:** `NCAPD_NODE_ID` overrides `server.node_id`. Optional.

### Security Parameters

| Parameter           | Default  | Required  | Description                                                |
|---------------------|----------|-----------|------------------------------------------------------------|
| `server.auth`       | `none`   | Optional  | Auth: `api_key` or `bearer_token`.                         |
| `server.tls`        | disabled | Optional  | HTTPS with TLS 1.2+, mTLS via `client_ca_file`.            |
| `server.master_tls` | disabled | Optional  | gRPC TLS to master server.                                 |
| `server.rate_limit` | disabled | Optional  | Per-IP token bucket rate limiter.                          |
| `server.audit`      | disabled | Optional  | Audit log per request.                                     |
| SSRF protection     | —        | Always on | Blocks `fallback_url` to private/link-local/metadata IPs.  |
| Target validation   | —        | Always on | Validates `host`, `ip`, `port` at config load and runtime. |

### Checks (`checks[]`)

| Field      | Description                                                    |
|------------|----------------------------------------------------------------|
| `id`       | Unique check identifier. No duplicates.                        |
| `type`     | Probe type (see Probe Types table).                            |
| `target`   | Target spec: `host`, `ip`, `port`, `sni`, `fallback_url`, etc. |
| `timeout`  | Execution timeout (`5s`, `10s`, `30s`).                        |
| `schedule` | Cron expression or interval (`@every 10s`).                    |

### Example

```json
{
  "server": {
    "addr": ":8080",
    "master_addr": "master.internal:50051",
    "node_id": "node-01"
  },
  "log": {
    "level": "info"
  },
  "scheduler": {
    "enabled": true
  },
  "checks": [
    {
      "id": "example_port_443",
      "type": "port_blocking",
      "target": {
        "host": "example.com",
        "port": 443,
        "proto": "tcp"
      },
      "timeout": "5s",
      "schedule": "@every 30s"
    }
  ]
}
```

Full example: [`config/example.json`](config/example.json)

---

## Integration with Master

ncapd submits probe results to an external master system via gRPC. It does **not** serve gRPC — it only acts as a
client.

### Contract

- **Service:** `ncapd.ProbeService`
- **Method:** `Submit(SubmitRequest) → SubmitResponse`
- **Proto:** [`proto/probe.proto`](proto/probe.proto)

```protobuf
message SubmitRequest {
  string node_id = 1;
  repeated ProbeResult results = 2;
}

message ProbeResult {
  string id = 1;
  string type = 8;
  string target_host = 2;
  string status = 3;
  int64 latency_ns = 4;
  double throughput_bps = 5;
  string detail = 6;
  string error = 7;
  google.protobuf.Timestamp at = 9;
}

message SubmitResponse {
  bool success = 1;
  string error = 2;
}
```

### Submission Flow

- **Initial Pass:** On startup, all checks run once, then the full batch is submitted to master.
- **Scheduled Pass:** After each check execution, its result is submitted individually.
- **No retry / buffering:** If master is unreachable, submission is logged at `debug` level and dropped. ncapd does not
  queue or retry — the master is expected to pull missed data from the HTTP `/results` endpoint if needed.
- **Empty `node_id`:** Submission is skipped silently.

---

## HTTP API

### `GET /healthz`

Liveness probe. Returns `{"status": "ok"}`.

### `GET /metrics`

Prometheus metrics. Go runtime, GC, goroutines, and custom probe metrics:

| Metric                                    | Type      | Labels                             |
|-------------------------------------------|-----------|------------------------------------|
| `ncapd_check_total`                       | counter   | `check_id`, `check_type`, `status` |
| `ncapd_check_duration_seconds`            | histogram | `check_id`, `check_type`           |
| `ncapd_check_blocked`                     | gauge     | `check_id`, `check_type`           |
| `ncapd_check_throughput_bytes_per_second` | gauge     | `check_id`, `check_type`           |

### `GET /results`

Latest results for all executed checks.

```json
[
  {
    "request_id": "example_port_443",
    "type": "port_blocking",
    "status": "ok",
    "checked_at": "2024-01-01T12:00:00Z",
    "latency_ns": 199229342,
    "detail": "connected to example.com:443",
    "target_host": "example.com"
  }
]
```

### `GET /results/{id}`

Result for a specific check.

| Code  | Description             |
|-------|-------------------------|
| `200` | Result found.           |
| `404` | No result for given id. |

### `GET /checks`

Lists all registered checks.

```json
[
  {
    "id": "check1",
    "type": "port_blocking",
    "schedule": "@every 10s"
  }
]
```

### `POST /checks/{id}/run`

Manually triggers a check.

| Code  | Description      |
|-------|------------------|
| `200` | Check executed.  |
| `404` | Check not found. |

Returns the full `Result` JSON:

```json
{
  "request_id": "check1",
  "type": "port_blocking",
  "status": "ok",
  "checked_at": "2024-01-01T12:00:00Z",
  "latency_ns": 199229342,
  "detail": "connected to example.com:443",
  "target_host": "example.com"
}
```

---

## Internal Flow

### 1. Probe Execution

Each adapter implements `core.Dispatcher.Check(ctx, req) → Result`. Result contains status (`ok`, `blocked`, `timeout`,
`error`), latency (ns), and diagnostic detail. Probe execution uses the configured timeout (default `10s`).
Manual runs via `POST /checks/{id}/run` use a hardcoded `30s` timeout.

### 2. Result Storage

Results are stored in-memory (concurrent map, `RWMutex`). Thread-safe access via `AllResults()` / `GetResult(id)`. Only
the latest result per check id is retained. No persistence to disk.

### 3. Master Submission

Batch submission is used only on startup for the initial pass. Scheduled checks submit their result individually. Both
use a 10s timeout. Failures are logged at `debug` and silently dropped.

---

## Observability

### Logging

- **Format:** JSON (Zap production encoder, ISO8601).
- **Levels:** `debug`, `info`, `warn`, `error`.
- **Content:** Each probe logged with `id`, `type`, `status`, `latency_ns`.

### Status Codes

| Status    | Description                                            |
|-----------|--------------------------------------------------------|
| `ok`      | Probe completed successfully.                          |
| `blocked` | Blocking detected (RST, SNI reject, connection reset). |
| `timeout` | Exceeded configured timeout.                           |
| `error`   | Execution error (invalid request, no adapter).         |

---

## Deployment

ncapd is deployed as a Docker container.

### Prerequisites

- **OS:** Linux with Docker.
- **Network:** Outbound access to target hosts and master server.
- **Master:** gRPC server accepting `ncapd.ProbeService.Submit` (optional — ncapd runs without it but does not submit
  results).

### Before Launch

1. Register a `node_id` in the master system.
2. Set `server.master_addr` and `server.node_id` in the config.
3. Define the `checks` array with target hosts and schedules.

### Docker

```bash
docker build -t ncapd .
docker run -d --name ncapd -p 8080:8080 \
  -v /path/to/config.json:/etc/ncapd/config.json:ro \
  -e NCAPD_NODE_ID="node-01" \
  ncapd
```

> **Note:** The Dockerfile includes a HEALTHCHECK that probes `https://localhost:8080/healthz`.
> This requires TLS to be configured (`server.tls.cert_file` + `server.tls.key_file`). Without TLS,
> the container will report `unhealthy`.

For master on host network:

```bash
docker run -d --name ncapd -p 8080:8080 \
  --add-host=host.docker.internal:host-gateway \
  -v /path/to/config.json:/etc/ncapd/config.json:ro \
  -e NCAPD_NODE_ID="node-01" \
  ncapd
```

---

## Development

### Build

```bash
go build -o bin/ncapd ./cmd/checker
```

### Run (local)

```bash
./bin/ncapd -config config/example.json
```

### Tests

Unit and integration tests (117 unit tests + 44 integration checks: auth, TLS/mTLS, rate limit, probes, scheduler,
graceful shutdown).

```bash
chmod +x ci.sh
./ci.sh                     # full cycle: build → vet → fmt → unit tests → integration tests
```

```bash
./ci.sh --unit-only         # unit tests only
./ci.sh --integration-only  # integration tests only
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details. © 2026 Robert Tkach.
