FROM golang:1.26.2-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -o /bin/ncapd ./cmd/checker

FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709 AS runtime

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S ncapd && \
    adduser -S -G ncapd -H ncapd

RUN mkdir -p /etc/ncapd /etc/ncapd/certs /var/log/ncapd && \
    chown -R ncapd:ncapd /etc/ncapd /var/log/ncapd

COPY --from=builder /bin/ncapd /usr/local/bin/ncapd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER ncapd

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --cacert /etc/ssl/certs/ca-certificates.crt https://localhost:8080/healthz || exit 1

LABEL org.opencontainers.image.title="ncapd-checker" \
      org.opencontainers.image.description="Network censorship probing daemon" \
      org.opencontainers.image.vendor="Robert Tkach" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/ncapd"]
CMD ["-config", "/etc/ncapd/config.json"]

# Node ID reported to master via gRPC.
# Overrides server.node_id from the config file.
# Optional: if unset and server.node_id is empty, master submission is skipped.
ENV NCAPD_NODE_ID=""
