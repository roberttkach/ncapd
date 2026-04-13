FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -o /bin/ncapd ./cmd/checker

FROM alpine:3.20 AS runtime

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S ncapd && \
    adduser -S -G ncapd -H ncapd

RUN mkdir -p /etc/ncapd /etc/ncapd/certs /var/log/ncapd && \
    chown -R ncapd:ncapd /etc/ncapd /var/log/ncapd

COPY --from=builder /bin/ncapd /usr/local/bin/ncapd

USER ncapd

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost:8080/healthz || exit 1

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
