FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY tests/integration/mock_grpc/main.go ./tests/integration/mock_grpc/
COPY proto/ ./proto/

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /bin/mock-grpc ./tests/integration/mock_grpc

FROM alpine:3.20 AS runtime
COPY --from=builder /bin/mock-grpc /usr/local/bin/mock-grpc
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/mock-grpc"]
