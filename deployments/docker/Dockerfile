# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o stac-proxy ./cmd/stac-proxy

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' stacproxy

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/stac-proxy /usr/local/bin/stac-proxy

# Copy example configs
COPY --from=builder /app/configs /app/configs

# Set ownership
RUN chown -R stacproxy:stacproxy /app

USER stacproxy

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["stac-proxy"]
CMD ["--config", "/app/configs/example.yaml"]
