# syntax=docker/dockerfile:1.7

# ---- build stage -----------------------------------------------------------
# Pin Go's minor version. Bump deliberately (not via :1.23) so reproducible
# builds don't drift when upstream cuts a new patch tag.
FROM golang:1.25.11-alpine3.22 AS builder

WORKDIR /src

# git is needed for module ops on private replaces; ca-certs for go module
# proxies on HTTPS. Both are dropped from the runtime image.
RUN apk add --no-cache git ca-certificates

# Cache module downloads in their own layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Bring in the source after the module fetch so a single source change
# doesn't bust the module-download cache.
COPY . .

# Build args injected from CI / Makefile so /usr/local/bin/stac-proxy
# --version reports something meaningful instead of "dev/unknown/unknown".
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux \
    go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
        -o /out/stac-proxy ./cmd/stac-proxy

# ---- runtime stage ---------------------------------------------------------
# Pin alpine patch version too. ca-certificates is the only runtime dep
# (TLS to upstream STAC origins); tzdata only if you actually need
# RFC3339-with-named-zone in logs — STAC datetimes are UTC so we skip it.
FROM alpine:3.22.3

RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 65532 -s /sbin/nologin stacproxy

COPY --from=builder /out/stac-proxy /usr/local/bin/stac-proxy

# Read-only example config baked in for quick smoke; production deployments
# mount their own at /etc/stac-proxy/config.yaml.
COPY --chown=stacproxy:stacproxy configs /etc/stac-proxy
COPY --chown=stacproxy:stacproxy policies /etc/stac-proxy/policies

USER 65532:65532
WORKDIR /etc/stac-proxy

EXPOSE 8080

# Self-healthcheck: the binary itself probes /health, so the runtime
# image needs neither wget nor curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/stac-proxy", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/stac-proxy"]
CMD ["--config", "/etc/stac-proxy/example.yaml"]
