// Package logging provides request/response logging middleware.
//
// Logging is a chi-style http middleware (func(http.Handler) http.Handler).
// It records request method, path, status, and duration once per request.
package logging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/felixge/httpsnoop"
	"github.com/google/uuid"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// defaultRedactedQueryParams lists the case-insensitive names of query
// parameters whose values must be replaced with "***" before logging.
// Covers the common credential-in-URL idioms (signed URLs, API keys,
// OAuth implicit-flow tokens). Operators can extend via Config.
var defaultRedactedQueryParams = []string{
	"token", "access_token", "refresh_token", "id_token",
	"signature", "sig", "api_key", "apikey", "key", "password",
}

// Config contains configuration for the logging middleware.
type Config struct {
	Logger *slog.Logger
	// RedactedQueryParams, when set, replaces the default set of
	// query-parameter names whose values are redacted in logs.
	// Nil/empty falls back to defaultRedactedQueryParams.
	RedactedQueryParams []string
	// LogRawUserAgent, when true, emits the raw User-Agent string in
	// logs. Default false: the UA is sha256-hashed (8-char prefix) so
	// operators can still bucket by client without retaining the
	// fingerprintable original. Set true for debugging where the
	// raw UA is required.
	LogRawUserAgent bool
}

// NewHTTPMiddleware returns chi-compatible middleware that:
//   - generates a request ID if none is already in context,
//   - logs request_started before the handler runs,
//   - logs request_completed (at level matching status code) after,
//   - sets X-Request-ID on the response.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	redacted := cfg.RedactedQueryParams
	if len(redacted) == 0 {
		redacted = defaultRedactedQueryParams
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID, _ := r.Context().Value(middleware.RequestIDKey).(string)
			if requestID == "" {
				requestID = generateRequestID()
			}
			ctx := context.WithValue(r.Context(), middleware.RequestIDKey, requestID)

			ua := r.UserAgent()
			if !cfg.LogRawUserAgent {
				ua = hashShort(ua)
			}
			// Drop the source port and hash the host to avoid logging
			// a long-lived PII identifier (GDPR). Operators who need
			// the raw IP have it via remote_addr in the access log
			// from the upstream proxy / load balancer.
			remoteHash := hashRemoteAddr(r.RemoteAddr)

			logger.Info("request_started",
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"query", redactQuery(r.URL.RawQuery, redacted),
				"remote_addr_hash", remoteHash,
				"user_agent", ua,
			)

			w.Header().Set("X-Request-ID", requestID)
			m := httpsnoop.CaptureMetrics(next, w, r.WithContext(ctx))

			attrs := []any{
				"request_id", requestID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", m.Code,
				"duration_ms", m.Duration.Milliseconds(),
				"response_size", m.Written,
			}
			switch {
			case m.Code >= 500:
				logger.Error("request_completed", attrs...)
			case m.Code >= 400:
				logger.Warn("request_completed", attrs...)
			default:
				logger.Info("request_completed", attrs...)
			}
		})
	}
}

// redactQuery returns a copy of rawQuery with values for any key in
// names (case-insensitive) replaced by "***". When parsing fails the
// input is treated as opaque and "[unparseable]" is returned so we
// don't leak the unparsed bytes by accident.
func redactQuery(rawQuery string, names []string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[unparseable]"
	}
	for k := range values {
		for _, n := range names {
			if strings.EqualFold(k, n) {
				values[k] = []string{"***"}
				break
			}
		}
	}
	return values.Encode()
}

// generateRequestID returns a UUIDv4 string suitable as a request ID
// when no upstream chain has already provided one.
func generateRequestID() string {
	return uuid.NewString()
}

// hashShort returns the first 8 hex chars of sha256(s), or "" for empty
// input. Stable per input across processes; not a secret-grade HMAC,
// just enough to bucket clients without retaining the original string.
func hashShort(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// hashRemoteAddr strips the ephemeral source port and returns a short
// hash of the host portion. Operators get a stable per-host bucket
// without the raw IP appearing in structured logs.
func hashRemoteAddr(addr string) string {
	if addr == "" {
		return ""
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return hashShort(host)
}
