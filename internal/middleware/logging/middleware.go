// Package logging provides request/response logging middleware.
//
// Logging is a chi-style http middleware (func(http.Handler) http.Handler).
// It records request method, path, status, and duration once per request.
package logging

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

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
	Logger *zap.Logger
	// RedactedQueryParams, when set, replaces the default set of
	// query-parameter names whose values are redacted in logs.
	// Nil/empty falls back to defaultRedactedQueryParams.
	RedactedQueryParams []string
}

// NewHTTPMiddleware returns chi-compatible middleware that:
//   - generates a request ID if none is already in context,
//   - logs request_started before the handler runs,
//   - logs request_completed (at level matching status code) after,
//   - sets X-Request-ID on the response.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	redacted := cfg.RedactedQueryParams
	if len(redacted) == 0 {
		redacted = defaultRedactedQueryParams
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			requestID, _ := r.Context().Value(middleware.RequestIDKey).(string)
			if requestID == "" {
				requestID = generateRequestID()
			}
			ctx := context.WithValue(r.Context(), middleware.RequestIDKey, requestID)

			logger.Info("request_started",
				zap.String("request_id", requestID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("query", redactQuery(r.URL.RawQuery, redacted)),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
			)

			sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			sr.Header().Set("X-Request-ID", requestID)
			next.ServeHTTP(sr, r.WithContext(ctx))

			fields := []zap.Field{
				zap.String("request_id", requestID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", sr.status),
				zap.Duration("duration", time.Since(start)),
				zap.Int("response_size", sr.written),
			}
			switch {
			case sr.status >= 500:
				logger.Error("request_completed", fields...)
			case sr.status >= 400:
				logger.Warn("request_completed", fields...)
			default:
				logger.Info("request_completed", fields...)
			}
		})
	}
}

// statusRecorder wraps an http.ResponseWriter so the middleware can
// observe the status code and bytes written after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
	wrote   bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.written += n
	return n, err
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
