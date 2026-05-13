// Package logging provides logging middleware.
package logging

import (
	"context"
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

// Middleware logs requests and responses.
type Middleware struct {
	middleware.BaseMiddleware
	logger          *zap.Logger
	includeBody     bool
	redactedParams  []string
}

// Config contains configuration for the logging middleware.
type Config struct {
	Logger      *zap.Logger
	IncludeBody bool
	// RedactedQueryParams, when set, replaces the default set of
	// query-parameter names whose values are redacted in logs.
	// Nil/empty falls back to defaultRedactedQueryParams.
	RedactedQueryParams []string
}

// NewMiddleware creates a new logging middleware.
func NewMiddleware(cfg Config) *Middleware {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	redacted := cfg.RedactedQueryParams
	if len(redacted) == 0 {
		redacted = defaultRedactedQueryParams
	}

	return &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("logging", middleware.PriorityLogging),
		logger:         logger,
		includeBody:    cfg.IncludeBody,
		redactedParams: redacted,
	}
}

// ProcessRequest logs the incoming request. Context values are added
// onto the existing request context — never replacing it wholesale —
// so values set by earlier middleware are preserved.
func (m *Middleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	start := time.Now()

	ctx = context.WithValue(ctx, startTimeKey, start)

	requestID, ok := ctx.Value(middleware.RequestIDKey).(string)
	if !ok || requestID == "" {
		requestID = generateRequestID()
		ctx = context.WithValue(ctx, middleware.RequestIDKey, requestID)
	}
	req.Context = ctx

	m.logger.Info("request_started",
		zap.String("request_id", requestID),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.String("query", redactQuery(req.URL.RawQuery, m.redactedParams)),
		zap.String("remote_addr", req.RemoteAddr),
		zap.String("user_agent", req.UserAgent()),
		zap.String("request_type", req.RequestType.String()),
	)

	return req, nil
}

// ProcessResponse logs the response.
func (m *Middleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest, resp *middleware.STACResponse) (*middleware.STACResponse, error) {
	duration := time.Duration(0)
	if start, ok := ctx.Value(startTimeKey).(time.Time); ok {
		duration = time.Since(start)
	}

	requestID, _ := ctx.Value(middleware.RequestIDKey).(string)

	fields := []zap.Field{
		zap.String("request_id", requestID),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.Int("status", resp.StatusCode),
		zap.Duration("duration", duration),
		zap.Int("response_size", len(resp.Body)),
	}

	// Add body size for responses
	if m.includeBody && len(resp.Body) < 1024 {
		fields = append(fields, zap.ByteString("response_body", resp.Body))
	}

	// Log at appropriate level based on status code
	if resp.StatusCode >= 500 {
		m.logger.Error("request_completed", fields...)
	} else if resp.StatusCode >= 400 {
		m.logger.Warn("request_completed", fields...)
	} else {
		m.logger.Info("request_completed", fields...)
	}

	// Add request ID to response headers
	if requestID != "" {
		if resp.Headers == nil {
			resp.Headers = make(map[string][]string)
		}
		resp.Headers.Set("X-Request-ID", requestID)
	}

	return resp, nil
}

// Context key for start time
type contextKeyType string

const startTimeKey contextKeyType = "logging_start_time"

// generateRequestID generates a globally unique request ID. Used
// when an upstream client didn't already inject one. UUIDv4 is the
// portable, collision-resistant choice and is what every observability
// stack (Grafana, Datadog, etc.) recognises.
func generateRequestID() string {
	return uuid.NewString()
}

// WithLogger returns a new middleware with the given logger.
func (m *Middleware) WithLogger(logger *zap.Logger) *Middleware {
	return &Middleware{
		BaseMiddleware: m.BaseMiddleware,
		logger:         logger,
		includeBody:    m.includeBody,
		redactedParams: m.redactedParams,
	}
}
