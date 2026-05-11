// Package logging provides logging middleware.
package logging

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// Middleware logs requests and responses.
type Middleware struct {
	middleware.BaseMiddleware
	logger      *zap.Logger
	includeBody bool
}

// Config contains configuration for the logging middleware.
type Config struct {
	Logger      *zap.Logger
	IncludeBody bool
}

// NewMiddleware creates a new logging middleware.
func NewMiddleware(cfg Config) *Middleware {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	return &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("logging", middleware.PriorityLogging),
		logger:         logger,
		includeBody:    cfg.IncludeBody,
	}
}

// ProcessRequest logs the incoming request.
func (m *Middleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	start := time.Now()

	// Store start time in context for response logging
	ctx = context.WithValue(ctx, startTimeKey, start)
	req.Context = ctx

	// Generate request ID if not present
	requestID, ok := ctx.Value(middleware.RequestIDKey).(string)
	if !ok || requestID == "" {
		requestID = generateRequestID()
		ctx = context.WithValue(ctx, middleware.RequestIDKey, requestID)
		req.Context = ctx
	}

	m.logger.Info("request_started",
		zap.String("request_id", requestID),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.String("query", req.URL.RawQuery),
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

// generateRequestID generates a unique request ID.
func generateRequestID() string {
	// Simple implementation - in production use UUID
	return time.Now().Format("20060102150405.000000")
}

// WithLogger returns a new middleware with the given logger.
func (m *Middleware) WithLogger(logger *zap.Logger) *Middleware {
	return &Middleware{
		BaseMiddleware: m.BaseMiddleware,
		logger:         logger,
		includeBody:    m.includeBody,
	}
}
