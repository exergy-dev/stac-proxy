// Package testutil provides test fixtures, mocks, and helpers.
package testutil

import (
	"context"
	"net/http"
	"sync"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// MockAuthProvider is a mock authentication provider.
type MockAuthProvider struct {
	Name_      string
	AuthFunc   func(ctx context.Context, req *http.Request) (*auth.Principal, error)
	CallCount  int
	LastReq    *http.Request
	mu         sync.Mutex
}

// Name returns the provider name.
func (m *MockAuthProvider) Name() string {
	return m.Name_
}

// Authenticate calls the mock function.
func (m *MockAuthProvider) Authenticate(ctx context.Context, req *http.Request) (*auth.Principal, error) {
	m.mu.Lock()
	m.CallCount++
	m.LastReq = req
	m.mu.Unlock()

	if m.AuthFunc != nil {
		return m.AuthFunc(ctx, req)
	}
	return nil, nil
}

// MockMiddleware is a mock middleware for testing chains.
type MockMiddleware struct {
	Name_           string
	ProcessReqFunc  func(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error)
	ProcessRespFunc func(ctx context.Context, req *middleware.STACRequest, resp *middleware.STACResponse) (*middleware.STACResponse, error)
	ReqCallCount    int
	RespCallCount   int
	mu              sync.Mutex
}

// Name returns the middleware name.
func (m *MockMiddleware) Name() string {
	return m.Name_
}

// Priority returns 0 (default priority).
func (m *MockMiddleware) Priority() int {
	return 0
}

// ProcessRequest processes the request.
func (m *MockMiddleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	m.mu.Lock()
	m.ReqCallCount++
	m.mu.Unlock()

	if m.ProcessReqFunc != nil {
		return m.ProcessReqFunc(ctx, req)
	}
	return req, nil // Continue to next middleware
}

// ProcessResponse processes the response.
func (m *MockMiddleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest, resp *middleware.STACResponse) (*middleware.STACResponse, error) {
	m.mu.Lock()
	m.RespCallCount++
	m.mu.Unlock()

	if m.ProcessRespFunc != nil {
		return m.ProcessRespFunc(ctx, req, resp)
	}
	return resp, nil
}

// MockOriginAuthProvider is a mock origin auth provider.
type MockOriginAuthProvider struct {
	ApplyAuthFunc func(ctx context.Context, req *http.Request) error
	CallCount     int
	mu            sync.Mutex
}

// ApplyAuth applies authentication to the request.
func (m *MockOriginAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	m.mu.Lock()
	m.CallCount++
	m.mu.Unlock()

	if m.ApplyAuthFunc != nil {
		return m.ApplyAuthFunc(ctx, req)
	}
	return nil
}

// MockHandler is a mock STAC handler.
type MockHandler struct {
	HandleFunc func(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error)
	CallCount  int
	LastReq    *middleware.STACRequest
	mu         sync.Mutex
}

// Handle processes the request.
func (m *MockHandler) Handle(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	m.mu.Lock()
	m.CallCount++
	m.LastReq = req
	m.mu.Unlock()

	if m.HandleFunc != nil {
		return m.HandleFunc(ctx, req)
	}
	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{}`),
	}, nil
}

// MockHTTPTransport is a mock HTTP transport for testing.
type MockHTTPTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
	Requests      []*http.Request
	mu            sync.Mutex
}

// RoundTrip executes the mock.
func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.Requests = append(m.Requests, req)
	m.mu.Unlock()

	if m.RoundTripFunc != nil {
		return m.RoundTripFunc(req)
	}
	return nil, nil
}


// OriginSearchResult for testing merger.
type OriginSearchResult struct {
	OriginID string
	Items    []*stac.Item
	Error    error
}

// MockOriginClient is a simplified mock for origin client testing.
type MockOriginClient struct {
	ID_              string
	SearchFunc       func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
	GetCollsFunc     func(ctx context.Context) ([]*stac.Collection, error)
	Collections_     []string
	Enabled_         bool
	Priority_        int
}

// Ensure MockOriginClient can be used where federation.OriginClient is expected
var _ interface {
	Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
} = (*MockOriginClient)(nil)

// Search performs a mock search.
func (m *MockOriginClient) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(ctx, req)
	}
	return nil, "", "", nil
}

// GetCollections returns mock collections.
func (m *MockOriginClient) GetCollections(ctx context.Context) ([]*stac.Collection, error) {
	if m.GetCollsFunc != nil {
		return m.GetCollsFunc(ctx)
	}
	return nil, nil
}

// ID returns the origin ID.
func (m *MockOriginClient) ID() string {
	return m.ID_
}

// Priority returns the origin priority.
func (m *MockOriginClient) Priority() int {
	return m.Priority_
}

// IsEnabled returns if the origin is enabled.
func (m *MockOriginClient) IsEnabled() bool {
	return m.Enabled_
}

// HasCollection checks if origin has a collection.
func (m *MockOriginClient) HasCollection(id string) bool {
	for _, c := range m.Collections_ {
		if c == id {
			return true
		}
	}
	return false
}

// Compile-time interface checks
var (
	_ auth.Provider         = (*MockAuthProvider)(nil)
	_ middleware.Middleware = (*MockMiddleware)(nil)
	_ middleware.Handler    = (*MockHandler)(nil)
	_ http.RoundTripper     = (*MockHTTPTransport)(nil)
)
