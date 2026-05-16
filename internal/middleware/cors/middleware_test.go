package cors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// countingHandler is a stub inner handler that records how many times
// it was called. Preflight tests use it to assert short-circuit
// behaviour (count must stay at zero).
type countingHandler struct {
	calls int
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls++
	w.WriteHeader(http.StatusOK)
}

func newRequest(method, origin string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/collections", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestPreflight_ShortCircuits(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"https://example.org"},
	})(inner)

	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}
	if inner.calls != 0 {
		t.Fatalf("preflight must not call inner handler; got %d calls", inner.calls)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.org" {
		t.Fatalf("ACAO=%q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("preflight missing Access-Control-Allow-Methods")
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Fatal("preflight missing Access-Control-Max-Age")
	}
}

func TestPreflight_DisallowedOrigin(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"https://example.org"},
	})(inner)

	r := newRequest(http.MethodOptions, "https://evil.example", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin must not get ACAO; got %q", got)
	}
	if inner.calls != 0 {
		t.Fatalf("preflight must not call inner handler even when origin disallowed; got %d", inner.calls)
	}
}

func TestActualRequest_OriginEchoed(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"https://example.org"},
	})(inner)

	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if inner.calls != 1 {
		t.Fatalf("want inner called once, got %d", inner.calls)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.org" {
		t.Fatalf("ACAO=%q", got)
	}
}

func TestActualRequest_WildcardWithoutCredentials(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"*"},
	})(inner)

	r := newRequest(http.MethodGet, "https://anything.example", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("ACAO=%q", got)
	}
}

func TestVaryHeader_OnAllResponses(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{AllowedOrigins: []string{"*"}})(inner)

	// Actual request
	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if !containsValue(w.Header().Values("Vary"), "Origin") {
		t.Fatalf("Vary missing Origin on actual: %v", w.Header().Values("Vary"))
	}

	// Preflight
	r = newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	vary := w.Header().Values("Vary")
	for _, expect := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !containsValue(vary, expect) {
			t.Fatalf("preflight Vary missing %q: %v", expect, vary)
		}
	}
}

func TestVaryHeader_AccumulatesNotOverwrites(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	})
	mw := NewHTTPMiddleware(Config{AllowedOrigins: []string{"*"}})(inner)

	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	vary := w.Header().Values("Vary")
	if !containsValue(vary, "Origin") || !containsValue(vary, "Accept-Encoding") {
		t.Fatalf("Vary should include both Origin and Accept-Encoding; got %v", vary)
	}
}

func TestAllowCredentials_NoWildcardEcho(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins:   []string{"https://example.org"},
		AllowCredentials: true,
	})(inner)

	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.org" {
		t.Fatalf("ACAO=%q (want exact-echo, never *)", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials=%q", got)
	}
}

func TestAllowCredentials_WildcardDowngradedToNoEcho(t *testing.T) {
	// Defensive guard: if a Config is constructed with both wildcard
	// and credentials (bypassing NewFromConfig validation), the
	// middleware must NOT emit a wildcard ACAO with credentials.
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})(inner)

	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatal("must not emit wildcard ACAO when credentials enabled")
	}
}

func TestNoOriginHeader_PassesThrough(t *testing.T) {
	inner := &countingHandler{}
	mw := NewHTTPMiddleware(Config{AllowedOrigins: []string{"*"}})(inner)

	r := httptest.NewRequest(http.MethodGet, "/collections", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if inner.calls != 1 {
		t.Fatalf("inner should be called for non-CORS request; got %d", inner.calls)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("no Origin → no ACAO; got %q", got)
	}
	if got := w.Header().Values("Vary"); len(got) != 0 {
		t.Fatalf("no Origin → no Vary added; got %v", got)
	}
}

func TestNewFromConfig_RejectsCredentialsWithWildcard(t *testing.T) {
	_, err := NewFromConfig(map[string]interface{}{
		"allowed_origins":   []interface{}{"*"},
		"allow_credentials": true,
	})
	if err == nil {
		t.Fatal("expected error for credentials+wildcard, got nil")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error should mention wildcard; got %v", err)
	}
}

func TestNewFromConfig_RejectsNonStringOrigin(t *testing.T) {
	_, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"https://example.org", 42},
	})
	if err == nil {
		t.Fatal("expected error for non-string origin element")
	}
}

func TestNewFromConfig_AppliesDefaults(t *testing.T) {
	mw, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"*"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("default Max-Age=%q, want 600", got)
	}
	methods := w.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"GET", "HEAD", "POST", "OPTIONS"} {
		if !strings.Contains(methods, m) {
			t.Fatalf("default methods missing %q: %s", m, methods)
		}
	}
}

func TestNewFromConfig_MaxAgeAcceptsFloat(t *testing.T) {
	mw, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"*"},
		"max_age":         float64(120),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Max-Age"); got != "120" {
		t.Fatalf("Max-Age=%q, want 120", got)
	}
}

func TestExposedHeaders_OnlyOnActualResponses(t *testing.T) {
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"*"},
		ExposedHeaders: []string{"ETag", "Content-Range"},
	})(&countingHandler{})

	// Actual request — should be present.
	r := newRequest(http.MethodGet, "https://example.org", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Expose-Headers"); got != "ETag, Content-Range" {
		t.Fatalf("actual Expose-Headers=%q", got)
	}

	// Preflight — should not be present.
	r = newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Expose-Headers"); got != "" {
		t.Fatalf("preflight should not emit Expose-Headers; got %q", got)
	}
}

func TestPreflight_EchoesRequestHeaders_WhenAllowedHeadersEmpty(t *testing.T) {
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"*"},
		// AllowedHeaders intentionally unset → echo path
	})(&countingHandler{})

	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "X-Custom-Header, X-Other",
	})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Headers"); got != "X-Custom-Header, X-Other" {
		t.Fatalf("Allow-Headers=%q (want echo)", got)
	}
}

func TestMaxAge_ZeroFallsBackToDefault(t *testing.T) {
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"*"},
		MaxAge:         0,
	})(&countingHandler{})

	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Fatalf("Max-Age=%q, want default 600", got)
	}
}

func TestCustomMaxAge(t *testing.T) {
	mw := NewHTTPMiddleware(Config{
		AllowedOrigins: []string{"*"},
		MaxAge:         30 * time.Second,
	})(&countingHandler{})

	r := newRequest(http.MethodOptions, "https://example.org", map[string]string{
		"Access-Control-Request-Method": "GET",
	})
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Max-Age"); got != "30" {
		t.Fatalf("Max-Age=%q, want 30", got)
	}
}

func containsValue(values []string, want string) bool {
	for _, v := range values {
		// Vary headers may be comma-joined within a single value or
		// split across multiple. Handle both.
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) == want {
				return true
			}
		}
	}
	return false
}
