package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

func TestBodyLimitMiddleware_LargeBodyRejected(t *testing.T) {
	// Stand up a chi router with the body-limit middleware and a
	// handler that tries to read the whole body. Sending more than
	// the limit should fail the read; the standard library returns
	// http.ErrAbortHandler, which manifests as a 500/empty response.
	const limit = 1024
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, limit+1)
		n, err := r.Body.Read(b)
		if err == nil && n > limit {
			t.Errorf("expected read to fail past %d bytes, got n=%d err=nil", limit, n)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrapped := bodyLimitMiddleware(limit)(mux)

	big := bytes.Repeat([]byte("x"), 4096)
	req := httptest.NewRequest("POST", "/echo", bytes.NewReader(big))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
}

func TestBodyLimitMiddleware_SmallBodyPasses(t *testing.T) {
	const limit = 1024
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, err := readAll(r.Body)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		if !strings.HasPrefix(string(b), "tiny") {
			t.Errorf("body mismatch: %q", b)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrapped := bodyLimitMiddleware(limit)(mux)

	req := httptest.NewRequest("POST", "/echo", strings.NewReader("tiny payload"))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func TestHandleError_RetryAfterIsNumericString(t *testing.T) {
	r := &Router{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.handleError(rr, req, &middleware.RateLimitError{RetryAfter: 30})

	if got := rr.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After: want %q, got %q", "30", got)
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status: want 429, got %d", rr.Code)
	}
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body must be valid JSON: %v\nbody=%q", err, rr.Body.String())
	}
	if body.Code != "RateLimitExceeded" {
		t.Errorf("code: want RateLimitExceeded, got %q", body.Code)
	}
}

func TestHandleError_HostileMessageStaysValidJSON(t *testing.T) {
	r := &Router{}
	for _, msg := range []string{
		`he said "hi"`,
		"with\nnewline",
		"with\\backslash",
		`{"injected": true}`,
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		r.handleError(rr, req, &middleware.AuthError{Message: msg, Code: "x"})

		var body errorBody
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Errorf("hostile message %q produced invalid JSON: %v\nraw=%q", msg, err, rr.Body.String())
			continue
		}
		if body.Description != msg {
			t.Errorf("description round-trip mismatch: want %q, got %q", msg, body.Description)
		}
	}
}

func TestHandleError_InternalErrorDoesNotLeakCause(t *testing.T) {
	r := &Router{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.handleError(rr, req, &middleware.InternalError{Message: "database password=hunter2"})

	if strings.Contains(rr.Body.String(), "hunter2") {
		t.Fatalf("internal error description leaked to client: %s", rr.Body.String())
	}
	var body errorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body.Code != "InternalError" {
		t.Errorf("code: want InternalError, got %q", body.Code)
	}
}

// readAll is a tiny inline helper so the test file doesn't import io
// purely for ReadAll.
func readAll(r interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	out := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}
