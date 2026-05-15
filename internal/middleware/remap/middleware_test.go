package remap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// TestRemap_NonJSONResponse_NotDecoded (M-remap-1): a response with a
// non-JSON Content-Type passes through the middleware unchanged. The
// middleware MUST NOT attempt a JSON decode on binary payloads — it
// would waste memory and latency for no gain (no href to rewrite).
func TestRemap_NonJSONResponse_NotDecoded(t *testing.T) {
	binary := bytes.Repeat([]byte{0xFF, 0x00, 0x42, 0xAB}, 64) // 256 bytes of "binary"

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binary)
	})

	mw, err := NewHTTPMiddleware(Config{
		Rules: []RuleConfig{
			{Match: `https?://example.com/`, Replace: `https://proxy/`},
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPMiddleware: %v", err)
	}
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/asset.png", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type: want image/png, got %q", got)
	}
	if !bytes.Equal(rr.Body.Bytes(), binary) {
		t.Errorf("body mutated by middleware (length got %d, want %d, equal=%v)",
			rr.Body.Len(), len(binary), bytes.Equal(rr.Body.Bytes(), binary))
	}
}

// TestRemap_JSONResponse_StillRewritten guards against an over-broad
// content-type gate: a real application/json response must continue to
// be decoded and have its href values remapped.
func TestRemap_JSONResponse_StillRewritten(t *testing.T) {
	body := []byte(`{"href":"https://upstream.example.com/items/1"}`)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	mw, err := NewHTTPMiddleware(Config{
		Rules: []RuleConfig{{
			Match:   `https://upstream\.example\.com/`,
			Replace: `https://proxy.example.com/`,
		}},
	})
	if err != nil {
		t.Fatalf("NewHTTPMiddleware: %v", err)
	}
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/items/1", nil))

	matched, _ := regexp.Match(`"href":"https://proxy\.example\.com/items/1"`, rr.Body.Bytes())
	if !matched {
		t.Errorf("href was not rewritten: body=%s", rr.Body.String())
	}
}

// TestRemap_GeoJSONContentType_IsRewritten covers the +json suffix path
// (STAC's typical application/geo+json).
func TestRemap_GeoJSONContentType_IsRewritten(t *testing.T) {
	body := []byte(`{"href":"https://upstream.example.com/x"}`)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/geo+json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	mw, err := NewHTTPMiddleware(Config{
		Rules: []RuleConfig{{
			Match:   `https://upstream\.example\.com/`,
			Replace: `https://proxy/`,
		}},
	})
	if err != nil {
		t.Fatalf("NewHTTPMiddleware: %v", err)
	}
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))

	if !bytes.Contains(rr.Body.Bytes(), []byte("https://proxy/x")) {
		t.Errorf("application/geo+json body not rewritten: %s", rr.Body.String())
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := map[string]bool{
		"":                                false,
		"application/json":                true,
		"Application/JSON":                true,
		"application/json; charset=utf-8": true,
		"application/geo+json":            true,
		"application/vnd.oai.openapi+json; version=3.0": true,
		"image/png":                                     false,
		"text/plain":                                    false,
		"application/octet-stream":                      false,
		"application/jsonp":                             false, // not actually JSON
	}
	for in, want := range cases {
		if got := isJSONContentType(in); got != want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", in, got, want)
		}
	}
}
