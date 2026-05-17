package remap

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "NewHTTPMiddleware")
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/asset.png", nil))

	require.Equal(t, http.StatusOK, rr.Code, "status")
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"), "Content-Type")
	assert.True(t, bytes.Equal(rr.Body.Bytes(), binary),
		"body mutated by middleware (length got %d, want %d)", rr.Body.Len(), len(binary))
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
	require.NoError(t, err, "NewHTTPMiddleware")
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/items/1", nil))

	matched, _ := regexp.Match(`"href":"https://proxy\.example\.com/items/1"`, rr.Body.Bytes())
	assert.True(t, matched, "href was not rewritten: body=%s", rr.Body.String())
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
	require.NoError(t, err, "NewHTTPMiddleware")
	h := mw(inner)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))

	assert.Contains(t, rr.Body.String(), "https://proxy/x",
		"application/geo+json body not rewritten")
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
		assert.Equal(t, want, isJSONContentType(in), "isJSONContentType(%q)", in)
	}
}

// TestTransformURLs_RespectsMaxDepth ensures pathological deeply
// nested JSON does not blow the stack. Builds a chain of nested
// objects (`{"x":{"x":...}}`) deeper than maxRemapDepth and asserts
// the call returns rather than recursing forever.
func TestTransformURLs_RespectsMaxDepth(t *testing.T) {
	// 1000 levels of nesting (well beyond maxRemapDepth=16).
	const depth = 1000
	root := map[string]interface{}{}
	cur := root
	for i := 0; i < depth; i++ {
		next := map[string]interface{}{}
		cur["x"] = next
		cur = next
	}

	done := make(chan struct{})
	go func() {
		transformURLs(context.Background(), nil, root, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "transformURLs did not return within 2s on deep input")
	}
}
