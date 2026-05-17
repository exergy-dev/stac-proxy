package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssetHrefUnderOrigin covers the SSRF defense: a decoded asset
// href must live under the configured origin's base URL.
func TestAssetHrefUnderOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		href   string
		base   string
		expect bool
	}{
		{"exact host match", "https://upstream.example/path/a.tif", "https://upstream.example", true},
		{"with base path prefix", "https://upstream.example/api/path/a.tif", "https://upstream.example/api", true},
		{"host mismatch", "https://attacker.example/a.tif", "https://upstream.example", false},
		{"scheme mismatch", "http://upstream.example/a.tif", "https://upstream.example", false},
		{"path prefix sneak", "https://upstream.example/api-evil/x", "https://upstream.example/api", false},
		{"empty base path matches anything on host", "https://upstream.example/x/y", "https://upstream.example/", true},
		{"unparseable href", "://broken", "https://upstream.example", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, assetHrefUnderOrigin(tt.href, tt.base))
		})
	}
}

// TestRewriteAssetHref_Modes exercises all three rewrite modes.
func TestRewriteAssetHref_Modes(t *testing.T) {
	t.Parallel()

	href := "https://upstream.example/items/x/asset.tif"
	mkClient := func(mode string) *OriginClient {
		o := &Origin{
			ID:            "originA",
			BaseURL:       "https://upstream.example",
			Enabled:       true,
			Timeout:       5 * time.Second,
			RewriteAssets: mode,
		}
		c, err := NewOriginClient(o)
		require.NoError(t, err, "client")
		return c
	}

	ctx := context.Background()

	t.Run("never preserves href", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		assert.Equal(t, href, h.rewriteAssetHref(ctx, mkClient("never"), href), "want unchanged")
	})

	t.Run("default (empty) preserves href", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		assert.Equal(t, href, h.rewriteAssetHref(ctx, mkClient(""), href), "want unchanged")
	})

	t.Run("sign without signer falls back to passthrough", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		assert.Equal(t, href, h.rewriteAssetHref(ctx, mkClient("sign"), href), "want unchanged (no signer wired)")
	})

	t.Run("sign with signer adds sig+exp", func(t *testing.T) {
		t.Parallel()
		h := &Handler{
			proxyBaseURL: "https://proxy.example",
			assetSigner:  fakeSigner{prefix: "?sig=X"},
		}
		got := h.rewriteAssetHref(ctx, mkClient("sign"), href)
		assert.Containsf(t, got, "?sig=X", "got %q, want signed url", got)
	})

	t.Run("proxy mode rewrites to /assets/{id}/{ref}", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		got := h.rewriteAssetHref(ctx, mkClient("proxy"), href)
		const wantPrefix = "https://proxy.example/assets/originA/"
		require.Truef(t, strings.HasPrefix(got, wantPrefix), "got %q, want prefix %q", got, wantPrefix)
		// And the suffix should base64-url-decode back to the href.
		ref := strings.TrimPrefix(got, wantPrefix)
		decoded, err := base64.RawURLEncoding.DecodeString(ref)
		require.NoErrorf(t, err, "ref not base64-decodable")
		assert.Equalf(t, href, string(decoded), "decoded ref mismatch")
	})

	t.Run("proxy mode with empty proxyBaseURL falls back to passthrough", func(t *testing.T) {
		t.Parallel()
		h := &Handler{}
		assert.Equal(t, href, h.rewriteAssetHref(ctx, mkClient("proxy"), href), "want unchanged")
	})
}

type fakeSigner struct{ prefix string }

func (s fakeSigner) Sign(_ context.Context, raw string, _ time.Duration) string {
	return raw + s.prefix
}

// TestServeAssetHTTP_StreamsAndForwardsRange covers the happy path
// of the streaming endpoint: a 1 MiB asset, a Range request, the
// proxy forwards Range to upstream and streams the response back with
// status 206.
func TestServeAssetHTTP_StreamsAndForwardsRange(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}

	var gotRange atomic.Value
	var gotAuth atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange.Store(r.Header.Get("Range"))
		gotAuth.Store(r.Header.Get("Authorization"))
		// Honor a single-range "bytes=0-1023" request.
		if rng := r.Header.Get("Range"); rng == "bytes=0-1023" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-1023/1048576")
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[:1024])
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:            "a",
				BaseURL:       upstream.URL,
				Enabled:       true,
				Timeout:       5 * time.Second,
				RewriteAssets: "proxy",
				Auth: AuthConfig{
					Type:  "bearer",
					Token: "upstream-token",
				},
			},
		},
		ProxyBaseURL: "https://proxy.example",
	})
	require.NoError(t, err, "NewHandler")

	assetURL := upstream.URL + "/items/x/asset.bin"
	ref := base64.RawURLEncoding.EncodeToString([]byte(assetURL))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil)
	req.Header.Set("Range", "bytes=0-1023")

	handler.ServeAssetHTTP(rec, req, "a", ref)

	require.Equalf(t, http.StatusPartialContent, rec.Code, "status; body=%q", rec.Body.String())
	assert.Equal(t, "bytes 0-1023/1048576", rec.Header().Get("Content-Range"), "Content-Range")
	assert.Equalf(t, 1024, rec.Body.Len(), "body length")
	// Range was forwarded.
	assert.Equal(t, "bytes=0-1023", gotRange.Load(), "upstream did not see Range")
	// Origin's configured bearer auth was applied to the upstream call.
	assert.Equal(t, "Bearer upstream-token", gotAuth.Load(), "upstream auth")
}

// TestServeAssetHTTP_RejectsOutOfOriginRef verifies the SSRF defense
// rejects refs that don't decode to a URL under the origin's base.
func TestServeAssetHTTP_RejectsOutOfOriginRef(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: upstream.URL, Enabled: true, Timeout: time.Second, RewriteAssets: "proxy"},
		},
	})
	require.NoError(t, err, "NewHandler")

	bad := base64.RawURLEncoding.EncodeToString([]byte("https://attacker.example/something"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+bad, nil)
	handler.ServeAssetHTTP(rec, req, "a", bad)

	assert.Equalf(t, http.StatusBadRequest, rec.Code, "status; want 400 for ref outside origin base")
}

// TestServeAssetHTTP_OriginNotInProxyModeIs404 verifies that the
// asset endpoint refuses to serve origins that haven't opted into
// rewrite_assets: proxy.
func TestServeAssetHTTP_OriginNotInProxyModeIs404(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: upstream.URL, Enabled: true, Timeout: time.Second /* no RewriteAssets */},
		},
	})
	require.NoError(t, err, "NewHandler")

	ref := base64.RawURLEncoding.EncodeToString([]byte(upstream.URL + "/x"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil)
	handler.ServeAssetHTTP(rec, req, "a", ref)

	assert.Equalf(t, http.StatusNotFound, rec.Code, "status; want 404 for non-proxy origin")
}

// TestServeAssetHTTP_UnknownOriginIs404 covers the path where the
// originId in the URL does not match any configured origin.
func TestServeAssetHTTP_UnknownOriginIs404(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{})
	require.NoError(t, err, "NewHandler")

	ref := base64.RawURLEncoding.EncodeToString([]byte("https://example.com/x"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/missing/"+ref, nil)
	handler.ServeAssetHTTP(rec, req, "missing", ref)

	assert.Equalf(t, http.StatusNotFound, rec.Code, "status; want 404 for unknown origin")
}

// TestServeAssetHTTP_ClientCancelAbortsUpstream verifies that
// canceling the inbound context unblocks the upstream read promptly.
func TestServeAssetHTTP_ClientCancelAbortsUpstream(t *testing.T) {
	t.Parallel()

	// Upstream that hangs forever on Read. Signals via `started` when
	// it has written headers and entered the hang, so the test can
	// cancel deterministically without a sleep.
	started := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(started)
		<-r.Context().Done()
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: upstream.URL, Enabled: true, Timeout: 5 * time.Second, RewriteAssets: "proxy"},
		},
	})
	require.NoError(t, err, "NewHandler")

	ref := base64.RawURLEncoding.EncodeToString([]byte(upstream.URL + "/x"))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeAssetHTTP(rec, req, "a", ref)
		close(done)
	}()

	// Wait for upstream to enter the hang, then cancel.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream handler did not start")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAssetHTTP did not return after context cancel")
	}
}

// TestRewriteLinks_WalksAssets covers the integration path: when a
// feature collection comes through transformResponse, the rewriter
// walks assets[*].href for every Item.
func TestRewriteLinks_WalksAssets(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	client, err := NewOriginClient(&Origin{
		ID:            "a",
		BaseURL:       upstream.URL,
		Enabled:       true,
		Timeout:       time.Second,
		RewriteAssets: "proxy",
	})
	require.NoError(t, err, "client")

	h := &Handler{proxyBaseURL: "https://proxy.example"}

	data := map[string]any{
		"type": "FeatureCollection",
		"features": []any{
			map[string]any{
				"id": "item-1",
				"assets": map[string]any{
					"data": map[string]any{
						"href": upstream.URL + "/a/asset.tif",
					},
				},
			},
		},
	}
	h.rewriteLinks(context.Background(), client, data)

	feat := data["features"].([]any)[0].(map[string]any)
	gotHref := feat["assets"].(map[string]any)["data"].(map[string]any)["href"].(string)
	const wantPrefix = "https://proxy.example/assets/a/"
	assert.Truef(t, strings.HasPrefix(gotHref, wantPrefix), "asset href = %q, want prefix %q", gotHref, wantPrefix)
}

// Ensure unused imports compile away.
var _ = json.Marshal
var _ = io.EOF
