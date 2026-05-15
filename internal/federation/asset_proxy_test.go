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
			if got := assetHrefUnderOrigin(tt.href, tt.base); got != tt.expect {
				t.Errorf("got %v want %v", got, tt.expect)
			}
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
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		return c
	}

	t.Run("never preserves href", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		if got := h.rewriteAssetHref(mkClient("never"), href); got != href {
			t.Errorf("got %q, want unchanged", got)
		}
	})

	t.Run("default (empty) preserves href", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		if got := h.rewriteAssetHref(mkClient(""), href); got != href {
			t.Errorf("got %q, want unchanged", got)
		}
	})

	t.Run("sign without signer falls back to passthrough", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		if got := h.rewriteAssetHref(mkClient("sign"), href); got != href {
			t.Errorf("got %q, want unchanged (no signer wired)", got)
		}
	})

	t.Run("sign with signer adds sig+exp", func(t *testing.T) {
		t.Parallel()
		h := &Handler{
			proxyBaseURL: "https://proxy.example",
			assetSigner:  fakeSigner{prefix: "?sig=X"},
		}
		got := h.rewriteAssetHref(mkClient("sign"), href)
		if !strings.Contains(got, "?sig=X") {
			t.Errorf("got %q, want signed url", got)
		}
	})

	t.Run("proxy mode rewrites to /assets/{id}/{ref}", func(t *testing.T) {
		t.Parallel()
		h := &Handler{proxyBaseURL: "https://proxy.example"}
		got := h.rewriteAssetHref(mkClient("proxy"), href)
		const wantPrefix = "https://proxy.example/assets/originA/"
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("got %q, want prefix %q", got, wantPrefix)
		}
		// And the suffix should base64-url-decode back to the href.
		ref := strings.TrimPrefix(got, wantPrefix)
		decoded, err := base64.RawURLEncoding.DecodeString(ref)
		if err != nil {
			t.Fatalf("ref not base64-decodable: %v", err)
		}
		if string(decoded) != href {
			t.Errorf("decoded ref = %q, want %q", string(decoded), href)
		}
	})

	t.Run("proxy mode with empty proxyBaseURL falls back to passthrough", func(t *testing.T) {
		t.Parallel()
		h := &Handler{}
		if got := h.rewriteAssetHref(mkClient("proxy"), href); got != href {
			t.Errorf("got %q, want unchanged", got)
		}
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
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	assetURL := upstream.URL + "/items/x/asset.bin"
	ref := base64.RawURLEncoding.EncodeToString([]byte(assetURL))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil)
	req.Header.Set("Range", "bytes=0-1023")

	handler.ServeAssetHTTP(rec, req, "a", ref)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 0-1023/1048576" {
		t.Errorf("Content-Range = %q", got)
	}
	if n := rec.Body.Len(); n != 1024 {
		t.Errorf("body length = %d, want 1024", n)
	}
	// Range was forwarded.
	if got := gotRange.Load(); got != "bytes=0-1023" {
		t.Errorf("upstream did not see Range: %v", got)
	}
	// Origin's configured bearer auth was applied to the upstream call.
	if got := gotAuth.Load(); got != "Bearer upstream-token" {
		t.Errorf("upstream auth = %v, want 'Bearer upstream-token'", got)
	}
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
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	bad := base64.RawURLEncoding.EncodeToString([]byte("https://attacker.example/something"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+bad, nil)
	handler.ServeAssetHTTP(rec, req, "a", bad)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for ref outside origin base", rec.Code)
	}
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
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ref := base64.RawURLEncoding.EncodeToString([]byte(upstream.URL + "/x"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil)
	handler.ServeAssetHTTP(rec, req, "a", ref)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for non-proxy origin", rec.Code)
	}
}

// TestServeAssetHTTP_UnknownOriginIs404 covers the path where the
// originId in the URL does not match any configured origin.
func TestServeAssetHTTP_UnknownOriginIs404(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ref := base64.RawURLEncoding.EncodeToString([]byte("https://example.com/x"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/assets/missing/"+ref, nil)
	handler.ServeAssetHTTP(rec, req, "missing", ref)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown origin", rec.Code)
	}
}

// TestServeAssetHTTP_ClientCancelAbortsUpstream verifies that
// canceling the inbound context unblocks the upstream read promptly.
func TestServeAssetHTTP_ClientCancelAbortsUpstream(t *testing.T) {
	t.Parallel()

	// Upstream that hangs forever on Read.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		<-r.Context().Done()
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: upstream.URL, Enabled: true, Timeout: 5 * time.Second, RewriteAssets: "proxy"},
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	ref := base64.RawURLEncoding.EncodeToString([]byte(upstream.URL + "/x"))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/assets/a/"+ref, nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeAssetHTTP(rec, req, "a", ref)
		close(done)
	}()

	// Give the upstream a moment to enter the hang, then cancel.
	time.Sleep(50 * time.Millisecond)
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
	if err != nil {
		t.Fatalf("client: %v", err)
	}

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
	h.rewriteLinks(client, data)

	feat := data["features"].([]any)[0].(map[string]any)
	gotHref := feat["assets"].(map[string]any)["data"].(map[string]any)["href"].(string)
	const wantPrefix = "https://proxy.example/assets/a/"
	if !strings.HasPrefix(gotHref, wantPrefix) {
		t.Errorf("asset href = %q, want prefix %q", gotHref, wantPrefix)
	}
}

// Ensure unused imports compile away.
var _ = json.Marshal
var _ = io.EOF
