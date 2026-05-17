package stac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeFilterExtension_True(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/conformance", r.URL.Path, "path = %q, want /conformance", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"conformsTo":["https://api.stacspec.org/v1.0.0/item-search#filter","other"]}`))
	}))
	defer srv.Close()

	ok, err := ProbeFilterExtension(context.Background(), nil, srv.URL)
	require.NoError(t, err)
	require.True(t, ok, "want supports=true")
}

func TestProbeFilterExtension_False(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"conformsTo":["https://api.stacspec.org/v1.0.0/core"]}`))
	}))
	defer srv.Close()

	ok, err := ProbeFilterExtension(context.Background(), nil, srv.URL)
	require.NoError(t, err)
	require.False(t, ok, "want supports=false when no filter URI advertised")
}

func TestProbeFilterExtension_TrailingSlashTolerant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/conformance", r.URL.Path, "path = %q, want /conformance (no double slash)", r.URL.Path)
		w.Write([]byte(`{"conformsTo":[]}`))
	}))
	defer srv.Close()

	_, err := ProbeFilterExtension(context.Background(), nil, srv.URL+"/")
	require.NoError(t, err)
}

func TestProbeFilterExtension_NetworkError(t *testing.T) {
	_, err := ProbeFilterExtension(context.Background(), nil, "http://127.0.0.1:1")
	require.Error(t, err, "want error for unreachable host")
}

func TestProbeFilterExtension_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	_, err := ProbeFilterExtension(context.Background(), nil, srv.URL)
	require.Error(t, err, "want error for 404 response")
}

func TestProxyConformanceFor(t *testing.T) {
	t.Parallel()

	t.Run("filter ext NOT advertised when CQL2 injection disabled", func(t *testing.T) {
		out := ProxyConformanceFor(ConformanceCaps{CQL2InjectionEnabled: false, AllOriginsSupportFilter: true})
		for _, c := range out {
			for _, f := range FilterExtensionConformance {
				assert.NotEqual(t, f, c, "filter ext %q leaked into output without injection", c)
			}
		}
	})

	t.Run("filter ext NOT advertised when an origin lacks support", func(t *testing.T) {
		out := ProxyConformanceFor(ConformanceCaps{CQL2InjectionEnabled: true, AllOriginsSupportFilter: false})
		for _, c := range out {
			for _, f := range FilterExtensionConformance {
				assert.NotEqual(t, f, c, "filter ext %q leaked when not all origins support it", c)
			}
		}
	})

	t.Run("filter ext IS advertised when both conditions hold", func(t *testing.T) {
		out := ProxyConformanceFor(ConformanceCaps{CQL2InjectionEnabled: true, AllOriginsSupportFilter: true})
		seen := make(map[string]bool)
		for _, c := range out {
			seen[c] = true
		}
		for _, f := range FilterExtensionConformance {
			assert.True(t, seen[f], "missing advertised filter ext class %q", f)
		}
	})
}

func TestIntersect(t *testing.T) {
	t.Parallel()

	proxy := []string{"a", "b", "c", "d"}

	t.Run("no origin sets returns proxy sorted", func(t *testing.T) {
		got := Intersect(proxy)
		assert.Equal(t, []string{"a", "b", "c", "d"}, got)
	})

	t.Run("single origin shrinks set", func(t *testing.T) {
		got := Intersect(proxy, []string{"b", "c"})
		assert.Equal(t, []string{"b", "c"}, got)
	})

	t.Run("multiple origins narrow to common subset", func(t *testing.T) {
		got := Intersect(proxy, []string{"a", "b", "c"}, []string{"b", "c", "d"})
		assert.Equal(t, []string{"b", "c"}, got)
	})

	t.Run("disjoint origin yields empty", func(t *testing.T) {
		got := Intersect(proxy, []string{"x", "y"})
		assert.Empty(t, got, "expected empty, got %v", got)
	})

	t.Run("class no origin advertises is dropped", func(t *testing.T) {
		got := Intersect([]string{"a", "b"}, []string{"a"}, []string{"a"})
		assert.Equal(t, []string{"a"}, got)
	})
}

func TestFetchConformance(t *testing.T) {
	t.Parallel()

	t.Run("returns full conformsTo", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"conformsTo":["a","b","c"]}`))
		}))
		defer srv.Close()
		got, err := FetchConformance(context.Background(), nil, srv.URL)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, got)
	})
}
