package stac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeFilterExtension_True(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/conformance" {
			t.Errorf("path = %q, want /conformance", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"conformsTo":["https://api.stacspec.org/v1.0.0/item-search#filter","other"]}`))
	}))
	defer srv.Close()

	ok, err := ProbeFilterExtension(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("want supports=true")
	}
}

func TestProbeFilterExtension_False(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"conformsTo":["https://api.stacspec.org/v1.0.0/core"]}`))
	}))
	defer srv.Close()

	ok, err := ProbeFilterExtension(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("want supports=false when no filter URI advertised")
	}
}

func TestProbeFilterExtension_TrailingSlashTolerant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/conformance" {
			t.Errorf("path = %q, want /conformance (no double slash)", r.URL.Path)
		}
		w.Write([]byte(`{"conformsTo":[]}`))
	}))
	defer srv.Close()

	if _, err := ProbeFilterExtension(context.Background(), nil, srv.URL+"/"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProbeFilterExtension_NetworkError(t *testing.T) {
	if _, err := ProbeFilterExtension(context.Background(), nil, "http://127.0.0.1:1"); err == nil {
		t.Fatal("want error for unreachable host")
	}
}

func TestProbeFilterExtension_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	if _, err := ProbeFilterExtension(context.Background(), nil, srv.URL); err == nil {
		t.Fatal("want error for 404 response")
	}
}

func TestProxyConformanceFor(t *testing.T) {
	t.Parallel()

	t.Run("filter ext NOT advertised when CQL2 injection disabled", func(t *testing.T) {
		out := ProxyConformanceFor(ConformanceCaps{CQL2InjectionEnabled: false, AllOriginsSupportFilter: true})
		for _, c := range out {
			for _, f := range FilterExtensionConformance {
				if c == f {
					t.Errorf("filter ext %q leaked into output without injection", c)
				}
			}
		}
	})

	t.Run("filter ext NOT advertised when an origin lacks support", func(t *testing.T) {
		out := ProxyConformanceFor(ConformanceCaps{CQL2InjectionEnabled: true, AllOriginsSupportFilter: false})
		for _, c := range out {
			for _, f := range FilterExtensionConformance {
				if c == f {
					t.Errorf("filter ext %q leaked when not all origins support it", c)
				}
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
			if !seen[f] {
				t.Errorf("missing advertised filter ext class %q", f)
			}
		}
	})
}

func TestIntersect(t *testing.T) {
	t.Parallel()

	proxy := []string{"a", "b", "c", "d"}

	t.Run("no origin sets returns proxy sorted", func(t *testing.T) {
		got := Intersect(proxy)
		want := []string{"a", "b", "c", "d"}
		if !equalStrings(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})

	t.Run("single origin shrinks set", func(t *testing.T) {
		got := Intersect(proxy, []string{"b", "c"})
		want := []string{"b", "c"}
		if !equalStrings(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})

	t.Run("multiple origins narrow to common subset", func(t *testing.T) {
		got := Intersect(proxy, []string{"a", "b", "c"}, []string{"b", "c", "d"})
		want := []string{"b", "c"}
		if !equalStrings(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})

	t.Run("disjoint origin yields empty", func(t *testing.T) {
		got := Intersect(proxy, []string{"x", "y"})
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("class no origin advertises is dropped", func(t *testing.T) {
		got := Intersect([]string{"a", "b"}, []string{"a"}, []string{"a"})
		want := []string{"a"}
		if !equalStrings(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFetchConformance(t *testing.T) {
	t.Parallel()

	t.Run("returns full conformsTo", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"conformsTo":["a","b","c"]}`))
		}))
		defer srv.Close()
		got, err := FetchConformance(context.Background(), nil, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if !equalStrings(got, []string{"a", "b", "c"}) {
			t.Errorf("got %v", got)
		}
	})
}
