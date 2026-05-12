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
