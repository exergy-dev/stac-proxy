package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/config"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// TestNewMetricsServer_ShutdownDrainsListener verifies that the
// metrics *http.Server returned by newMetricsServer is shutdown-able
// (Fix H-server-tls-2 — previously the metrics goroutine was orphaned
// past SIGTERM because the *http.Server was not retained by the
// caller).
//
// We start the server on an ephemeral port, then call Shutdown and
// assert that ListenAndServe returns http.ErrServerClosed within
// the deadline. If the caller had not retained the handle, this
// test could not even be expressed.
func TestNewMetricsServer_ShutdownDrainsListener(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := observability.NewMetrics("test_shutdown")

	// Port 0 → kernel picks a free port.
	srv := newMetricsServer(config.MetricsConfig{
		Enabled:  true,
		BindAddr: "127.0.0.1:0",
	}, metrics, logger)

	// We need to bind explicitly so we know the port — ListenAndServe
	// would block. Use a separate listener and Serve.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of Shutdown")
	}
}

// TestParallelShutdown_BothServersDrain models the run() shutdown
// path: a main http.Server and a metrics http.Server are both
// shut down in parallel via WaitGroup. Verifies that both
// goroutines complete and Wait returns.
func TestParallelShutdown_BothServersDrain(t *testing.T) {
	t.Parallel()

	mkServer := func() (*http.Server, net.Listener) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		s := &http.Server{
			Handler:           http.NewServeMux(),
			ReadHeaderTimeout: time.Second,
		}
		go func() {
			_ = s.Serve(ln)
		}()
		return s, ln
	}

	mainSrv, mainLn := mkServer()
	metricsSrv, metricsLn := mkServer()
	_, _ = mainLn, metricsLn // listeners owned by Server

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = mainSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			defer wg.Done()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: both shut down cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("parallel Shutdown did not complete within 5s")
	}
}
