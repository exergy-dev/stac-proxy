// Package config provides configuration management.
package config

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Watcher watches configuration files for changes.
type Watcher struct {
	watcher   *fsnotify.Watcher
	paths     []string
	callbacks []func(*Config, error)
	loader    func(string) (*Config, error)
	logger    *zap.Logger
	mu        sync.RWMutex
	current   *Config
	debounce  time.Duration
	stopCh    chan struct{}
}

// WatcherConfig configures the config watcher.
type WatcherConfig struct {
	Paths    []string
	Loader   func(string) (*Config, error)
	Logger   *zap.Logger
	Debounce time.Duration
}

// NewWatcher creates a new configuration watcher.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	if cfg.Debounce == 0 {
		cfg.Debounce = 1 * time.Second
	}

	if cfg.Logger == nil {
		cfg.Logger, _ = zap.NewProduction()
	}

	if cfg.Loader == nil {
		cfg.Loader = func(path string) (*Config, error) {
			return Load(path)
		}
	}

	w := &Watcher{
		watcher:  fsWatcher,
		paths:    cfg.Paths,
		loader:   cfg.Loader,
		logger:   cfg.Logger,
		debounce: cfg.Debounce,
		stopCh:   make(chan struct{}),
	}

	// Add paths to watch
	for _, path := range cfg.Paths {
		// Watch the directory containing the file
		dir := filepath.Dir(path)
		if err := fsWatcher.Add(dir); err != nil {
			fsWatcher.Close()
			return nil, err
		}
	}

	return w, nil
}

// OnChange registers a callback for configuration changes.
func (w *Watcher) OnChange(callback func(*Config, error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks = append(w.callbacks, callback)
}

// Current returns the current configuration.
func (w *Watcher) Current() *Config {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

// Start begins watching for configuration changes.
func (w *Watcher) Start(ctx context.Context) error {
	// Load initial configuration
	if len(w.paths) > 0 {
		cfg, err := w.loader(w.paths[0])
		if err != nil {
			return err
		}
		w.mu.Lock()
		w.current = cfg
		w.mu.Unlock()
	}

	go w.watch(ctx)
	return nil
}

// watch runs the file watching loop.
func (w *Watcher) watch(ctx context.Context) {
	var timer *time.Timer
	var timerMu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			// Check if this event is for one of our watched files
			if !w.isWatchedFile(event.Name) {
				continue
			}

			// Only handle write and create events
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			w.logger.Debug("Config file changed",
				zap.String("file", event.Name),
				zap.String("op", event.Op.String()),
			)

			// Debounce - reset timer on each event
			timerMu.Lock()
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(w.debounce, func() {
				w.reload(event.Name)
			})
			timerMu.Unlock()

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.logger.Error("Config watcher error", zap.Error(err))
		}
	}
}

// isWatchedFile checks if a file path is being watched.
func (w *Watcher) isWatchedFile(path string) bool {
	absPath, _ := filepath.Abs(path)
	for _, watchedPath := range w.paths {
		watchedAbs, _ := filepath.Abs(watchedPath)
		if absPath == watchedAbs {
			return true
		}
	}
	return false
}

// reload loads configuration and notifies callbacks.
func (w *Watcher) reload(path string) {
	w.logger.Info("Reloading configuration", zap.String("path", path))

	cfg, err := w.loader(path)

	w.mu.Lock()
	callbacks := make([]func(*Config, error), len(w.callbacks))
	copy(callbacks, w.callbacks)
	if err == nil {
		w.current = cfg
	}
	w.mu.Unlock()

	// Notify callbacks
	for _, callback := range callbacks {
		callback(cfg, err)
	}

	if err != nil {
		w.logger.Error("Failed to reload configuration",
			zap.String("path", path),
			zap.Error(err),
		)
	} else {
		w.logger.Info("Configuration reloaded successfully",
			zap.String("path", path),
		)
	}
}

// Stop stops watching for changes.
func (w *Watcher) Stop() error {
	close(w.stopCh)
	return w.watcher.Close()
}

// Reload manually triggers a configuration reload.
func (w *Watcher) Reload() error {
	if len(w.paths) == 0 {
		return nil
	}
	w.reload(w.paths[0])
	return nil
}

// HotReloader provides hot-reload functionality for specific components.
type HotReloader struct {
	watcher    *Watcher
	reloaders  map[string]func(*Config) error
	mu         sync.RWMutex
	logger     *zap.Logger
}

// NewHotReloader creates a new hot reloader.
func NewHotReloader(watcher *Watcher, logger *zap.Logger) *HotReloader {
	hr := &HotReloader{
		watcher:   watcher,
		reloaders: make(map[string]func(*Config) error),
		logger:    logger,
	}

	// Register for config changes
	watcher.OnChange(hr.onConfigChange)

	return hr
}

// Register registers a component for hot reload.
func (hr *HotReloader) Register(name string, reloader func(*Config) error) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	hr.reloaders[name] = reloader
}

// Unregister removes a component from hot reload.
func (hr *HotReloader) Unregister(name string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	delete(hr.reloaders, name)
}

// onConfigChange handles configuration changes.
func (hr *HotReloader) onConfigChange(cfg *Config, loadErr error) {
	if loadErr != nil {
		hr.logger.Error("Config load failed, skipping hot reload", zap.Error(loadErr))
		return
	}

	hr.mu.RLock()
	reloaders := make(map[string]func(*Config) error)
	for k, v := range hr.reloaders {
		reloaders[k] = v
	}
	hr.mu.RUnlock()

	for name, reloader := range reloaders {
		if err := reloader(cfg); err != nil {
			hr.logger.Error("Hot reload failed",
				zap.String("component", name),
				zap.Error(err),
			)
		} else {
			hr.logger.Info("Component hot reloaded",
				zap.String("component", name),
			)
		}
	}
}
