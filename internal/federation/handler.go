// Package federation provides the federation handler for multi-origin queries.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Handler orchestrates queries across all configured origins.
type Handler struct {
	origins          map[string]*OriginClient
	router           *CollectionRouter
	merger           *ResultMerger
	maxConcurrent    int
	aggregateTimeout time.Duration
	proxyBaseURL     string
	defaultPageSize  int
	maxPageSize      int
}

// HandlerConfig contains configuration for the federation handler.
type HandlerConfig struct {
	Origins          []*Origin
	ConflictStrategy ConflictStrategy
	MaxConcurrent    int
	AggregateTimeout time.Duration
	ProxyBaseURL     string
	DefaultPageSize  int
	MaxPageSize      int
}

// NewHandler creates a new federation handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	handler := &Handler{
		origins:          make(map[string]*OriginClient),
		router:           NewCollectionRouter(),
		merger:           NewResultMerger(cfg.ConflictStrategy),
		maxConcurrent:    cfg.MaxConcurrent,
		aggregateTimeout: cfg.AggregateTimeout,
		proxyBaseURL:     cfg.ProxyBaseURL,
		defaultPageSize:  cfg.DefaultPageSize,
		maxPageSize:      cfg.MaxPageSize,
	}

	if handler.maxConcurrent <= 0 {
		handler.maxConcurrent = 10
	}
	if handler.aggregateTimeout <= 0 {
		handler.aggregateTimeout = 60 * time.Second
	}
	if handler.defaultPageSize <= 0 {
		handler.defaultPageSize = 100
	}
	if handler.maxPageSize <= 0 {
		handler.maxPageSize = 1000
	}

	// Initialize origin clients
	for _, origin := range cfg.Origins {
		if !origin.Enabled {
			continue
		}

		client, err := NewOriginClient(origin)
		if err != nil {
			return nil, fmt.Errorf("failed to init origin %s: %w", origin.ID, err)
		}

		handler.origins[origin.ID] = client
		handler.router.Register(origin)
	}

	return handler, nil
}

// Handle processes a STAC request by routing to appropriate origins.
func (h *Handler) Handle(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	switch req.RequestType {
	case middleware.RequestTypeSearch:
		return h.handleSearch(ctx, req)
	case middleware.RequestTypeCollections:
		return h.handleGetCollections(ctx, req)
	case middleware.RequestTypeCollection:
		return h.handleGetCollection(ctx, req)
	case middleware.RequestTypeItem:
		return h.handleGetItem(ctx, req)
	default:
		// For other request types, try to proxy to the first available origin
		return h.handleGenericProxy(ctx, req)
	}
}

// handleSearch handles federated search requests.
func (h *Handler) handleSearch(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	searchReq := req.SearchReq
	if searchReq == nil {
		// Parse search request from body or query params
		var err error
		searchReq, err = h.parseSearchRequest(req)
		if err != nil {
			return nil, fmt.Errorf("invalid search request: %w", err)
		}
	}

	// Apply pagination limits
	if searchReq.Limit <= 0 {
		searchReq.Limit = h.defaultPageSize
	}
	if searchReq.Limit > h.maxPageSize {
		searchReq.Limit = h.maxPageSize
	}

	// Determine which origins to query
	origins := h.router.Route(searchReq.Collections)
	if len(origins) == 0 {
		return h.emptySearchResponse(searchReq)
	}

	// Create context with aggregate timeout
	ctx, cancel := context.WithTimeout(ctx, h.aggregateTimeout)
	defer cancel()

	// Fan out requests to origins
	results := h.fanOutSearch(ctx, origins, searchReq)

	// Merge results
	fc, err := h.merger.MergeSearchResults(results, searchReq)
	if err != nil {
		return nil, err
	}

	// Build response
	return h.buildSearchResponse(fc, req)
}

// fanOutSearch executes search requests to multiple origins in parallel.
func (h *Handler) fanOutSearch(ctx context.Context, origins []*Origin,
	searchReq *stac.SearchRequest) []*OriginSearchResult {

	resultsChan := make(chan *OriginSearchResult, len(origins))
	sem := make(chan struct{}, h.maxConcurrent)

	var wg sync.WaitGroup
	for _, origin := range origins {
		wg.Add(1)
		go func(origin *Origin) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result := h.searchOrigin(ctx, origin, searchReq)
			resultsChan <- result
		}(origin)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []*OriginSearchResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// searchOrigin executes a search against a single origin.
func (h *Handler) searchOrigin(ctx context.Context, origin *Origin,
	searchReq *stac.SearchRequest) *OriginSearchResult {

	client := h.origins[origin.ID]

	result := &OriginSearchResult{
		OriginID: origin.ID,
		Priority: origin.Priority,
	}

	// Adapt request for this origin
	adaptedReq := h.adaptRequestForOrigin(searchReq, origin)

	// Execute the search
	start := time.Now()
	fc, err := client.Search(ctx, adaptedReq)
	if m := observability.Default(); m != nil {
		m.UpstreamRequestDuration.WithLabelValues(origin.ID).Observe(time.Since(start).Seconds())
		status := "ok"
		if err != nil {
			status = "error"
			m.UpstreamErrors.WithLabelValues(origin.ID, classifyError(err)).Inc()
		}
		m.UpstreamRequestsTotal.WithLabelValues(origin.ID, status).Inc()
		m.FederationOriginsQueried.WithLabelValues(origin.ID, status).Inc()
	}
	if err != nil {
		result.Error = err
		zap.L().Error("federation origin search failed",
			zap.String("origin", origin.ID),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err))
		return result
	}

	result.Items = fc.Features
	result.Context = fc.Context
	result.Links = fc.Links

	return result
}

// classifyError buckets an upstream error into a short tag suitable
// for use as a Prometheus label cardinality-friendly value.
func classifyError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "network"
}

// adaptRequestForOrigin modifies the search request for a specific origin.
func (h *Handler) adaptRequestForOrigin(req *stac.SearchRequest, origin *Origin) *stac.SearchRequest {
	adapted := *req // Shallow copy

	// Map collection names if the origin uses different names
	if len(origin.CollectionMapping) > 0 {
		var mappedCollections []string
		for _, coll := range adapted.Collections {
			if mapped, ok := origin.CollectionMapping[coll]; ok {
				mappedCollections = append(mappedCollections, mapped)
			} else {
				mappedCollections = append(mappedCollections, coll)
			}
		}
		adapted.Collections = mappedCollections
	}

	// Remove collection prefix if origin uses prefixed names
	if origin.CollectionPrefix != "" {
		for i, coll := range adapted.Collections {
			if len(coll) > len(origin.CollectionPrefix) {
				adapted.Collections[i] = coll[len(origin.CollectionPrefix):]
			}
		}
	}

	return &adapted
}

// handleGetCollections handles GET /collections.
func (h *Handler) handleGetCollections(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	ctx, cancel := context.WithTimeout(ctx, h.aggregateTimeout)
	defer cancel()

	var results []*OriginCollectionsResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for originID, client := range h.origins {
		originID, client := originID, client
		origin := client.Origin()

		wg.Add(1)
		go func() {
			defer wg.Done()

			collections, err := client.GetCollections(ctx)

			mu.Lock()
			defer mu.Unlock()

			result := &OriginCollectionsResult{
				OriginID: originID,
				Error:    err,
			}

			if err == nil {
				// Apply collection prefix
				for i := range collections {
					if origin.CollectionPrefix != "" {
						collections[i].ID = origin.CollectionPrefix + collections[i].ID
					}
					// Add origin metadata
					if collections[i].Properties == nil {
						collections[i].Properties = make(map[string]interface{})
					}
					collections[i].Properties["stac_proxy:origin"] = originID
				}
				result.Collections = collections
			}

			results = append(results, result)
		}()
	}

	wg.Wait()

	// Merge collections
	collections := h.merger.MergeCollections(results)

	// Build response
	resp := &stac.CollectionsResponse{
		Collections: collections,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body,
	}, nil
}

// handleGetCollection handles GET /collections/{collectionId}.
func (h *Handler) handleGetCollection(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	collectionID := req.Collection
	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return &middleware.STACResponse{
			StatusCode: http.StatusNotFound,
			Body:       []byte(`{"code": "NotFound", "description": "Collection not found"}`),
		}, nil
	}

	// Try origins in priority order
	for _, origin := range origins {
		client := h.origins[origin.ID]

		// Remove prefix if present
		lookupID := collectionID
		if origin.CollectionPrefix != "" {
			if len(collectionID) > len(origin.CollectionPrefix) {
				lookupID = collectionID[len(origin.CollectionPrefix):]
			}
		}

		collection, err := client.GetCollection(ctx, lookupID)
		if err != nil {
			continue
		}
		if collection == nil {
			continue
		}

		// Add origin metadata
		if collection.Properties == nil {
			collection.Properties = make(map[string]interface{})
		}
		collection.Properties["stac_proxy:origin"] = origin.ID

		body, err := json.Marshal(collection)
		if err != nil {
			return nil, err
		}

		return &middleware.STACResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body: body,
		}, nil
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusNotFound,
		Body:       []byte(`{"code": "NotFound", "description": "Collection not found"}`),
	}, nil
}

// handleGetItem handles GET /collections/{collectionId}/items/{itemId}.
func (h *Handler) handleGetItem(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	collectionID := req.Collection
	itemID := req.ItemID

	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return &middleware.STACResponse{
			StatusCode: http.StatusNotFound,
			Body:       []byte(`{"code": "NotFound", "description": "Item not found"}`),
		}, nil
	}

	// Try origins in priority order
	for _, origin := range origins {
		client := h.origins[origin.ID]

		// Remove prefix if present
		lookupCollID := collectionID
		if origin.CollectionPrefix != "" {
			if len(collectionID) > len(origin.CollectionPrefix) {
				lookupCollID = collectionID[len(origin.CollectionPrefix):]
			}
		}

		item, err := client.GetItem(ctx, lookupCollID, itemID)
		if err != nil {
			continue
		}
		if item == nil {
			continue
		}

		// Add origin metadata
		if item.Properties.Extra == nil {
			item.Properties.Extra = make(map[string]interface{})
		}
		item.Properties.Extra["stac_proxy:origin"] = origin.ID

		body, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}

		return &middleware.STACResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"Content-Type": []string{"application/geo+json"},
			},
			Body: body,
		}, nil
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusNotFound,
		Body:       []byte(`{"code": "NotFound", "description": "Item not found"}`),
	}, nil
}

// handleGenericProxy proxies requests to the highest priority origin.
func (h *Handler) handleGenericProxy(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	origins := h.router.EnabledOrigins()
	if len(origins) == 0 {
		return &middleware.STACResponse{
			StatusCode: http.StatusServiceUnavailable,
			Body:       []byte(`{"code": "NoOrigins", "description": "No origins available"}`),
		}, nil
	}

	// Use the highest priority origin
	client := h.origins[origins[0].ID]

	resp, err := client.DoRequest(ctx, req.Method, req.URL.Path, req.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	if resp.Body != nil {
		body, _ = json.Marshal(resp.Body)
	}

	return &middleware.STACResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       body,
	}, nil
}

// parseSearchRequest parses a search request from the STAC request.
func (h *Handler) parseSearchRequest(req *middleware.STACRequest) (*stac.SearchRequest, error) {
	searchReq := &stac.SearchRequest{}

	if req.Method == http.MethodPost && req.Body != nil {
		if err := json.NewDecoder(req.Body).Decode(searchReq); err != nil {
			return nil, err
		}
	} else {
		// Parse from query parameters
		q := req.URL.Query()
		if colls := q.Get("collections"); colls != "" {
			searchReq.Collections = []string{colls} // Simplified
		}
		if bbox := q.Get("bbox"); bbox != "" {
			// Parse bbox - simplified
		}
		if datetime := q.Get("datetime"); datetime != "" {
			searchReq.Datetime = datetime
		}
	}

	return searchReq, nil
}

// emptySearchResponse returns an empty feature collection.
func (h *Handler) emptySearchResponse(req *stac.SearchRequest) (*middleware.STACResponse, error) {
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: []stac.Item{},
		Context: &stac.SearchContext{
			Returned: 0,
			Matched:  0,
		},
	}

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// buildSearchResponse builds the HTTP response for search results.
func (h *Handler) buildSearchResponse(fc *stac.FeatureCollection,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// OriginCount returns the number of configured origins.
func (h *Handler) OriginCount() int {
	return len(h.origins)
}

// OriginIDs returns the IDs of all configured origins.
func (h *Handler) OriginIDs() []string {
	ids := make([]string, 0, len(h.origins))
	for id := range h.origins {
		ids = append(ids, id)
	}
	return ids
}
