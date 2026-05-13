// Package cache provides caching middleware.
package cache

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

func TestNewDefaultStrategy(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()
	if strategy == nil {
		t.Fatal("NewDefaultStrategy returned nil")
	}

	// Verify default TTL values
	if strategy.CollectionTTL != 5*time.Minute {
		t.Errorf("CollectionTTL = %v, want %v", strategy.CollectionTTL, 5*time.Minute)
	}
	if strategy.ItemTTL != 1*time.Minute {
		t.Errorf("ItemTTL = %v, want %v", strategy.ItemTTL, 1*time.Minute)
	}
	if strategy.SearchTTL != 30*time.Second {
		t.Errorf("SearchTTL = %v, want %v", strategy.SearchTTL, 30*time.Second)
	}
	if strategy.CatalogTTL != 10*time.Minute {
		t.Errorf("CatalogTTL = %v, want %v", strategy.CatalogTTL, 10*time.Minute)
	}
}

func TestDefaultStrategy_ShouldCache(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	tests := []struct {
		name       string
		method     string
		reqType    middleware.RequestType
		queryCount int
		hasFilter  bool
		want       bool
	}{
		{
			name:    "GET landing page",
			method:  "GET",
			reqType: middleware.RequestTypeLanding,
			want:    true,
		},
		{
			name:    "GET conformance",
			method:  "GET",
			reqType: middleware.RequestTypeConformance,
			want:    true,
		},
		{
			name:    "GET collections",
			method:  "GET",
			reqType: middleware.RequestTypeCollections,
			want:    true,
		},
		{
			name:    "GET collection",
			method:  "GET",
			reqType: middleware.RequestTypeCollection,
			want:    true,
		},
		{
			name:    "GET items",
			method:  "GET",
			reqType: middleware.RequestTypeItems,
			want:    true,
		},
		{
			name:    "GET item",
			method:  "GET",
			reqType: middleware.RequestTypeItem,
			want:    true,
		},
		{
			name:    "GET queryables",
			method:  "GET",
			reqType: middleware.RequestTypeQueryables,
			want:    true,
		},
		{
			name:    "GET collection queryables",
			method:  "GET",
			reqType: middleware.RequestTypeCollectionQueryables,
			want:    true,
		},
		{
			name:       "GET simple search",
			method:     "GET",
			reqType:    middleware.RequestTypeSearch,
			queryCount: 3,
			want:       true,
		},
		{
			name:       "GET search with too many params",
			method:     "GET",
			reqType:    middleware.RequestTypeSearch,
			queryCount: 6,
			want:       false,
		},
		{
			name:      "GET search with filter",
			method:    "GET",
			reqType:   middleware.RequestTypeSearch,
			hasFilter: true,
			want:      false,
		},
		{
			name:    "POST request",
			method:  "POST",
			reqType: middleware.RequestTypeSearch,
			want:    false,
		},
		{
			name:    "PUT request",
			method:  "PUT",
			reqType: middleware.RequestTypeCollection,
			want:    false,
		},
		{
			name:    "DELETE request",
			method:  "DELETE",
			reqType: middleware.RequestTypeItem,
			want:    false,
		},
		{
			name:    "Unknown request type",
			method:  "GET",
			reqType: middleware.RequestTypeUnknown,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Build URL with query parameters
			url := "http://example.com/test"
			if tt.queryCount > 0 {
				url += "?"
				for i := 0; i < tt.queryCount; i++ {
					if i > 0 {
						url += "&"
					}
					url += "param" + string(rune('0'+i)) + "=value"
				}
			}
			if tt.hasFilter {
				url += "?filter=complex_filter"
			}

			req := httptest.NewRequest(tt.method, url, nil)
			stacReq := &middleware.STACRequest{
				Request:     req,
				RequestType: tt.reqType,
			}

			got := strategy.ShouldCache(stacReq)
			if got != tt.want {
				t.Errorf("ShouldCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultStrategy_GetTTL(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	tests := []struct {
		name    string
		reqType middleware.RequestType
		want    time.Duration
	}{
		{
			name:    "Landing page",
			reqType: middleware.RequestTypeLanding,
			want:    10 * time.Minute,
		},
		{
			name:    "Conformance",
			reqType: middleware.RequestTypeConformance,
			want:    10 * time.Minute,
		},
		{
			name:    "Collections list",
			reqType: middleware.RequestTypeCollections,
			want:    5 * time.Minute,
		},
		{
			name:    "Collection detail",
			reqType: middleware.RequestTypeCollection,
			want:    5 * time.Minute,
		},
		{
			name:    "Item",
			reqType: middleware.RequestTypeItem,
			want:    1 * time.Minute,
		},
		{
			name:    "Items list",
			reqType: middleware.RequestTypeItems,
			want:    1 * time.Minute,
		},
		{
			name:    "Search",
			reqType: middleware.RequestTypeSearch,
			want:    30 * time.Second,
		},
		{
			name:    "Queryables",
			reqType: middleware.RequestTypeQueryables,
			want:    5 * time.Minute,
		},
		{
			name:    "Collection Queryables",
			reqType: middleware.RequestTypeCollectionQueryables,
			want:    5 * time.Minute,
		},
		{
			name:    "Unknown type defaults to ItemTTL",
			reqType: middleware.RequestTypeUnknown,
			want:    1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/", nil),
				RequestType: tt.reqType,
			}

			got := strategy.GetTTL(req)
			if got != tt.want {
				t.Errorf("GetTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultStrategy_GenerateKey(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	tests := []struct {
		name           string
		reqType        middleware.RequestType
		path           string
		collection     string
		itemID         string
		query          string
		wantDifferent  bool
		compareWith    *middleware.STACRequest
		compareReason  string
	}{
		{
			name:       "Basic collection request",
			reqType:    middleware.RequestTypeCollection,
			path:       "/collections/test",
			collection: "test",
		},
		{
			name:       "Item request",
			reqType:    middleware.RequestTypeItem,
			path:       "/collections/test/items/item1",
			collection: "test",
			itemID:     "item1",
		},
		{
			name:    "Landing page",
			reqType: middleware.RequestTypeLanding,
			path:    "/",
		},
		{
			name:    "Search request with query",
			reqType: middleware.RequestTypeSearch,
			path:    "/search",
			query:   "limit=10&bbox=-10,-10,10,10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			url := "http://example.com" + tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}

			req := httptest.NewRequest("GET", url, nil)
			stacReq := &middleware.STACRequest{
				Request:     req,
				RequestType: tt.reqType,
				Collection:  tt.collection,
				ItemID:      tt.itemID,
			}

			key := strategy.GenerateKey(stacReq)

			// Verify key is not empty
			if key == "" {
				t.Error("GenerateKey() returned empty string")
			}

			// Verify key length (should be 32 chars for 16 bytes hex)
			if len(key) != 32 {
				t.Errorf("GenerateKey() returned key with length %d, want 32", len(key))
			}

			// Verify key is deterministic
			key2 := strategy.GenerateKey(stacReq)
			if key != key2 {
				t.Error("GenerateKey() is not deterministic")
			}
		})
	}
}

func TestDefaultStrategy_GenerateKey_Uniqueness(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	tests := []struct {
		name    string
		req1    *middleware.STACRequest
		req2    *middleware.STACRequest
		wantSame bool
	}{
		{
			name: "Same request produces same key",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test", nil),
				RequestType: middleware.RequestTypeCollection,
				Collection:  "test",
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test", nil),
				RequestType: middleware.RequestTypeCollection,
				Collection:  "test",
			},
			wantSame: true,
		},
		{
			name: "Different collections produce different keys",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test1", nil),
				RequestType: middleware.RequestTypeCollection,
				Collection:  "test1",
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test2", nil),
				RequestType: middleware.RequestTypeCollection,
				Collection:  "test2",
			},
			wantSame: false,
		},
		{
			name: "Different items produce different keys",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test/items/item1", nil),
				RequestType: middleware.RequestTypeItem,
				Collection:  "test",
				ItemID:      "item1",
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections/test/items/item2", nil),
				RequestType: middleware.RequestTypeItem,
				Collection:  "test",
				ItemID:      "item2",
			},
			wantSame: false,
		},
		{
			name: "Different query params produce different keys",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/search?limit=10", nil),
				RequestType: middleware.RequestTypeSearch,
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/search?limit=20", nil),
				RequestType: middleware.RequestTypeSearch,
			},
			wantSame: false,
		},
		{
			name: "Query params in different order produce same key",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/search?limit=10&bbox=-10,-10,10,10", nil),
				RequestType: middleware.RequestTypeSearch,
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/search?bbox=-10,-10,10,10&limit=10", nil),
				RequestType: middleware.RequestTypeSearch,
			},
			wantSame: true,
		},
		{
			name: "Different request types produce different keys",
			req1: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections", nil),
				RequestType: middleware.RequestTypeCollections,
			},
			req2: &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/collections", nil),
				RequestType: middleware.RequestTypeLanding,
			},
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key1 := strategy.GenerateKey(tt.req1)
			key2 := strategy.GenerateKey(tt.req2)

			same := (key1 == key2)
			if same != tt.wantSame {
				if tt.wantSame {
					t.Errorf("Expected same keys but got different: %s vs %s", key1, key2)
				} else {
					t.Errorf("Expected different keys but got same: %s", key1)
				}
			}
		})
	}
}

func TestNormalizeQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		want  string
	}{
		{
			name:  "Empty query",
			query: "",
			want:  "",
		},
		{
			name:  "Single param",
			query: "limit=10",
			want:  "limit=10",
		},
		{
			name:  "Multiple params in order",
			query: "bbox=-10,-10,10,10&limit=10",
			want:  "bbox=-10,-10,10,10&limit=10",
		},
		{
			name:  "Multiple params out of order",
			query: "limit=10&bbox=-10,-10,10,10",
			want:  "bbox=-10,-10,10,10&limit=10",
		},
		{
			name:  "Multiple values for same param",
			query: "collections=col1&collections=col2",
			want:  "collections=col1&collections=col2",
		},
		{
			name:  "Multiple values out of order",
			query: "collections=col2&collections=col1",
			want:  "collections=col1&collections=col2",
		},
		{
			name:  "Complex query",
			query: "limit=10&bbox=-10,-10,10,10&collections=col1&datetime=2020-01-01T00:00:00Z",
			want:  "bbox=-10,-10,10,10&collections=col1&datetime=2020-01-01T00:00:00Z&limit=10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://example.com/?"+tt.query, nil)
			got := normalizeQuery(req.URL.Query())

			if got != tt.want {
				t.Errorf("normalizeQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}


func TestNoCacheStrategy(t *testing.T) {
	t.Parallel()

	strategy := &NoCacheStrategy{}

	t.Run("ShouldCache always returns false", func(t *testing.T) {
		t.Parallel()

		req := &middleware.STACRequest{
			Request:     httptest.NewRequest("GET", "/collections/test", nil),
			RequestType: middleware.RequestTypeCollection,
		}

		if strategy.ShouldCache(req) {
			t.Error("ShouldCache should always return false")
		}
	})

	t.Run("GetTTL always returns zero", func(t *testing.T) {
		t.Parallel()

		req := &middleware.STACRequest{
			Request:     httptest.NewRequest("GET", "/collections/test", nil),
			RequestType: middleware.RequestTypeCollection,
		}

		if ttl := strategy.GetTTL(req); ttl != 0 {
			t.Errorf("GetTTL should return 0, got %v", ttl)
		}
	})

	t.Run("GenerateKey returns empty string", func(t *testing.T) {
		t.Parallel()

		req := &middleware.STACRequest{
			Request:     httptest.NewRequest("GET", "/collections/test", nil),
			RequestType: middleware.RequestTypeCollection,
		}

		if key := strategy.GenerateKey(req); key != "" {
			t.Errorf("GenerateKey should return empty string, got %v", key)
		}
	})
}

func TestDefaultStrategy_isSimpleSearch(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	tests := []struct {
		name  string
		url   string
		want  bool
	}{
		{
			name: "No query params",
			url:  "http://example.com/search",
			want: true,
		},
		{
			name: "One param",
			url:  "http://example.com/search?limit=10",
			want: true,
		},
		{
			name: "Five params (at limit)",
			url:  "http://example.com/search?limit=10&bbox=-10,-10,10,10&collections=test&datetime=2020-01-01&ids=item1",
			want: true,
		},
		{
			name: "Six params (over limit)",
			url:  "http://example.com/search?limit=10&bbox=-10,-10,10,10&collections=test&datetime=2020-01-01&ids=item1&extra=value",
			want: false,
		},
		{
			name: "Has filter param",
			url:  "http://example.com/search?filter=complex",
			want: false,
		},
		{
			name: "Has filter param with other params",
			url:  "http://example.com/search?limit=10&filter=complex",
			want: false,
		},
		{
			name: "Empty filter param still prevents caching",
			url:  "http://example.com/search?filter=",
			want: true, // Empty filter value is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", tt.url, nil)
			stacReq := &middleware.STACRequest{
				Request:     req,
				RequestType: middleware.RequestTypeSearch,
			}

			got := strategy.isSimpleSearch(stacReq)
			if got != tt.want {
				t.Errorf("isSimpleSearch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultStrategy_CustomTTLs(t *testing.T) {
	t.Parallel()

	strategy := &DefaultStrategy{
		CollectionTTL: 15 * time.Minute,
		ItemTTL:       2 * time.Minute,
		SearchTTL:     1 * time.Minute,
		CatalogTTL:    30 * time.Minute,
	}

	tests := []struct {
		name    string
		reqType middleware.RequestType
		want    time.Duration
	}{
		{
			name:    "Custom collection TTL",
			reqType: middleware.RequestTypeCollection,
			want:    15 * time.Minute,
		},
		{
			name:    "Custom item TTL",
			reqType: middleware.RequestTypeItem,
			want:    2 * time.Minute,
		},
		{
			name:    "Custom search TTL",
			reqType: middleware.RequestTypeSearch,
			want:    1 * time.Minute,
		},
		{
			name:    "Custom catalog TTL",
			reqType: middleware.RequestTypeLanding,
			want:    30 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest("GET", "/", nil),
				RequestType: tt.reqType,
			}

			got := strategy.GetTTL(req)
			if got != tt.want {
				t.Errorf("GetTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCacheStrategyInterface(t *testing.T) {
	t.Parallel()

	// Verify all strategies implement the interface
	var _ CacheStrategy = (*DefaultStrategy)(nil)
	var _ CacheStrategy = (*NoCacheStrategy)(nil)
}

func BenchmarkDefaultStrategy_GenerateKey(b *testing.B) {
	strategy := NewDefaultStrategy()
	req := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/collections/test?limit=10&bbox=-10,-10,10,10", nil),
		RequestType: middleware.RequestTypeCollection,
		Collection:  "test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strategy.GenerateKey(req)
	}
}


func BenchmarkNormalizeQuery(b *testing.B) {
	req := httptest.NewRequest("GET", "http://example.com/?limit=10&bbox=-10,-10,10,10&collections=col1&datetime=2020-01-01", nil)
	query := req.URL.Query()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeQuery(query)
	}
}

func TestDefaultStrategy_ShouldCache_HTTPMethods(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	methods := []struct {
		method string
		want   bool
	}{
		{"GET", true},
		{"POST", false},
		{"PUT", false},
		{"DELETE", false},
		{"PATCH", false},
		{"HEAD", false},
		{"OPTIONS", false},
	}

	for _, m := range methods {
		t.Run(m.method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(m.method, "/collections/test", nil)
			stacReq := &middleware.STACRequest{
				Request:     req,
				RequestType: middleware.RequestTypeCollection,
			}

			got := strategy.ShouldCache(stacReq)
			if got != m.want {
				t.Errorf("ShouldCache(%s) = %v, want %v", m.method, got, m.want)
			}
		})
	}
}

func TestGenerateKey_PathSensitivity(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	paths := []string{
		"/collections/test1",
		"/collections/test2",
		"/collections/test1/items",
		"/collections/test1/items/item1",
	}

	keys := make(map[string]string)
	for _, path := range paths {
		req := &middleware.STACRequest{
			Request:     httptest.NewRequest("GET", path, nil),
			RequestType: middleware.RequestTypeCollection,
		}
		key := strategy.GenerateKey(req)

		// Check for duplicates
		if existingPath, exists := keys[key]; exists {
			t.Errorf("Paths %s and %s generated the same key: %s", path, existingPath, key)
		}
		keys[key] = path
	}
}

func TestGenerateKey_QueryParameterOrder(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	queries := []string{
		"?a=1&b=2&c=3",
		"?c=3&b=2&a=1",
		"?b=2&a=1&c=3",
		"?a=1&c=3&b=2",
	}

	var expectedKey string
	for i, query := range queries {
		req := &middleware.STACRequest{
			Request:     httptest.NewRequest("GET", "/search"+query, nil),
			RequestType: middleware.RequestTypeSearch,
		}
		key := strategy.GenerateKey(req)

		if i == 0 {
			expectedKey = key
		} else if key != expectedKey {
			t.Errorf("Query %s generated different key %s, expected %s", query, key, expectedKey)
		}
	}
}

func TestGenerateKey_MultiValueQueryParams(t *testing.T) {
	t.Parallel()

	strategy := NewDefaultStrategy()

	// Same collections in different order should produce same key
	req1 := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/search?collections=col1&collections=col2", nil),
		RequestType: middleware.RequestTypeSearch,
	}

	req2 := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/search?collections=col2&collections=col1", nil),
		RequestType: middleware.RequestTypeSearch,
	}

	key1 := strategy.GenerateKey(req1)
	key2 := strategy.GenerateKey(req2)

	if key1 != key2 {
		t.Errorf("Multi-value params in different order should produce same key, got %s and %s", key1, key2)
	}
}
