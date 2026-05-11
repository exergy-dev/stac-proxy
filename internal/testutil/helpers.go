// Package testutil provides test fixtures, mocks, and helpers.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// MustParseJSON parses JSON into a map, failing the test on error.
func MustParseJSON(t *testing.T, data string) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	return result
}

// MustMarshalJSON marshals a value to JSON, failing the test on error.
func MustMarshalJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	return data
}

// AssertItemsEqual asserts that two item slices are equal.
func AssertItemsEqual(t *testing.T, expected, actual []*stac.Item) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("item count mismatch: expected %d, got %d", len(expected), len(actual))
		return
	}
	for i := range expected {
		if expected[i].ID != actual[i].ID {
			t.Errorf("item[%d] ID mismatch: expected %s, got %s", i, expected[i].ID, actual[i].ID)
		}
	}
}

// AssertItemIDs asserts that items have the expected IDs in order.
func AssertItemIDs(t *testing.T, items []*stac.Item, expectedIDs ...string) {
	t.Helper()
	if len(items) != len(expectedIDs) {
		t.Errorf("item count mismatch: expected %d, got %d", len(expectedIDs), len(items))
		return
	}
	for i, id := range expectedIDs {
		if items[i].ID != id {
			t.Errorf("item[%d] ID mismatch: expected %s, got %s", i, id, items[i].ID)
		}
	}
}

// AssertNoError asserts that an error is nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// AssertError asserts that an error is not nil.
func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("expected error but got nil")
	}
}

// AssertEqual asserts that two values are equal using reflect.DeepEqual.
func AssertEqual(t *testing.T, expected, actual interface{}) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("values not equal:\nexpected: %v\nactual:   %v", expected, actual)
	}
}

// AssertTrue asserts that a condition is true.
func AssertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Errorf("assertion failed: %s", msg)
	}
}

// AssertFalse asserts that a condition is false.
func AssertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Errorf("assertion failed (expected false): %s", msg)
	}
}

// NewTestServer creates a test HTTP server with the given handler.
func NewTestServer(handler http.Handler) *httptest.Server {
	return httptest.NewServer(handler)
}

// NewTestServerWithResponse creates a test server that returns a fixed response.
func NewTestServerWithResponse(statusCode int, body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
}

// NewTestServerWithJSONResponse creates a test server returning JSON.
func NewTestServerWithJSONResponse(body interface{}) *httptest.Server {
	return NewTestServerWithResponse(http.StatusOK, body)
}

// NewTestServerWithError creates a test server that returns an error.
func NewTestServerWithError(statusCode int, message string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
	}))
}

// NewTestServerWithDelay creates a test server that delays before responding.
func NewTestServerWithDelay(delay time.Duration, body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		if body != nil {
			json.NewEncoder(w).Encode(body)
		}
	}))
}

// NewSTACRequest creates a STACRequest for testing.
func NewSTACRequest(method, path string, body interface{}) *middleware.STACRequest {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")

	return &middleware.STACRequest{
		Request:     req,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		Params:      make(map[string]interface{}),
	}
}

// NewSearchRequest creates a STACRequest for search testing.
func NewSearchRequest(searchReq *stac.SearchRequest) *middleware.STACRequest {
	return NewSTACRequest(http.MethodPost, "/search", searchReq)
}

// NewCollectionRequest creates a STACRequest for collection testing.
func NewCollectionRequest(collectionID string) *middleware.STACRequest {
	req := NewSTACRequest(http.MethodGet, "/collections/"+collectionID, nil)
	req.RequestType = middleware.RequestTypeCollection
	req.Collection = collectionID
	return req
}

// NewItemRequest creates a STACRequest for item testing.
func NewItemRequest(collectionID, itemID string) *middleware.STACRequest {
	req := NewSTACRequest(http.MethodGet, "/collections/"+collectionID+"/items/"+itemID, nil)
	req.RequestType = middleware.RequestTypeItem
	req.Collection = collectionID
	req.ItemID = itemID
	return req
}

// ContextWithTimeout creates a context with timeout for testing.
func ContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// TestHTTPClient creates an HTTP client using the given transport.
func TestHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}

// CaptureRequestHandler creates a handler that captures requests.
type CaptureRequestHandler struct {
	Requests []*http.Request
	Response interface{}
	Status   int
}

// ServeHTTP implements http.Handler.
func (h *CaptureRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read and replace body so it can be read again
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	h.Requests = append(h.Requests, r)

	w.Header().Set("Content-Type", "application/json")
	if h.Status != 0 {
		w.WriteHeader(h.Status)
	}
	if h.Response != nil {
		json.NewEncoder(w).Encode(h.Response)
	}
}

// GenerateItems generates n sample items with sequential IDs.
func GenerateItems(n int, prefix string) []*stac.Item {
	items := make([]*stac.Item, n)
	for i := 0; i < n; i++ {
		items[i] = SampleItem(prefix + string(rune('0'+i)))
	}
	return items
}

// GenerateItemsWithDatetime generates items with sequential datetimes.
func GenerateItemsWithDatetime(n int, prefix string, startTime time.Time, interval time.Duration) []*stac.Item {
	items := make([]*stac.Item, n)
	for i := 0; i < n; i++ {
		dt := startTime.Add(time.Duration(i) * interval)
		items[i] = SampleItem(prefix+string(rune('0'+i)), WithDatetime(dt))
	}
	return items
}

// ContainsItemID checks if items contain an item with the given ID.
func ContainsItemID(items []*stac.Item, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

// GetItemByID finds an item by ID in a slice.
func GetItemByID(items []*stac.Item, id string) *stac.Item {
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	return nil
}

// ItemIDSet returns a set of item IDs.
func ItemIDSet(items []*stac.Item) map[string]bool {
	set := make(map[string]bool)
	for _, item := range items {
		set[item.ID] = true
	}
	return set
}
