package federation

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestNewFederatedCursor tests cursor creation
func TestNewFederatedCursor(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		t.Parallel()

		queryHash := "test-query-hash"
		originIDs := []string{"origin1", "origin2", "origin3"}

		cursor := NewFederatedCursor(queryHash, originIDs, nil)

		if cursor == nil {
			t.Fatal("expected cursor to be non-nil")
		}

		if cursor.Version != 1 {
			t.Errorf("expected version 1, got %d", cursor.Version)
		}

		if cursor.QueryHash != queryHash {
			t.Errorf("expected query hash %q, got %q", queryHash, cursor.QueryHash)
		}

		if len(cursor.Origins) != len(originIDs) {
			t.Errorf("expected %d origins, got %d", len(originIDs), len(cursor.Origins))
		}

		for _, id := range originIDs {
			origin, ok := cursor.Origins[id]
			if !ok {
				t.Errorf("expected origin %q to exist", id)
				continue
			}
			if origin.ID != id {
				t.Errorf("expected origin ID %q, got %q", id, origin.ID)
			}
			if origin.Exhausted {
				t.Error("new origin should not be exhausted")
			}
			if origin.Error {
				t.Error("new origin should not have error")
			}
			if origin.ItemCount != 0 {
				t.Errorf("expected item count 0, got %d", origin.ItemCount)
			}
		}

		if cursor.TotalReturned != 0 {
			t.Errorf("expected total returned 0, got %d", cursor.TotalReturned)
		}

		if cursor.CreatedAt == 0 {
			t.Error("expected created at to be set")
		}

		if cursor.ExpiresAt == 0 {
			t.Error("expected expires at to be set")
		}

		expectedExpiry := cursor.CreatedAt + int64(time.Hour.Seconds())
		if cursor.ExpiresAt != expectedExpiry {
			t.Errorf("expected expiry at %d, got %d", expectedExpiry, cursor.ExpiresAt)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		t.Parallel()

		cfg := &CursorConfig{
			DefaultTTL: 30 * time.Minute,
			MaxTTL:     2 * time.Hour,
		}

		cursor := NewFederatedCursor("hash", []string{"origin1"}, cfg)

		expectedExpiry := cursor.CreatedAt + int64((30 * time.Minute).Seconds())
		if cursor.ExpiresAt != expectedExpiry {
			t.Errorf("expected expiry at %d, got %d", expectedExpiry, cursor.ExpiresAt)
		}
	})

	t.Run("with empty origin list", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{}, nil)

		if cursor == nil {
			t.Fatal("expected cursor to be non-nil")
		}

		if len(cursor.Origins) != 0 {
			t.Errorf("expected 0 origins, got %d", len(cursor.Origins))
		}
	})

	t.Run("with nil origin list", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", nil, nil)

		if cursor == nil {
			t.Fatal("expected cursor to be non-nil")
		}

		if cursor.Origins == nil {
			t.Error("expected origins map to be initialized")
		}

		if len(cursor.Origins) != 0 {
			t.Errorf("expected 0 origins, got %d", len(cursor.Origins))
		}
	})
}

// TestEncodeDecodeRoundTrip tests encoding and decoding
func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Run("basic cursor", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("query-hash", []string{"origin1", "origin2"}, nil)
		original.TotalReturned = 50

		encoded, err := original.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		if encoded == "" {
			t.Fatal("expected non-empty encoded string")
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, original, decoded)
	})

	t.Run("cursor with origin state", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)
		original.Origins["origin1"].NextToken = "token1"
		original.Origins["origin1"].ItemCount = 10
		original.Origins["origin2"].NextURL = "https://example.com/next"
		original.Origins["origin2"].Offset = 20
		original.Origins["origin3"].Exhausted = true
		original.TotalReturned = 30

		encoded, err := original.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, original, decoded)
	})

	t.Run("cursor with last sort values", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.LastSortValues = []interface{}{"2023-01-01", 123.45}
		original.Origins["origin1"].LastSortValue = "value1"

		encoded, err := original.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, original, decoded)
	})

	t.Run("cursor with mixed origin states", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"active", "exhausted", "error"}, nil)
		original.Origins["active"].NextToken = "next"
		original.Origins["active"].ItemCount = 5
		original.Origins["exhausted"].Exhausted = true
		original.Origins["error"].Error = true

		encoded, err := original.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, original, decoded)
	})
}

// TestDecodeCursor tests cursor decoding with various inputs
func TestDecodeCursor(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		t.Parallel()

		_, err := DecodeCursor("")
		if err == nil {
			t.Error("expected error for empty cursor")
		}
		if err.Error() != "empty cursor" {
			t.Errorf("expected 'empty cursor' error, got %v", err)
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		t.Parallel()

		_, err := DecodeCursor("not-valid-base64!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
		if !strings.Contains(err.Error(), "invalid cursor encoding") {
			t.Errorf("expected 'invalid cursor encoding' error, got %v", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()

		invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{invalid json}"))
		_, err := DecodeCursor(invalidJSON)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
		if !strings.Contains(err.Error(), "invalid cursor data") {
			t.Errorf("expected 'invalid cursor data' error, got %v", err)
		}
	})

	t.Run("expired cursor", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		// Set expiry to 1 hour ago
		cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		_, err = DecodeCursor(encoded)
		if err == nil {
			t.Error("expected error for expired cursor")
		}
		if err.Error() != "cursor expired" {
			t.Errorf("expected 'cursor expired' error, got %v", err)
		}
	})

	t.Run("cursor at exact expiry moment", func(t *testing.T) {
		// Not parallel because we need precise timing

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		// Set expiry to just barely in the future (1 second)
		cursor.ExpiresAt = time.Now().Add(1 * time.Second).Unix()

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Should decode successfully
		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Errorf("expected success, got error: %v", err)
		}
		if decoded == nil {
			t.Error("expected non-nil decoded cursor")
		}
	})

	t.Run("valid cursor far in future", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Errorf("expected success, got error: %v", err)
		}
		if decoded == nil {
			t.Error("expected non-nil decoded cursor")
		}
	})
}

// TestIsExpired tests cursor expiration
func TestIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		if cursor.IsExpired() {
			t.Error("newly created cursor should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

		if !cursor.IsExpired() {
			t.Error("cursor with past expiry should be expired")
		}
	})

	t.Run("expires at boundary", func(t *testing.T) {
		// Not parallel because we need precise timing

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Unix()

		// At the exact moment, it might be expired or not depending on timing
		// Sleep a tiny bit to ensure we're past it
		time.Sleep(10 * time.Millisecond)

		if !cursor.IsExpired() {
			t.Error("cursor at expiry boundary should be expired after waiting")
		}
	})

	t.Run("zero expiry", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = 0

		if !cursor.IsExpired() {
			t.Error("cursor with zero expiry should be expired")
		}
	})

	t.Run("far future expiry", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(100 * 365 * 24 * time.Hour).Unix() // 100 years

		if cursor.IsExpired() {
			t.Error("cursor with far future expiry should not be expired")
		}
	})
}

// TestHasMore tests whether cursor has more results
func TestHasMore(t *testing.T) {
	t.Run("all origins active", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)

		if !cursor.HasMore() {
			t.Error("cursor with active origins should have more")
		}
	})

	t.Run("some origins exhausted", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)
		cursor.Origins["origin1"].Exhausted = true
		cursor.Origins["origin2"].Exhausted = true

		if !cursor.HasMore() {
			t.Error("cursor with at least one active origin should have more")
		}
	})

	t.Run("all origins exhausted", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)
		cursor.Origins["origin1"].Exhausted = true
		cursor.Origins["origin2"].Exhausted = true

		if cursor.HasMore() {
			t.Error("cursor with all exhausted origins should not have more")
		}
	})

	t.Run("some origins have errors", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)
		cursor.Origins["origin1"].Error = true
		cursor.Origins["origin2"].Exhausted = true

		if !cursor.HasMore() {
			t.Error("cursor with at least one active origin should have more")
		}
	})

	t.Run("all origins have errors", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)
		cursor.Origins["origin1"].Error = true
		cursor.Origins["origin2"].Error = true

		if cursor.HasMore() {
			t.Error("cursor with all error origins should not have more")
		}
	})

	t.Run("mixed states", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"active", "exhausted", "error", "also-exhausted"}, nil)
		cursor.Origins["exhausted"].Exhausted = true
		cursor.Origins["error"].Error = true
		cursor.Origins["also-exhausted"].Exhausted = true

		if !cursor.HasMore() {
			t.Error("cursor with one active origin should have more")
		}
	})

	t.Run("empty origins", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{}, nil)

		if cursor.HasMore() {
			t.Error("cursor with no origins should not have more")
		}
	})
}

// TestActiveOrigins tests getting active origin IDs
func TestActiveOrigins(t *testing.T) {
	t.Run("all origins active", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)

		active := cursor.ActiveOrigins()
		if len(active) != 3 {
			t.Errorf("expected 3 active origins, got %d", len(active))
		}

		// Should be sorted
		expected := []string{"origin1", "origin2", "origin3"}
		for i, id := range expected {
			if active[i] != id {
				t.Errorf("expected active[%d] = %q, got %q", i, id, active[i])
			}
		}
	})

	t.Run("some origins inactive", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3", "origin4"}, nil)
		cursor.Origins["origin2"].Exhausted = true
		cursor.Origins["origin4"].Error = true

		active := cursor.ActiveOrigins()
		if len(active) != 2 {
			t.Errorf("expected 2 active origins, got %d", len(active))
		}

		expected := []string{"origin1", "origin3"}
		for i, id := range expected {
			if active[i] != id {
				t.Errorf("expected active[%d] = %q, got %q", i, id, active[i])
			}
		}
	})

	t.Run("no active origins", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)
		cursor.Origins["origin1"].Exhausted = true
		cursor.Origins["origin2"].Error = true

		active := cursor.ActiveOrigins()
		if len(active) != 0 {
			t.Errorf("expected 0 active origins, got %d", len(active))
		}
	})

	t.Run("sorted alphabetically", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"zebra", "alpha", "mike", "charlie"}, nil)

		active := cursor.ActiveOrigins()
		expected := []string{"alpha", "charlie", "mike", "zebra"}

		for i, id := range expected {
			if active[i] != id {
				t.Errorf("expected active[%d] = %q, got %q", i, id, active[i])
			}
		}
	})
}

// TestMarkExhausted tests marking origins as exhausted
func TestMarkExhausted(t *testing.T) {
	t.Run("mark existing origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextToken = "token"
		cursor.Origins["origin1"].NextURL = "url"

		cursor.MarkExhausted("origin1")

		origin := cursor.Origins["origin1"]
		if !origin.Exhausted {
			t.Error("origin should be marked exhausted")
		}
		if origin.NextToken != "" {
			t.Error("next token should be cleared")
		}
		if origin.NextURL != "" {
			t.Error("next URL should be cleared")
		}
	})

	t.Run("mark non-existent origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		// Should not panic
		cursor.MarkExhausted("non-existent")

		// Should not add the origin
		if _, ok := cursor.Origins["non-existent"]; ok {
			t.Error("non-existent origin should not be added")
		}
	})

	t.Run("preserves other state", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.Origins["origin1"].ItemCount = 100
		cursor.Origins["origin1"].Offset = 50
		cursor.Origins["origin1"].LastSortValue = "value"

		cursor.MarkExhausted("origin1")

		origin := cursor.Origins["origin1"]
		if origin.ItemCount != 100 {
			t.Error("item count should be preserved")
		}
		if origin.Offset != 50 {
			t.Error("offset should be preserved")
		}
		if origin.LastSortValue != "value" {
			t.Error("last sort value should be preserved")
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.MarkExhausted("origin1")
		cursor.MarkExhausted("origin1")
		cursor.MarkExhausted("origin1")

		origin := cursor.Origins["origin1"]
		if !origin.Exhausted {
			t.Error("origin should remain exhausted")
		}
	})
}

// TestMarkError tests marking origins as having errors
func TestMarkError(t *testing.T) {
	t.Run("mark existing origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.MarkError("origin1")

		origin := cursor.Origins["origin1"]
		if !origin.Error {
			t.Error("origin should be marked with error")
		}
	})

	t.Run("mark non-existent origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		// Should not panic
		cursor.MarkError("non-existent")

		// Should not add the origin
		if _, ok := cursor.Origins["non-existent"]; ok {
			t.Error("non-existent origin should not be added")
		}
	})

	t.Run("preserves other state", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextToken = "token"
		cursor.Origins["origin1"].ItemCount = 50
		cursor.Origins["origin1"].Exhausted = false

		cursor.MarkError("origin1")

		origin := cursor.Origins["origin1"]
		if origin.NextToken != "token" {
			t.Error("next token should be preserved")
		}
		if origin.ItemCount != 50 {
			t.Error("item count should be preserved")
		}
		if origin.Exhausted {
			t.Error("exhausted state should be preserved")
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.MarkError("origin1")
		cursor.MarkError("origin1")
		cursor.MarkError("origin1")

		origin := cursor.Origins["origin1"]
		if !origin.Error {
			t.Error("origin should remain marked with error")
		}
	})
}

// TestUpdateOrigin tests updating origin cursor state
func TestUpdateOrigin(t *testing.T) {
	t.Run("update existing origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "next-token", "next-url", "sort-value")

		origin := cursor.Origins["origin1"]
		if origin.ItemCount != 10 {
			t.Errorf("expected item count 10, got %d", origin.ItemCount)
		}
		if origin.NextToken != "next-token" {
			t.Errorf("expected next token 'next-token', got %q", origin.NextToken)
		}
		if origin.NextURL != "next-url" {
			t.Errorf("expected next URL 'next-url', got %q", origin.NextURL)
		}
		if origin.LastSortValue != "sort-value" {
			t.Errorf("expected last sort value 'sort-value', got %v", origin.LastSortValue)
		}
		if origin.Exhausted {
			t.Error("origin should not be exhausted when tokens are present")
		}
	})

	t.Run("update creates new origin if not exists", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{}, nil)

		cursor.UpdateOrigin("new-origin", 5, "token", "", nil)

		origin, ok := cursor.Origins["new-origin"]
		if !ok {
			t.Fatal("expected new origin to be created")
		}
		if origin.ID != "new-origin" {
			t.Errorf("expected origin ID 'new-origin', got %q", origin.ID)
		}
		if origin.ItemCount != 5 {
			t.Errorf("expected item count 5, got %d", origin.ItemCount)
		}
	})

	t.Run("marks exhausted when no next token or URL", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "", "", nil)

		origin := cursor.Origins["origin1"]
		if !origin.Exhausted {
			t.Error("origin should be marked exhausted when no next token/URL")
		}
	})

	t.Run("not exhausted with only next token", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "token", "", nil)

		origin := cursor.Origins["origin1"]
		if origin.Exhausted {
			t.Error("origin should not be exhausted with next token")
		}
	})

	t.Run("not exhausted with only next URL", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "", "url", nil)

		origin := cursor.Origins["origin1"]
		if origin.Exhausted {
			t.Error("origin should not be exhausted with next URL")
		}
	})

	t.Run("increments item count", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "token", "", nil)
		cursor.UpdateOrigin("origin1", 15, "token2", "", nil)
		cursor.UpdateOrigin("origin1", 5, "", "", nil)

		origin := cursor.Origins["origin1"]
		if origin.ItemCount != 30 {
			t.Errorf("expected cumulative item count 30, got %d", origin.ItemCount)
		}
	})

	t.Run("updates sort value", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 5, "token", "", "value1")
		if cursor.Origins["origin1"].LastSortValue != "value1" {
			t.Error("expected last sort value to be updated")
		}

		cursor.UpdateOrigin("origin1", 5, "token", "", "value2")
		if cursor.Origins["origin1"].LastSortValue != "value2" {
			t.Error("expected last sort value to be overwritten")
		}
	})

	t.Run("with nil sort value", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOrigin("origin1", 10, "token", "", nil)

		origin := cursor.Origins["origin1"]
		if origin.LastSortValue != nil {
			t.Errorf("expected nil sort value, got %v", origin.LastSortValue)
		}
	})
}

// TestUpdateOffset tests updating offset-based pagination
func TestUpdateOffset(t *testing.T) {
	t.Run("update existing origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOffset("origin1", 100)

		origin := cursor.Origins["origin1"]
		if origin.Offset != 100 {
			t.Errorf("expected offset 100, got %d", origin.Offset)
		}
	})

	t.Run("update non-existent origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		// Should not panic
		cursor.UpdateOffset("non-existent", 50)

		// Should not create the origin
		if _, ok := cursor.Origins["non-existent"]; ok {
			t.Error("non-existent origin should not be created")
		}
	})

	t.Run("multiple updates", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		cursor.UpdateOffset("origin1", 10)
		cursor.UpdateOffset("origin1", 20)
		cursor.UpdateOffset("origin1", 30)

		origin := cursor.Origins["origin1"]
		if origin.Offset != 30 {
			t.Errorf("expected offset 30, got %d", origin.Offset)
		}
	})
}

// TestClone tests deep copying of cursors
func TestClone(t *testing.T) {
	t.Run("basic clone", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)
		original.TotalReturned = 50
		original.Origins["origin1"].ItemCount = 25
		original.Origins["origin2"].NextToken = "token"

		cloned := original.Clone()

		assertCursorsEqual(t, original, cloned)
	})

	t.Run("no shared references - modify original", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.Origins["origin1"].NextToken = "token1"
		original.LastSortValues = []interface{}{"value1"}

		cloned := original.Clone()

		// Modify original
		original.TotalReturned = 100
		original.Origins["origin1"].NextToken = "modified"
		original.Origins["origin1"].ItemCount = 999
		original.LastSortValues[0] = "modified"

		// Cloned should remain unchanged
		if cloned.TotalReturned == 100 {
			t.Error("cloned total returned should not change")
		}
		if cloned.Origins["origin1"].NextToken == "modified" {
			t.Error("cloned origin token should not change")
		}
		if cloned.Origins["origin1"].ItemCount == 999 {
			t.Error("cloned origin item count should not change")
		}
		if cloned.LastSortValues[0] == "modified" {
			t.Error("cloned last sort values should not change")
		}
	})

	t.Run("no shared references - modify clone", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.Origins["origin1"].NextURL = "url1"

		cloned := original.Clone()

		// Modify clone
		cloned.QueryHash = "different"
		cloned.Origins["origin1"].NextURL = "modified"
		cloned.Origins["origin1"].Exhausted = true

		// Original should remain unchanged
		if original.QueryHash == "different" {
			t.Error("original query hash should not change")
		}
		if original.Origins["origin1"].NextURL == "modified" {
			t.Error("original origin URL should not change")
		}
		if original.Origins["origin1"].Exhausted {
			t.Error("original origin exhausted state should not change")
		}
	})

	t.Run("no shared origins map", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cloned := original.Clone()

		// Add to original
		original.Origins["origin2"] = &OriginCursor{ID: "origin2"}

		// Clone should not have it
		if _, ok := cloned.Origins["origin2"]; ok {
			t.Error("clone should not have origin added to original")
		}

		// Add to clone
		cloned.Origins["origin3"] = &OriginCursor{ID: "origin3"}

		// Original should not have it
		if _, ok := original.Origins["origin3"]; ok {
			t.Error("original should not have origin added to clone")
		}
	})

	t.Run("clone with nil last sort values", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.LastSortValues = nil

		cloned := original.Clone()

		if cloned.LastSortValues != nil {
			t.Error("cloned last sort values should be nil")
		}
	})

	t.Run("clone with empty last sort values", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.LastSortValues = []interface{}{}

		cloned := original.Clone()

		if cloned.LastSortValues == nil {
			t.Error("cloned last sort values should not be nil")
		}
		if len(cloned.LastSortValues) != 0 {
			t.Error("cloned last sort values should be empty")
		}
	})

	t.Run("clone preserves all origin fields", func(t *testing.T) {
		t.Parallel()

		original := NewFederatedCursor("hash", []string{"origin1"}, nil)
		original.Origins["origin1"].NextToken = "token"
		original.Origins["origin1"].NextURL = "url"
		original.Origins["origin1"].Offset = 50
		original.Origins["origin1"].Exhausted = true
		original.Origins["origin1"].Error = true
		original.Origins["origin1"].ItemCount = 100
		original.Origins["origin1"].LastSortValue = "value"

		cloned := original.Clone()

		assertOriginCursorEqual(t, original.Origins["origin1"], cloned.Origins["origin1"])
	})
}

// TestGetOriginCursor tests retrieving origin cursors
func TestGetOriginCursor(t *testing.T) {
	t.Run("get existing origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		origin := cursor.GetOriginCursor("origin1")
		if origin == nil {
			t.Fatal("expected origin to exist")
		}
		if origin.ID != "origin1" {
			t.Errorf("expected origin ID 'origin1', got %q", origin.ID)
		}
	})

	t.Run("get non-existent origin", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		origin := cursor.GetOriginCursor("non-existent")
		if origin != nil {
			t.Error("expected nil for non-existent origin")
		}
	})
}

// TestString tests string representation
func TestString(t *testing.T) {
	t.Run("basic string", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)
		cursor.TotalReturned = 50

		str := cursor.String()
		if !strings.Contains(str, "FederatedCursor") {
			t.Error("string should contain 'FederatedCursor'")
		}
		if !strings.Contains(str, "version=1") {
			t.Error("string should contain version")
		}
		if !strings.Contains(str, "active=2/2") {
			t.Error("string should contain active count")
		}
		if !strings.Contains(str, "returned=50") {
			t.Error("string should contain returned count")
		}
	})

	t.Run("with exhausted origins", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2", "origin3"}, nil)
		cursor.Origins["origin2"].Exhausted = true

		str := cursor.String()
		if !strings.Contains(str, "active=2/3") {
			t.Errorf("expected 'active=2/3' in string, got: %s", str)
		}
	})
}

// TestBase64URLSafeEncoding tests URL-safe base64 encoding
func TestBase64URLSafeEncoding(t *testing.T) {
	t.Run("no padding", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// RawURLEncoding should not include padding
		if strings.Contains(encoded, "=") {
			t.Error("encoded cursor should not contain padding characters")
		}
	})

	t.Run("URL-safe characters", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		// Add data that might produce + or / in standard base64
		cursor.Origins["origin1"].NextToken = "+++///+++"

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Should not contain + or /
		if strings.Contains(encoded, "+") {
			t.Error("encoded cursor should not contain '+' character")
		}
		if strings.Contains(encoded, "/") {
			t.Error("encoded cursor should not contain '/' character")
		}
	})

	t.Run("decode with padding fails", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()

		// Get valid encoding
		data, err := json.Marshal(cursor)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		// Encode with standard base64 (with padding)
		encodedWithPadding := base64.StdEncoding.EncodeToString(data)

		// Try to decode - should fail if it has padding
		if strings.Contains(encodedWithPadding, "=") {
			_, err = DecodeCursor(encodedWithPadding)
			if err == nil {
				t.Error("expected error when decoding base64 with padding")
			}
		}
	})

	t.Run("round-trip with special characters", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash?&=special", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextURL = "https://example.com/search?q=test&page=2"
		cursor.Origins["origin1"].NextToken = "abc123+/=def456"

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, cursor, decoded)
	})
}

// TestQueryHashValidation tests query hash validation
func TestQueryHashValidation(t *testing.T) {
	t.Run("round-trip preserves query hash", func(t *testing.T) {
		t.Parallel()

		queryHash := "abc123def456"
		cursor := NewFederatedCursor(queryHash, []string{"origin1"}, nil)

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.QueryHash != queryHash {
			t.Errorf("expected query hash %q, got %q", queryHash, decoded.QueryHash)
		}
	})

	t.Run("empty query hash", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("", []string{"origin1"}, nil)

		if cursor.QueryHash != "" {
			t.Error("empty query hash should be preserved")
		}

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.QueryHash != "" {
			t.Error("empty query hash should round-trip")
		}
	})

	t.Run("different query hashes produce different cursors", func(t *testing.T) {
		t.Parallel()

		cursor1 := NewFederatedCursor("hash1", []string{"origin1"}, nil)
		cursor2 := NewFederatedCursor("hash2", []string{"origin1"}, nil)

		encoded1, _ := cursor1.Encode()
		encoded2, _ := cursor2.Encode()

		if encoded1 == encoded2 {
			t.Error("different query hashes should produce different encoded cursors")
		}
	})

	t.Run("query hash with special characters", func(t *testing.T) {
		t.Parallel()

		specialHash := "hash-with-special!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
		cursor := NewFederatedCursor(specialHash, []string{"origin1"}, nil)

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.QueryHash != specialHash {
			t.Error("special characters in query hash should be preserved")
		}
	})
}

// TestDefaultCursorConfig tests default cursor configuration
func TestDefaultCursorConfig(t *testing.T) {
	t.Run("returns non-nil config", func(t *testing.T) {
		t.Parallel()

		cfg := DefaultCursorConfig()
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
	})

	t.Run("has expected default TTL", func(t *testing.T) {
		t.Parallel()

		cfg := DefaultCursorConfig()
		if cfg.DefaultTTL != 1*time.Hour {
			t.Errorf("expected default TTL 1h, got %v", cfg.DefaultTTL)
		}
	})

	t.Run("has expected max TTL", func(t *testing.T) {
		t.Parallel()

		cfg := DefaultCursorConfig()
		if cfg.MaxTTL != 24*time.Hour {
			t.Errorf("expected max TTL 24h, got %v", cfg.MaxTTL)
		}
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("cursor with many origins", func(t *testing.T) {
		t.Parallel()

		origins := make([]string, 100)
		for i := 0; i < 100; i++ {
			origins[i] = "origin" + string(rune('0'+i))
		}

		cursor := NewFederatedCursor("hash", origins, nil)

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if len(decoded.Origins) != 100 {
			t.Errorf("expected 100 origins, got %d", len(decoded.Origins))
		}
	})

	t.Run("cursor with very long strings", func(t *testing.T) {
		t.Parallel()

		longString := strings.Repeat("a", 10000)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextToken = longString
		cursor.Origins["origin1"].NextURL = longString

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.Origins["origin1"].NextToken != longString {
			t.Error("long next token not preserved")
		}
		if decoded.Origins["origin1"].NextURL != longString {
			t.Error("long next URL not preserved")
		}
	})

	t.Run("cursor with complex sort values", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.LastSortValues = []interface{}{
			"string",
			123.456,
			true,
			nil,
			[]interface{}{"nested", "array"},
			map[string]interface{}{"nested": "object"},
		}

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if len(decoded.LastSortValues) != 6 {
			t.Errorf("expected 6 sort values, got %d", len(decoded.LastSortValues))
		}
	})

	t.Run("cursor with zero timestamps", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.CreatedAt = 0
		cursor.ExpiresAt = 0

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Decoding should fail due to expiration
		_, err = DecodeCursor(encoded)
		if err == nil {
			t.Error("expected error for zero expiry")
		}
	})

	t.Run("cursor with negative timestamps", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.CreatedAt = -1000
		cursor.ExpiresAt = -500

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		// Should be expired
		_, err = DecodeCursor(encoded)
		if err == nil {
			t.Error("expected error for negative expiry")
		}
	})

	t.Run("cursor with large item counts", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.TotalReturned = 1000000
		cursor.Origins["origin1"].ItemCount = 999999
		cursor.Origins["origin1"].Offset = 888888

		encoded, err := cursor.Encode()
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}

		decoded, err := DecodeCursor(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		assertCursorsEqual(t, cursor, decoded)
	})
}

// Helper functions

func assertCursorsEqual(t *testing.T, expected, actual *FederatedCursor) {
	t.Helper()

	if expected.Version != actual.Version {
		t.Errorf("version mismatch: expected %d, got %d", expected.Version, actual.Version)
	}

	if expected.QueryHash != actual.QueryHash {
		t.Errorf("query hash mismatch: expected %q, got %q", expected.QueryHash, actual.QueryHash)
	}

	if expected.TotalReturned != actual.TotalReturned {
		t.Errorf("total returned mismatch: expected %d, got %d", expected.TotalReturned, actual.TotalReturned)
	}

	if expected.CreatedAt != actual.CreatedAt {
		t.Errorf("created at mismatch: expected %d, got %d", expected.CreatedAt, actual.CreatedAt)
	}

	if expected.ExpiresAt != actual.ExpiresAt {
		t.Errorf("expires at mismatch: expected %d, got %d", expected.ExpiresAt, actual.ExpiresAt)
	}

	if len(expected.Origins) != len(actual.Origins) {
		t.Errorf("origins count mismatch: expected %d, got %d", len(expected.Origins), len(actual.Origins))
	}

	for id, expectedOrigin := range expected.Origins {
		actualOrigin, ok := actual.Origins[id]
		if !ok {
			t.Errorf("origin %q missing in actual", id)
			continue
		}
		assertOriginCursorEqual(t, expectedOrigin, actualOrigin)
	}

	if !lastSortValuesEqual(expected.LastSortValues, actual.LastSortValues) {
		t.Errorf("last sort values mismatch: expected %v, got %v", expected.LastSortValues, actual.LastSortValues)
	}
}

func assertOriginCursorEqual(t *testing.T, expected, actual *OriginCursor) {
	t.Helper()

	if expected.ID != actual.ID {
		t.Errorf("origin ID mismatch: expected %q, got %q", expected.ID, actual.ID)
	}

	if expected.NextToken != actual.NextToken {
		t.Errorf("next token mismatch for %q: expected %q, got %q", expected.ID, expected.NextToken, actual.NextToken)
	}

	if expected.NextURL != actual.NextURL {
		t.Errorf("next URL mismatch for %q: expected %q, got %q", expected.ID, expected.NextURL, actual.NextURL)
	}

	if expected.Offset != actual.Offset {
		t.Errorf("offset mismatch for %q: expected %d, got %d", expected.ID, expected.Offset, actual.Offset)
	}

	if expected.Exhausted != actual.Exhausted {
		t.Errorf("exhausted mismatch for %q: expected %v, got %v", expected.ID, expected.Exhausted, actual.Exhausted)
	}

	if expected.Error != actual.Error {
		t.Errorf("error mismatch for %q: expected %v, got %v", expected.ID, expected.Error, actual.Error)
	}

	if expected.ItemCount != actual.ItemCount {
		t.Errorf("item count mismatch for %q: expected %d, got %d", expected.ID, expected.ItemCount, actual.ItemCount)
	}

	expectedJSON, _ := json.Marshal(expected.LastSortValue)
	actualJSON, _ := json.Marshal(actual.LastSortValue)
	if string(expectedJSON) != string(actualJSON) {
		t.Errorf("last sort value mismatch for %q: expected %v, got %v", expected.ID, expected.LastSortValue, actual.LastSortValue)
	}
}

func lastSortValuesEqual(a, b []interface{}) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}

	// Compare via JSON to handle nested structures
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}
