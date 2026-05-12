package logging

import (
	"regexp"
	"testing"
)

func TestGenerateRequestID_IsUUID(t *testing.T) {
	id := generateRequestID()
	if !uuidRe.MatchString(id) {
		t.Fatalf("not a UUIDv4: %q", id)
	}
	// Two consecutive IDs must differ.
	if id == generateRequestID() {
		t.Fatal("generateRequestID returned duplicate IDs")
	}
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
