package logging

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRequestID_IsUUID(t *testing.T) {
	id := generateRequestID()
	require.Truef(t, uuidRe.MatchString(id), "not a UUIDv4: %q", id)
	// Two consecutive IDs must differ.
	require.NotEqual(t, id, generateRequestID(), "generateRequestID returned duplicate IDs")
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
