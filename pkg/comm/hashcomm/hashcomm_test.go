package hashcomm

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c := NewCommitter(sessionId)
	v := NewVerifier(sessionId)
	msg := []byte("test")
	commit, opening, err := c.Commit(crand.Reader, msg)
	require.NoError(t, err)
	err = v.Verify(commit, opening)
	require.NoError(t, err)
}
