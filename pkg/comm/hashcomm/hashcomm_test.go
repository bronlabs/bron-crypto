package hashcomm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c := Committer{sessionId}
	v := Verifier{sessionId}
	msg := []byte("test")
	commit, opening, err := c.Commit(msg)
	require.NoError(t, err)
	err = v.Verify(commit, opening, msg)
	require.NoError(t, err)
}
