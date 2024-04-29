package hashcomm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHappyPath(t *testing.T) {
	hc := NewHashCommitment([]byte("00000001"))
	msg := []byte("test")
	commit, opening, err := hc.Commit(msg)
	require.NoError(t, err)
	err = hc.Open(commit, opening, msg)
	require.NoError(t, err)
}
