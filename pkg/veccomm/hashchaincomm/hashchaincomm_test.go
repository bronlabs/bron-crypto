package hashchaincomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/hashchaincomm"
	"github.com/stretchr/testify/require"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := hashchaincomm.NewVectorCommitter(crand.Reader, sessionId)
	require.NoError(t, err)

	messages := make([]hashcomm.Message, 3)
	messages[0] = []byte("Hello")
	messages[1] = []byte("World")
	messages[2] = []byte("!")

	_, _, err = c.Commit(messages)
	require.NoError(t, err)
}
