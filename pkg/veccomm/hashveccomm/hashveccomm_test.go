package hashveccomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/hashveccomm"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := hashveccomm.NewVectorCommitter(sessionId, crand.Reader)
	require.NoError(t, err)
	v, err := hashveccomm.NewVectorVerifier(sessionId)
	require.NoError(t, err)

	messages := make([]hashcomm.Message, 3)
	messages[0] = []byte("Hello")
	messages[1] = []byte("World")
	messages[2] = []byte("!")

	com, opn, err := c.Commit(messages)
	require.NoError(t, err)
	err = v.Verify(com, opn)
	require.NoError(t, err)
}
