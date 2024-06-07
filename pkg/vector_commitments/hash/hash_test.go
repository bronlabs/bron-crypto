package hashvectorcommitments_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	hashvectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/hash"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := hashvectorcommitments.NewVectorCommitter(sessionId, crand.Reader)
	require.NoError(t, err)
	v := hashvectorcommitments.NewVectorVerifier(sessionId)

	messages := hashvectorcommitments.Vector(make([]hashvectorcommitments.Message, 3))
	messages[0] = []byte("Hello")
	messages[1] = []byte("World")
	messages[2] = []byte("!")

	com, opn, err := c.Commit(messages)
	require.NoError(t, err)
	err = v.Verify(com, opn)
	require.NoError(t, err)
}
