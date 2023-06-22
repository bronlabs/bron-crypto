package commitments_test

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	h := sha3.New256
	commitment, witness, err := commitments.Commit(h, message)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	openingError := commitments.Open(h, message, commitment, witness)
	require.NoError(t, openingError)
}
