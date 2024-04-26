package pedersen

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

func TestHappyPath(t *testing.T) {
	pcs := PedersenCommitmentScheme{}
	curve := k256.NewCurve()
	msg, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	fmt.Println("message to commit to is:", msg)
	com, wit, err := pcs.Commit([]byte("00000001"), msg)
	require.NoError(t, err)
	err = pcs.Open([]byte("00000001"), com, wit, msg)
	require.NoError(t, err)
}
