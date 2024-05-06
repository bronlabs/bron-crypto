package elgamalcomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/comm/elgamalcomm"
	"github.com/stretchr/testify/require"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	curve := k256.NewCurve()
	privateKey, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	c, err := elgamalcomm.NewHomomorphicCommitter(sessionId, crand.Reader, privateKey)
	require.NoError(t, err)
	v, err := elgamalcomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	msg, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	commit, opening, err := c.Commit(curve.Generator().ScalarMul(msg))
	require.NoError(t, err)
	err = v.Verify(commit, opening)
	require.NoError(t, err)
}
