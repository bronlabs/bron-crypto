package elgamalcomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/stretchr/testify/require"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sessionId)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sessionId)
	require.NoError(t, err)
	curve := k256.NewCurve()
	msg, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	commit, opening, err := c.Commit(msg)
	require.NoError(t, err)
	err = v.Verify(commit, opening)
	require.NoError(t, err)
}
