package pedersenveccomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/pedersenveccomm"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	curve := k256.NewCurve()
	c, err := pedersenveccomm.NewVectorCommitter(sessionId, crand.Reader, curve)
	require.NoError(t, err)
	v, err := pedersenveccomm.NewVectorVerifier(sessionId, curve)
	require.NoError(t, err)

	messages := make([]pedersencomm.Message, 3)
	messages[0], _ = curve.ScalarField().Random(crand.Reader)
	messages[1], _ = curve.ScalarField().Random(crand.Reader)
	messages[2], _ = curve.ScalarField().Random(crand.Reader)

	com, opn, err := c.Commit(messages)
	require.NoError(t, err)
	err = v.Verify(com, opn)
	require.NoError(t, err)

	// Scale commitment
	// Pick a random scalar for scaling
	rnd, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	scaledCommitment, err := c.ScaleCommitment(com, rnd.Nat())
	require.NoError(t, err)
	scaledOpening, err := c.ScaleOpening(opn, rnd.Nat())
	require.NoError(t, err)
	err = v.Verify(scaledCommitment, scaledOpening)
	require.NoError(t, err)

	// Combine commitments
	messagesPrime := make([]pedersencomm.Message, 3)
	messagesPrime[0], _ = curve.ScalarField().Random(crand.Reader)
	messagesPrime[1], _ = curve.ScalarField().Random(crand.Reader)
	messagesPrime[2], _ = curve.ScalarField().Random(crand.Reader)

	comPrime, opnPrime, err := c.Commit(messagesPrime)
	require.NoError(t, err)

	combinedCommitment, err := c.CombineCommitments(com, comPrime)
	require.NoError(t, err)
	combinedOpening, err := c.CombineOpenings(opn, opnPrime)
	require.NoError(t, err)
	err = v.Verify(combinedCommitment, combinedOpening)
	require.NoError(t, err)
}
