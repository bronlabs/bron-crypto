package pedersenveccomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/pedersenveccomm"
	"github.com/stretchr/testify/require"
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	curve := k256.NewCurve()
	c, err := pedersenveccomm.NewVectorCommitter(sessionId, crand.Reader, curve)
	require.NoError(t, err)
	v, err := pedersenveccomm.NewVectorVerifier(sessionId)
	require.NoError(t, err)

	messages := make([]pedersencomm.Message, 3)
	messages[0], _ = curve.ScalarField().Random(crand.Reader)
	messages[1], _ = curve.ScalarField().Random(crand.Reader)
	messages[2], _ = curve.ScalarField().Random(crand.Reader)

	com, opn, err := c.Commit(messages)
	require.NoError(t, err)
	err = v.Verify(com, opn)
	require.NoError(t, err)
}
