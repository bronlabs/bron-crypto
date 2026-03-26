package ecbbot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	ecbbottestutils "github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot/testutils"
)

func Test_HappyPathRandomOT(t *testing.T) {
	t.Parallel()
	const CHI = 128
	const L = 1
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	senderOutput, receiverOutput, err := ecbbottestutils.RunBBOT(t, CHI, L, curve, prng)
	require.NoError(t, err)
	ecbbottestutils.ValidateOT(t, CHI, L, senderOutput, receiverOutput)
}
