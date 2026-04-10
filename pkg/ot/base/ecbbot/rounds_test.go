package ecbbot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
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

func TestRound2RejectsInvalidChoiceLength(t *testing.T) {
	t.Parallel()

	const CHI = 128
	const L = 1
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := ecbbot.NewSuite(CHI, L, curve)
	require.NoError(t, err)

	quorum := sharing.NewOrdinalShareholderSet(2)
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	sender, err := ecbbot.NewSender(ctxs[1], suite, prng)
	require.NoError(t, err)
	receiver, err := ecbbot.NewReceiver(ctxs[2], suite, prng)
	require.NoError(t, err)

	r1, err := sender.Round1()
	require.NoError(t, err)

	_, _, err = receiver.Round2(r1, make([]byte, CHI/8-1))
	require.Error(t, err)

	_, _, err = receiver.Round2(r1, make([]byte, CHI/8+1))
	require.Error(t, err)
}
