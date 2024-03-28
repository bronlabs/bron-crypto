package softspoken_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	csprng_testutils "github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	bbot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/testutils"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
}

var baseOTrunners = []func(senderKey, receiverKey types.AuthKey, curve curves.Curve, sessionId []byte, rng io.Reader, Xi, L int) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error){
	bbot_testutils.BBOT,
	vsot_testutils.VSOT,
}

func Test_HappyPath_ROTe(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			prng := csprng_testutils.TestRng()
			sessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(sessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, curve, sessionId[:], prng, ot.Kappa, 1)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Run ROTe
			senderMesages, receiverChoices, receiverChosenMessage, err := testutils.SoftspokenROTe(
				senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, baseOtSend, baseOtRec, nil, Xi, L)
			require.NoError(t, err)

			// Check ROTe result
			err = ot_testutils.ValidateOT(Xi, L, senderMesages, receiverChoices, receiverChosenMessage)
			require.NoError(t, err)
		}
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	t.Parallel()
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			sessionId := [ot.KappaBytes]byte{}
			prng := csprng_testutils.TestRng()
			_, err := crand.Read(sessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(senderKey, receiverKey, curve, sessionId[:], prng, ot.Kappa, 1)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)
			// Run COTe
			x, a, z_A, z_B, err := testutils.SoftspokenCOTe(
				senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, baseOtSend, baseOtRec, nil, Xi, L)
			require.NoError(t, err)

			// Check COTe result
			err = ot_testutils.ValidateCOT(Xi, L, x, a, z_A, z_B)
			require.NoError(t, err)
		}
	}
}
