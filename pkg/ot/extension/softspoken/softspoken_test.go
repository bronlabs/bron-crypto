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

var baseOTrunners = []func(batchSize, messageLength int, curve curves.Curve, uniqueSessionId []byte, rng io.Reader) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error){
	vsot_testutils.RunVSOT,
	bbot_testutils.RunBBOT,
}

func Test_HappyPath_ROTe(t *testing.T) {
	t.Parallel()
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.Messages, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Set OTe inputs
			receiverChoices, _, err := ot_testutils.GenerateCOTinputs(Xi, L, nil)
			require.NoError(t, err)

			// Run OTe
			senderMesages, receiverChosenMessage, err := testutils.RunSoftspokenOTe(
				Xi, L, curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, receiverChoices)
			require.NoError(t, err)

			// Check OTe result
			err = ot_testutils.ValidateOT(Xi, L, senderMesages, receiverChoices, receiverChosenMessage)
			require.NoError(t, err)
		}
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	t.Parallel()
	for _, curve := range curveInstances {
		for _, baseOTrunner := range baseOTrunners {
			// Generic setup
			L := 4
			Xi := 4 * base.ComputationalSecurity
			uniqueSessionId := [ot.KappaBytes]byte{}
			_, err := crand.Read(uniqueSessionId[:])
			require.NoError(t, err)

			// BaseOTs
			baseOtSend, baseOtRec, err := baseOTrunner(ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
			require.NoError(t, err)
			err = ot_testutils.ValidateOT(ot.Kappa, 1, baseOtSend.Messages, baseOtRec.Choices, baseOtRec.ChosenMessages)
			require.NoError(t, err)

			// Set COTe inputs
			choices, cOTeSenderInput, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
			require.NoError(t, err)

			// Run COTe
			cOTeSenderOutput, cOTeReceiverOutput, err := testutils.RunSoftspokenCOTe(
				curve, uniqueSessionId[:], crand.Reader, baseOtSend, baseOtRec, choices, cOTeSenderInput, L, Xi)
			require.NoError(t, err)

			// Check COTe result
			err = ot_testutils.ValidateCOT(Xi, L, choices, cOTeSenderInput, cOTeSenderOutput, cOTeReceiverOutput)
			require.NoError(t, err)
		}
	}
}
