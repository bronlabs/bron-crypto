package softspoken_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
}

func Test_HappyPath_OTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		LOTe := 4
		Xi := 4 * base.ComputationalSecurity
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSendOutput, baseOtRecOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)

		err = testutils.CheckBaseOTOutputs(baseOtSendOutput, baseOtRecOutput)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _, err := testutils.GenerateSoftspokenRandomInputs(nil, LOTe, Xi)
		require.NoError(t, err)

		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := testutils.RunSoftspokenOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSendOutput, baseOtRecOutput, choices, LOTe, Xi)
		require.NoError(t, err)

		// Check OTe result
		err = testutils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices, LOTe, Xi)
		require.NoError(t, err)
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		LOTe := 4
		Xi := 4 * base.ComputationalSecurity
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = testutils.CheckBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)
		require.NoError(t, err)

		// Set COTe inputs
		choices, cOTeSenderInput, err := testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
		require.NoError(t, err)

		// Run COTe
		cOTeSenderOutput, cOTeReceiverOutput, err := testutils.RunSoftspokenCOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSenderOutput, baseOtReceiverOutput, choices, cOTeSenderInput, LOTe, Xi)
		require.NoError(t, err)

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(choices, cOTeSenderInput, cOTeSenderOutput, cOTeReceiverOutput, LOTe, Xi)
		require.NoError(t, err)

	}
}
