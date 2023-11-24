package softspoken_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
)

var curveInstances = []curves.Curve{
	k256.New(),
	p256.New(),
}

func Test_HappyPath_OTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		scalarsPerSlot := 2
		inputBatchLen := 3
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSendOutput, baseOtRecOutput, err := testutils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _, err := testutils.GenerateSoftspokenRandomInputs(inputBatchLen, scalarsPerSlot, curve, useForcedReuse)
		require.NoError(t, err)

		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := testutils.RunSoftspokenOTe(
			curve, uniqueSessionId[:], crand.Reader, baseOtSendOutput, baseOtRecOutput, choices)
		require.NoError(t, err)

		// Check OTe result
		err = testutils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices)
		require.NoError(t, err)
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		inputBatchLen := 5
		scalarsPerSlot := 3
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = testutils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)
		require.NoError(t, err)

		// Set COTe inputs
		choices, inputOpts, err := testutils.GenerateSoftspokenRandomInputs(
			inputBatchLen, scalarsPerSlot, curve, useForcedReuse)
		require.NoError(t, err)

		// Run COTe
		cOTeSenderOutputs, cOTeMessages, err := testutils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], crand.Reader, baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeMessages, inputOpts, choices)
		require.NoError(t, err)

	}
}

func Test_HappyPath_COTeForcedReuse(t *testing.T) {
	for _, curve := range curveInstances {
		// Fixed parameters
		useForcedReuse := true
		inputBatchLen := 5
		scalarsPerSlot := 4

		// Session ID
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		testutils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err := testutils.GenerateSoftspokenRandomInputs(
			inputBatchLen, scalarsPerSlot, curve, useForcedReuse)
		require.NoError(t, err)

		// Run COTe
		cOTeSenderOutputs, cOTeMessages, err := testutils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], crand.Reader, baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		err = testutils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeMessages, inputOpts, choices)
		require.NoError(t, err)
	}
}
