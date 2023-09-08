package softspoken_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken/test_utils"
)

var curveInstances = []curves.Curve{
	k256.New(),
	p256.New(),
}

func Test_HappyPath_OTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		inputBatchLen := 3
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSendOutput, baseOtRecOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _, err := test_utils.GenerateSoftspokenRandomInputs(inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := test_utils.RunSoftspokenOTe(
			curve, uniqueSessionId[:], baseOtSendOutput, baseOtRecOutput, choices)
		require.NoError(t, err)

		// Check OTe result
		err = test_utils.CheckSoftspokenOTeOutputs(oTeSenderOutput, oTeReceiverOutput, choices)
		require.NoError(t, err)
	}
}

func Test_HappyPath_COTe(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		inputBatchLen := 5
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = test_utils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)
		require.NoError(t, err)

		// Set COTe inputs
		choices, inputOpts, err := test_utils.GenerateSoftspokenRandomInputs(
			inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := test_utils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		err = test_utils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeReceiverOutputs, inputOpts, choices)
		require.NoError(t, err)

	}
}

func Test_HappyPath_COTeForcedReuse(t *testing.T) {
	for _, curve := range curveInstances {
		// Fixed parameters
		useForcedReuse := true
		inputBatchLen := 5

		// Session ID
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err := test_utils.GenerateSoftspokenRandomInputs(
			inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := test_utils.RunSoftspokenCOTe(
			useForcedReuse, curve, uniqueSessionId[:], baseOtSenderOutput, baseOtReceiverOutput, choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		err = test_utils.CheckSoftspokenCOTeOutputs(cOTeSenderOutputs, cOTeReceiverOutputs, inputOpts, choices)
		require.NoError(t, err)
	}
}
