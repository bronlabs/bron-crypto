package softspoken_test

import (
	"crypto/rand"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/extension/softspoken/test_utils"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
)

var curveInstances = []*curves.Curve{
	curves.K256(),
	curves.P256(),
}

func TestOTextension(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _ := test_utils.GenerateSoftspokenRandomInputs(
			t, 1, curve)

		// Run OTe
		oTeSenderOutput, oTeReceiverOutput, err := test_utils.RunSoftspokenOTe(
			t, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices)
		require.NoError(t, err)

		// Check OTe result
		test_utils.CheckSoftspokenOTeOutputs(t, oTeSenderOutput, oTeReceiverOutput, &choices)
	}
}

func TestCOTextension(t *testing.T) {
	for _, curve := range curveInstances {
		// Generic setup
		useForcedReuse := false
		inputBatchLen := 1 // Must be 1 if useForcedReuse is false. Set L>1 for higher batch sizes, or loop over inputBatchLen.
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(t, baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts := test_utils.GenerateSoftspokenRandomInputs(
			t, inputBatchLen, curve)

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := test_utils.RunSoftspokenCOTe(t,
			useForcedReuse, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		test_utils.CheckSoftspokenCOTeOutputs(t, cOTeSenderOutputs, cOTeReceiverOutputs, inputOpts, choices)

	}
}

func TestCOTextensionWithForcedReuse(t *testing.T) {
	for _, curve := range curveInstances {
		// Fixed parameters
		useForcedReuse := true
		inputBatchLen := 128

		// Session ID
		uniqueSessionId := [vsot.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)

		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(t, baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts := test_utils.GenerateSoftspokenRandomInputs(
			t, inputBatchLen, curve)

		// Run COTe
		cOTeSenderOutputs, cOTeReceiverOutputs, err := test_utils.RunSoftspokenCOTe(t,
			useForcedReuse, curve, uniqueSessionId, baseOtSenderOutput, baseOtReceiverOutput, &choices, inputOpts)
		require.NoError(t, err)

		// Check COTe result
		test_utils.CheckSoftspokenCOTeOutputs(t, cOTeSenderOutputs, cOTeReceiverOutputs, inputOpts, choices)
	}
}
