package softspoken_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/knox-primitives/pkg/ot/extension/softspoken/test_utils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	useForcedReuse := true
	inputBatchLen := 5
	curve := k256.New()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeInputChoices
	var receiver *softspoken.Receiver
	internal.RunMeasurement(500, "softspoken_round1", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, _, err = test_utils.GenerateSoftspokenRandomInputs(
			inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Setup COTe
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, useForcedReuse)
		require.NoError(t, err)
	}, func() {
		receiver.Round1ExtendAndProveConsistency(choices)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	useForcedReuse := true
	inputBatchLen := 5
	curve := k256.New()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeInputChoices
	var receiver *softspoken.Receiver
	var round1Output *softspoken.Round1Output
	var inputOpts softspoken.COTeInputOpt
	var sender *softspoken.Sender
	internal.RunMeasurement(500, "softspoken_round2", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err = test_utils.GenerateSoftspokenRandomInputs(
			inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Setup COTe
		sender, err = softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId[:], nil, curve, useForcedReuse)
		require.NoError(t, err)
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, useForcedReuse)
		require.NoError(t, err)

		_, round1Output, err = receiver.Round1ExtendAndProveConsistency(choices)
		require.NoError(t, err)
	}, func() {
		sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	useForcedReuse := true
	inputBatchLen := 5
	curve := k256.New()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeInputChoices
	var receiver *softspoken.Receiver
	var round1Output *softspoken.Round1Output
	var inputOpts softspoken.COTeInputOpt
	var sender *softspoken.Sender
	var round2Output *softspoken.Round2Output
	var oTeReceiverOutput softspoken.OTeReceiverOutput
	internal.RunMeasurement(500, "softspoken_round3", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := test_utils.RunSoftspokenBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		test_utils.CheckSoftspokenBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err = test_utils.GenerateSoftspokenRandomInputs(
			inputBatchLen, curve, useForcedReuse)
		require.NoError(t, err)

		// Setup COTe
		sender, err = softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId[:], nil, curve, useForcedReuse)
		require.NoError(t, err)
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, useForcedReuse)
		require.NoError(t, err)

		oTeReceiverOutput, round1Output, err = receiver.Round1ExtendAndProveConsistency(choices)
		require.NoError(t, err)
		_, _, round2Output, err = sender.Round2ExtendAndCheckConsistency(round1Output, inputOpts)
		require.NoError(t, err)

	}, func() {
		receiver.Round3Derandomize(round2Output, oTeReceiverOutput)
	})
}
