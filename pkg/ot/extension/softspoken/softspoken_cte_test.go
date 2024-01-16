package softspoken_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken/testutils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	LOTe := 2
	Xi := 5
	curve := k256.NewCurve()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeChoices
	var receiver *softspoken.Receiver
	internal.RunMeasurement(500, "softspoken_round1", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		testutils.CheckBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, _, err = testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
		require.NoError(t, err)

		// Setup COTe
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, crand.Reader, nil, LOTe, Xi)
		require.NoError(t, err)
	}, func() {
		receiver.Round1(choices)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	Xi := 5
	LOTe := 2
	curve := k256.NewCurve()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeChoices
	var receiver *softspoken.Receiver
	var round1Output *softspoken.Round1Output
	var inputOpts softspoken.COTeMessageBatch
	var sender *softspoken.Sender
	internal.RunMeasurement(500, "softspoken_round2", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		testutils.CheckBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err = testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
		require.NoError(t, err)

		// Setup COTe
		sender, err = softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId[:], nil, curve, crand.Reader, nil, LOTe, Xi)
		require.NoError(t, err)
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, crand.Reader, nil, LOTe, Xi)
		require.NoError(t, err)

		_, round1Output, err = receiver.Round1(choices)
		require.NoError(t, err)
	}, func() {
		sender.Round2(round1Output, inputOpts)
	})
}

func Test_MeasureConstantTime_round3(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	// Fixed parameters
	LOTe := 2
	Xi := 5
	curve := k256.NewCurve()

	// Session ID
	uniqueSessionId := [vsot.DigestSize]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices softspoken.OTeChoices
	var receiver *softspoken.Receiver
	var round1Output *softspoken.Round1Output
	var inputOpts softspoken.COTeMessageBatch
	var sender *softspoken.Sender
	var round2Output *softspoken.Round2Output
	internal.RunMeasurement(500, "softspoken_round3", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := testutils.RunBaseOT(t, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		testutils.CheckBaseOTOutputs(baseOtSenderOutput, baseOtReceiverOutput)

		// Set COTe inputs
		choices, inputOpts, err = testutils.GenerateSoftspokenRandomInputs(curve, LOTe, Xi)
		require.NoError(t, err)

		// Setup COTe
		sender, err = softspoken.NewCOtSender(baseOtReceiverOutput, uniqueSessionId[:], nil, curve, crand.Reader, nil, LOTe, Xi)
		require.NoError(t, err)
		receiver, err = softspoken.NewCOtReceiver(baseOtSenderOutput, uniqueSessionId[:], nil, curve, crand.Reader, nil, LOTe, Xi)
		require.NoError(t, err)

		_, round1Output, err = receiver.Round1(choices)
		require.NoError(t, err)
		_, _, round2Output, err = sender.Round2(round1Output, inputOpts)
		require.NoError(t, err)

	}, func() {
		receiver.Round3(round2Output)
	})
}
