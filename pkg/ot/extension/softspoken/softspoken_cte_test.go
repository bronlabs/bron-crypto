package softspoken_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	vsot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func Test_MeasureConstantTime_round1(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	senderKey, receiverKey := getKeys(t)

	// Fixed parameters
	L := 2
	Xi := 5
	curve := k256.NewCurve()

	// Session ID
	uniqueSessionId := [ot.KappaBytes]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices ot.PackedBits
	var receiver *softspoken.Receiver
	internal.RunMeasurement(500, "softspoken_round1", func(i int) {
		// BaseOTs
		baseOtSenderOutput, baseOtReceiverOutput, err := vsot_testutils.RunVSOT(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, baseOtSenderOutput.MessagePairs, baseOtReceiverOutput.Choices, baseOtReceiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _, err = ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Setup OTe
		otProtocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
		require.NoError(t, err)
		receiver, err = softspoken.NewSoftspokenReceiver(receiverKey, otProtocol, baseOtSenderOutput, uniqueSessionId[:], nil, crand.Reader, nil, L, Xi)
		require.NoError(t, err)
	}, func() {
		receiver.Round1(choices)
	})
}

func Test_MeasureConstantTime_round2(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	senderKey, receiverKey := getKeys(t)
	// Fixed parameters
	Xi := 256
	L := 2
	curve := k256.NewCurve()

	// Session ID
	uniqueSessionId := [ot.KappaBytes]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(t, err)
	var choices ot.PackedBits
	var receiver *softspoken.Receiver
	var round1Output *softspoken.Round1Output
	var sender *softspoken.Sender
	internal.RunMeasurement(500, "softspoken_round2", func(i int) {
		// BaseOTs
		baseOtSend, baseOtRec, err := vsot_testutils.RunVSOT(senderKey, receiverKey, ot.Kappa, 1, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, baseOtSend.MessagePairs, baseOtRec.Choices, baseOtRec.ChosenMessages)
		require.NoError(t, err)

		// Set OTe inputs
		choices, _, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Setup OTe
		otProtocol, err := types.NewMPCProtocol(curve, hashset.NewHashableHashSet(senderKey.(types.IdentityKey), receiverKey.(types.IdentityKey)))
		require.NoError(t, err)
		sender, err = softspoken.NewSoftspokenSender(senderKey, otProtocol, baseOtRec, uniqueSessionId[:], nil, crand.Reader, nil, L, Xi)
		require.NoError(t, err)
		receiver, err = softspoken.NewSoftspokenReceiver(receiverKey, otProtocol, baseOtSend, uniqueSessionId[:], nil, crand.Reader, nil, L, Xi)
		require.NoError(t, err)

		_, round1Output, err = receiver.Round1(choices)
		require.NoError(t, err)
	}, func() {
		sender.Round2(round1Output)
	})
}
