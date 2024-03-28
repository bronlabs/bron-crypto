package vsot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func TestHappyPathVSOT_ROT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())
	for _, curve := range curveInstances {
		Xi := 256
		L := 4
		sessionId := [32]byte{}
		_, err := crand.Read(sessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, Xi, L)
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
	}
}
func TestHappyPathVSOT_OT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		sessionId := [32]byte{}
		_, err := crand.Read(sessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, Xi, L)
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := senderOutput.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiverOutput.Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiverOutput.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_COT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		sessionId := [32]byte{}
		_, err := crand.Read(sessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, curve, crand.Reader, sessionId[:], nil, Xi, L)
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := senderOutput.CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiverOutput.ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		x := receiverOutput.Choices
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}
