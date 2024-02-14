package bbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
}

func TestHappyPathBBOT_ROT(t *testing.T) {
	t.Parallel()
	Xi := 128
	L := 4
	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.Messages, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathBBOT_OT(t *testing.T) {
	t.Parallel()
	Xi := 256
	L := 3
	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.Messages, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := senderOutput.Round2Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiverOutput.Round3Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiverOutput.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathBBOT_COT(t *testing.T) {
	t.Parallel()
	Xi := 256
	L := 3

	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.Messages, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiverOutput.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := senderOutput.Round2CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiverOutput.Round3ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}

func BenchmarkBBOT(b *testing.B) {
	Xi := 128
	L := 4
	uniqueSessionId := [32]byte{}
	_, err := crand.Read(uniqueSessionId[:])
	require.NoError(b, err)
	for _, curve := range curveInstances {
		_, _, err := testutils.RunBBOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(b, err)
	}
}
