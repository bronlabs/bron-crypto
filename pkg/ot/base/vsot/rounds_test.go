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
	for _, curve := range curveInstances {
		Xi := 256
		L := 4
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.Messages, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
	}
}
func TestHappyPathVSOT_OT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.Messages, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := sender.Round2Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiver.Round3Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(Xi, L, senderMessages, receiver.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathVSOT_COT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.Messages, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiver.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := sender.Round2CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiver.Round3ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}
