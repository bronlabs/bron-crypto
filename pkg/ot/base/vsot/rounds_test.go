package vsot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/bronlabs/krypton-primitives/pkg/ot/testutils"
)

func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)
	return authKeys[0], authKeys[1]
}

func TestHappyPathVSOT_ROT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 256
		L := 4
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
	}
}
func TestHappyPathVSOT_OT(t *testing.T) {
	t.Parallel()
	curveInstances := []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
	}
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := sender.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiver.Decrypt(masks)
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
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		Xi := 128
		L := 3
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, sender.MessagePairs, receiver.Choices, receiver.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiver.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (chosen) OT
		z_A, tau, err := sender.CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiver.ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}
