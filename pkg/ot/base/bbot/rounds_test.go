package bbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/bbot/testutils"
	ot_testutils "github.com/bronlabs/bron-crypto/pkg/ot/testutils"
)

var curveInstances = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
}

func getKeys(t *testing.T) (senderKey, receiverKey types.AuthKey) {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)
	return authKeys[0], authKeys[1]
}

func TestHappyPathBBOT_ROT(t *testing.T) {
	t.Parallel()
	Xi := 128
	L := 4
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
	}
}

func TestHappyPathBBOT_OT(t *testing.T) {
	t.Parallel()
	Xi := 256
	L := 3
	senderKey, receiverKey := getKeys(t)
	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)

		// Run (standard chosen) OT
		masks, err := senderOutput.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiverOutput.Decrypt(masks)
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
	senderKey, receiverKey := getKeys(t)

	for _, curve := range curveInstances {
		uniqueSessionId := [32]byte{}
		_, err := crand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)

		// Generate inputs for Correlated OT
		x := receiverOutput.Choices
		_, a, err := ot_testutils.GenerateCOTinputs(Xi, L, curve)
		require.NoError(t, err)

		// Run (correlated) OT
		z_A, tau, err := senderOutput.CreateCorrelation(a)
		require.NoError(t, err)
		z_B, err := receiverOutput.ApplyCorrelation(tau)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateCOT(Xi, L, x, a, z_B, z_A)
		require.NoError(t, err)
	}
}

func BenchmarkBBOT(b *testing.B) {
	Xi := 128
	L := 4
	cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
	require.NoError(b, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(b, err)
	senderKey, receiverKey := authKeys[0], authKeys[1]
	uniqueSessionId := [32]byte{}
	_, err = crand.Read(uniqueSessionId[:])
	require.NoError(b, err)
	for _, curve := range curveInstances {
		_, _, err := testutils.RunBBOT(senderKey, receiverKey, Xi, L, curve, uniqueSessionId[:], crand.Reader)
		require.NoError(b, err)
	}
}
