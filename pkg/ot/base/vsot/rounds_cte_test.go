package vsot_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

func Test_MeasureConstantTime_encrypt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, k256.NewCurve(), crand.Reader, sid[:], nil, Xi, L)
	require.NoError(t, err)
	senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
	require.NoError(t, err)
	err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
	require.NoError(t, err)

	var messages [][2]ot.Message
	internal.RunMeasurement(500, "vsot_encrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
	}, func() {
		senderOutput.Encrypt(messages)
	})
}

func Test_MeasureConstantTime_decrypt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	senderKey, receiverKey := ot_testutils.MakeOtIdentitites(k256.NewCurve())

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, k256.NewCurve(), crand.Reader, sid[:], nil, Xi, L)
	require.NoError(t, err)
	senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
	require.NoError(t, err)
	err = ot_testutils.ValidateOT(Xi, L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
	require.NoError(t, err)
	var messages [][2]ot.Message
	var encrypted [][2]ot.Message
	internal.RunMeasurement(500, "vsot_decrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
		encrypted, err = senderOutput.Encrypt(messages)
		require.NoError(t, err)
	}, func() {
		receiverOutput.Decrypt(encrypted)
	})
}
