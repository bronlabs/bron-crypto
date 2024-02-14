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

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.RunVSOT(Xi, L, k256.NewCurve(), sid[:], crand.Reader)
	require.NoError(t, err)

	for i := 0; i < Xi; i++ {
		require.Equal(t, receiver.ChosenMessages[i], sender.Messages[i][receiver.Choices.Select(i)])
	}
	var messages []ot.MessagePair
	internal.RunMeasurement(500, "vsot_encrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
	}, func() {
		sender.Round2Encrypt(messages)
	})
}

func Test_MeasureConstantTime_decrypt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.RunVSOT(Xi, L, k256.NewCurve(), sid[:], crand.Reader)
	require.NoError(t, err)

	for i := 0; i < Xi; i++ {
		require.Equal(t, receiver.ChosenMessages[i], sender.Messages[i][receiver.Choices.Select(i)])
	}
	var messages []ot.MessagePair
	var encrypted []ot.MessagePair
	internal.RunMeasurement(500, "vsot_decrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
		encrypted, err = sender.Round2Encrypt(messages)
		require.NoError(t, err)
	}, func() {
		receiver.Round3Decrypt(encrypted)
	})
}
