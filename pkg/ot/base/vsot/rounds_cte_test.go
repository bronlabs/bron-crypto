package vsot_test

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/bronlabs/bron-crypto/pkg/ot/testutils"
)

func Test_MeasureConstantTime_encrypt(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	senderKey, receiverKey := getKeys(t)

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, k256.NewCurve(), sid[:], crand.Reader)
	require.NoError(t, err)

	for i := 0; i < Xi; i++ {
		require.Equal(t, receiver.ChosenMessages[i], sender.MessagePairs[i][receiver.Choices.Get(uint(i))])
	}
	var messages [][2]ot.Message
	internal.RunMeasurement(500, "vsot_encrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
	}, func() {
		sender.Encrypt(messages)
	})
}

func Test_MeasureConstantTime_decrypt(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	senderKey, receiverKey := getKeys(t)

	Xi := 256
	L := 4
	sid := [32]byte{}
	_, err := crand.Read(sid[:])
	require.NoError(t, err)
	sender, receiver, err := testutils.RunVSOT(senderKey, receiverKey, Xi, L, k256.NewCurve(), sid[:], crand.Reader)
	require.NoError(t, err)

	for i := 0; i < Xi; i++ {
		require.Equal(t, receiver.ChosenMessages[i], sender.MessagePairs[i][receiver.Choices.Get(uint(i))])
	}
	var messages [][2]ot.Message
	var encrypted [][2]ot.Message
	internal.RunMeasurement(500, "vsot_decrypt", func(i int) {
		_, messages, err = ot_testutils.GenerateOTinputs(Xi, L)
		require.NoError(t, err)
		encrypted, err = sender.Encrypt(messages)
		require.NoError(t, err)
	}, func() {
		receiver.Decrypt(encrypted)
	})
}
