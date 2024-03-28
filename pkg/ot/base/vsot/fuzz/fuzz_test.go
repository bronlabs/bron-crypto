package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot/testutils"
	ot_testutils "github.com/copperexchange/krypton-primitives/pkg/ot/testutils"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

const L = 4

func Fuzz_Test(f *testing.F) {
	f.Add(uint(256), uint(0), []byte("sid"), []byte("test"), int64(0))
	f.Fuzz(func(t *testing.T, Xi uint, curveIndex uint, sid []byte, message []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite, err := ttu.MakeSigningSuite(k256.NewCurve(), sha3.New256)
		require.NoError(t, err)
		authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
		require.NoError(t, err)
		senderKey, receiverKey := authKeys[0], authKeys[1]

		require.NoError(t, err)
		sender, receiver, err := testutils.MakeVSOTParticipants(senderKey, receiverKey, curve, prng, sid, nil, int(Xi), L)
		require.NoError(t, err)
		senderOutput, receiverOutput, err := testutils.RunVSOT(sender, receiver)
		require.NoError(t, err)
		err = ot_testutils.ValidateOT(int(Xi), L, senderOutput.MessagePairs, receiverOutput.Choices, receiverOutput.ChosenMessages)
		require.NoError(t, err)
		// Generate inputs for (chosen) OT
		_, senderMessages, err := ot_testutils.GenerateOTinputs(int(Xi), L)
		require.NoError(t, err)

		// Run (chosen) OT
		masks, err := senderOutput.Encrypt(senderMessages)
		require.NoError(t, err)
		receiverOTchosenMessages, err := receiverOutput.Decrypt(masks)
		require.NoError(t, err)

		// Validate result
		err = ot_testutils.ValidateOT(int(Xi), L, senderMessages, receiverOutput.Choices, receiverOTchosenMessages)
		require.NoError(t, err)
	})
}
