package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(256), []byte("sid"), []byte("test"), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, batchSize uint, hashKeySeed []byte, message []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		messages := make([][2][32]byte, batchSize)
		prng := rand.New(rand.NewSource(randomSeed))
		receiver, err := vsot.NewReceiver(curve, int(batchSize), hashKeySeed[:], nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		sender, err := vsot.NewSender(curve, int(batchSize), hashKeySeed[:], nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		proof, publicKey, err := sender.Round1ComputeAndZkpToPublicKey()
		require.NoError(t, err)
		receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(publicKey, proof)
		require.NoError(t, err)
		challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
		require.NoError(t, err)
		challengeResponse, err := receiver.Round4RespondToChallenge(challenge)
		require.NoError(t, err)
		challengeOpenings, err := sender.Round5Verify(challengeResponse)
		require.NoError(t, err)
		err = receiver.Round6Verify(challengeOpenings)
		require.NoError(t, err)
		s := sender.Output
		r := receiver.Output
		for i := 0; i < int(batchSize); i++ {
			var m [32]byte
			copy(m[:], message)
			messages[i] = [2][32]byte{
				m,
				m,
			}
		}
		ciphertexts, err := s.Encrypt(messages)
		require.NoError(t, err)
		decrypted, err := r.Decrypt(ciphertexts)
		require.NoError(t, err)

		for i := 0; i < int(batchSize); i++ {
			choice := r.RandomChoiceBits[i]
			require.Equal(t, messages[i][choice], decrypted[i])
		}
	})
}
