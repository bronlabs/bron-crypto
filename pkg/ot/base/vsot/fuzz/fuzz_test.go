package fuzz

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

const L = 4

func Fuzz_Test(f *testing.F) {
	f.Add(uint(256), uint(0), []byte("sid"), []byte("test"), int64(0))
	f.Fuzz(func(t *testing.T, batchSize uint, curveIndex uint, sid []byte, message []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		messages := make([]ot.MessagePair, batchSize)
		prng := rand.New(rand.NewSource(randomSeed))
		receiver, err := vsot.NewReceiver(int(batchSize), L, curve, sid[:], randomisedFischlin.Name, nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		sender, err := vsot.NewSender(int(batchSize), L, curve, sid[:], randomisedFischlin.Name, nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		r1out, err := sender.Round1()
		require.NoError(t, err)
		receiversMaskedChoice, err := receiver.Round2(r1out)
		require.NoError(t, err)
		challenge, err := sender.Round3(receiversMaskedChoice)
		require.NoError(t, err)
		challengeResponse, err := receiver.Round4(challenge)
		require.NoError(t, err)
		challengeOpenings, err := sender.Round5(challengeResponse)
		require.NoError(t, err)
		err = receiver.Round6(challengeOpenings)
		require.NoError(t, err)
		s := sender.Output
		r := receiver.Output
		for i := 0; i < int(batchSize); i++ {
			m0 := sha256.Sum256([]byte(fmt.Sprintf("messages[%d][0]", i)))
			m1 := sha256.Sum256([]byte(fmt.Sprintf("messages[%d][1]", i)))
			messages[i] = ot.MessagePair{
				make([]ot.MessageElement, L),
				make([]ot.MessageElement, L),
			}
			for l := 0; l < L; l++ {
				messages[i][0][l] = ([ot.KappaBytes]byte)(m0[:ot.KappaBytes])
				messages[i][1][l] = ([ot.KappaBytes]byte)(m1[:ot.KappaBytes])
			}
		}
		ciphertexts, err := s.Encrypt(messages)
		require.NoError(t, err)
		decrypted, err := r.Decrypt(ciphertexts)
		require.NoError(t, err)

		for i := 0; i < int(batchSize); i++ {
			choice := r.Choices.Select(i)
			require.Equal(t, messages[i][choice], decrypted[i])
		}
	})
}
