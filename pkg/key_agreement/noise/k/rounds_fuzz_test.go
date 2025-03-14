package k_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/noise"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/noise/k"
)

var allHashes = []noise.SupportedHash{noise.NOISE_HASH_SHA3256, noise.NOISE_HASH_BLAKE2S}
var allCurves = []curves.Curve{k256.NewCurve(), edwards25519.NewCurve(), curve25519.NewCurve()}

func Fuzz_K(f *testing.F) {
	f.Add(uint(0), uint(0), uint64(0), uint64(1), []byte("sid"), []byte("message"), []byte("handshakeMessage"), int64(0))
	f.Fuzz(func(t *testing.T, hashIndex uint, curveIndex uint, aliceSecret uint64, bobSecret uint64, sid []byte, message []byte, handshakeMessage []byte, randomSeed int64) {
		curve := allCurves[curveIndex%uint(len(allCurves))]
		hashFunc := allHashes[hashIndex%uint(len(allHashes))]
		prng := rand.New(rand.NewSource(randomSeed))
		aliceIdentity := noise.NewSigner(prng, curve, nil)
		bobIdentity := noise.NewSigner(prng, curve, nil)
		var aliceToBobRound1Message *noise.P2PMessage
		var encryptedMessage noise.P2PMessage
		suite := &noise.Suite{
			Curve: curve,
			Hash:  hashFunc,
			Aead:  noise.NOISE_AEAD_CHACHA,
		}
		aliceSession, err := k.NewInitiator(suite, prng, sid, aliceIdentity, bobIdentity.PublicKey, handshakeMessage)
		if err != nil {
			if !errs.IsKnownError(err) {
				require.NoError(t, err)
			} else {
				t.Skip()
			}
		}
		bobSession, err := k.NewResponder(suite, prng, sid, bobIdentity, aliceIdentity.PublicKey, handshakeMessage)
		if err != nil {
			if !errs.IsKnownError(err) {
				require.NoError(t, err)
			} else {
				t.Skip()
			}
		}

		aliceToBobRound1Message, err = aliceSession.Round1(nil)
		require.NoError(t, err)
		encryptedMessage, err = aliceSession.State.Encrypt(message)
		require.NoError(t, err)

		_, err = bobSession.Round1(aliceToBobRound1Message)
		require.NoError(t, err)
		plaintext, valid, err := bobSession.State.Decrypt(&encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})
}
