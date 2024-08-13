package k_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise/k"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	var allHashes = []noise.SupportedHash{noise.NOISE_HASH_SHA3256, noise.NOISE_HASH_BLAKE2S}
	var messages = []string{"hello", ""}
	for _, c := range []curves.Curve{k256.NewCurve(), edwards25519.NewCurve(), curve25519.NewCurve()} {
		c := c // capture range variable
		t.Run(fmt.Sprintf("Curve_%v", c), func(t *testing.T) {
			t.Parallel()
			for _, hashFunc := range allHashes {
				hashFunc := hashFunc // capture range variable
				t.Run(fmt.Sprintf("Hash_%v", hashFunc), func(t *testing.T) {
					t.Parallel()
					for _, message := range messages {
						message := message // capture range variable
						t.Run(fmt.Sprintf("Message_%s", message), func(t *testing.T) {
							t.Parallel()
							happyPath(t, c, []byte(message), hashFunc)
						})
					}
				})
			}
		})
	}
}

func happyPath(t *testing.T, curve curves.Curve, message []byte, hashFunc noise.SupportedHash) {
	t.Helper()
	sid := []byte("sid")
	aliceIdentity := noise.NewSigner(crand.Reader, curve, nil)
	bobIdentity := noise.NewSigner(crand.Reader, curve, nil)
	charlieIdentity := noise.NewSigner(crand.Reader, curve, nil)
	var aliceToBobRound1Message *noise.P2PMessage
	var encryptedMessage noise.P2PMessage
	suite := &noise.Suite{
		Curve: curve,
		Hash:  hashFunc,
		Aead:  noise.NOISE_AEAD_CHACHA,
	}
	aliceSession, err := k.NewInitiator(suite, crand.Reader, sid, aliceIdentity, bobIdentity.PublicKey, []byte("handshake"))
	require.NoError(t, err)
	bobSession, err := k.NewResponder(suite, crand.Reader, sid, bobIdentity, aliceIdentity.PublicKey, []byte("handshake"))
	require.NoError(t, err)

	t.Run(fmt.Sprintf("[%s] alice generate one way handshake and encrypted message to bob", curve.Name()), func(t *testing.T) {
		aliceToBobRound1Message, err = aliceSession.Round1(nil)
		require.NoError(t, err)
		encryptedMessage, err = aliceSession.State.Encrypt(message)
		require.NoError(t, err)
	})

	t.Run(fmt.Sprintf("[%s] bob receive handshake from alice and decrypt her message", curve.Name()), func(t *testing.T) {
		_, err = bobSession.Round1(aliceToBobRound1Message)
		require.NoError(t, err)
		plaintext, valid, err := bobSession.State.Decrypt(&encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})

	t.Run(fmt.Sprintf("[%s] charlie who did not handshake with alice can't read the message", curve.Name()), func(t *testing.T) {
		charlieSession, err := k.NewResponder(suite, crand.Reader, sid, bobIdentity, charlieIdentity.PublicKey, []byte("handshake"))
		require.NoError(t, err)
		_, err = charlieSession.Round1(aliceToBobRound1Message)
		require.Error(t, err)
	})
}
