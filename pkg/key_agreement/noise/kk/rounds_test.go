package kk_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/noise"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/noise/kk"
)

func TestHappyPath(t *testing.T) {
	t.Parallel()
	var allHashes = []noise.SupportedHash{noise.NOISE_HASH_SHA3256, noise.NOISE_HASH_BLAKE2S}
	for _, c := range []curves.Curve{k256.NewCurve(), edwards25519.NewCurve(), curve25519.NewCurve()} {
		c := c // capture range variable
		for _, hashFunc := range allHashes {
			hashFunc := hashFunc // capture range variable
			t.Run(fmt.Sprintf("Curve_%v_Hash_%v", c, hashFunc), func(t *testing.T) {
				t.Parallel()
				happyPath(t, c, hashFunc)
			})
		}
	}
}

func happyPath(t *testing.T, curve curves.Curve, hashFunc noise.SupportedHash) {
	t.Helper()
	sid := []byte("sid")
	message := []byte("hello")
	aliceIdentity := noise.NewSigner(crand.Reader, curve, nil)
	bobIdentity := noise.NewSigner(crand.Reader, curve, nil)

	var aliceToBobRound1Message *noise.P2PMessage
	var bobToAliceRound2Message *noise.P2PMessage
	var encryptedMessage noise.P2PMessage
	suite := &noise.Suite{
		Curve: curve,
		Hash:  hashFunc,
		Aead:  noise.NOISE_AEAD_CHACHA,
	}
	aliceSession, err := kk.NewInitiator(suite, crand.Reader, sid, aliceIdentity, bobIdentity.PublicKey, []byte("handshake1"), []byte("handshake2"))
	require.NoError(t, err)
	bobSession, err := kk.NewResponder(suite, crand.Reader, sid, bobIdentity, aliceIdentity.PublicKey, []byte("handshake1"), []byte("handshake2"))
	require.NoError(t, err)

	t.Run(fmt.Sprintf("[%s] alice and bob exchange messages for handshaking", curve.Name()), func(t *testing.T) {
		aliceToBobRound1Message, err = aliceSession.Round1(nil)
		require.NoError(t, err)
		bobToAliceRound2Message, err = bobSession.Round1(aliceToBobRound1Message)
		require.NoError(t, err)
		_, err = aliceSession.Round2(bobToAliceRound2Message)
		require.NoError(t, err)
	})

	t.Run(fmt.Sprintf("[%s] alice can send bob encrypted message", curve.Name()), func(t *testing.T) {
		encryptedMessage, err = aliceSession.State.Encrypt(message)
		require.NoError(t, err)
		plaintext, valid, err := bobSession.State.Decrypt(&encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})

	t.Run(fmt.Sprintf("[%s] bob can send alice encrypted message", curve.Name()), func(t *testing.T) {
		encryptedMessage, err = bobSession.State.Encrypt(message)
		require.NoError(t, err)
		plaintext, valid, err := aliceSession.State.Decrypt(&encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})
}
