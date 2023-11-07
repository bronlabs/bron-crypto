package kk

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
)

func TestHappyPath(t *testing.T) {
	var allHashes = []noise.SupportedHash{noise.NOISE_HASH_SHA3256, noise.NOISE_HASH_BLAKE2S}
	for _, c := range []curves.Curve{k256.New(), edwards25519.New(), curve25519.New()} {
		for _, hashFunc := range allHashes {
			happyPath(t, c, hashFunc)
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
	aliceSession, err := NewInitiator(suite, crand.Reader, sid, aliceIdentity, bobIdentity.PublicKey, []byte("handshake1"), []byte("handshake2"))
	require.NoError(t, err)
	bobSession, err := NewResponder(suite, crand.Reader, sid, bobIdentity, aliceIdentity.PublicKey, []byte("handshake1"), []byte("handshake2"))
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
		_, encryptedMessage, err = noise.EncryptMessage(suite, aliceSession.State, message)
		require.NoError(t, err)
		_, plaintext, valid, err := noise.DecryptMessage(suite, bobSession.State, &encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})

	t.Run(fmt.Sprintf("[%s] bob can send alice encrypted message", curve.Name()), func(t *testing.T) {
		_, encryptedMessage, err = noise.EncryptMessage(suite, bobSession.State, message)
		require.NoError(t, err)
		_, plaintext, valid, err := noise.DecryptMessage(suite, aliceSession.State, &encryptedMessage)
		require.True(t, valid)
		require.NoError(t, err)
		require.Equal(t, message, plaintext)
	})
}
