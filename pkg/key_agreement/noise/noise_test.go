package noise_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise/k"
	"github.com/copperexchange/krypton-primitives/pkg/key_agreement/noise/kk"
)

type Message struct {
	msg   string
	ciper string
}

func TestVectorKPattern(t *testing.T) {
	t.Parallel()
	curve := curve25519.NewCurve()
	// ref: https://github.com/symbolicsoft/noiseexplorer/blob/master/implementations/tests/cacophony.json
	t.Run("case Noise_K_25519_ChaChaPoly_BLAKE2s", func(t *testing.T) {
		t.Parallel()
		messages := []Message{
			{
				msg:   "4c756477696720766f6e204d69736573",
				ciper: "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79443ab57eb07c96791ebddff95c2ed2ccfe412d87270c753c0a5b5fe46164087647",
			},
			{
				msg:   "4d757272617920526f746862617264",
				ciper: "3e7b4d83fa0cca62cc0b6d202da416c0b59289e518982742851e534f1916f8",
			},
			{
				msg:   "462e20412e20486179656b",
				ciper: "d52fe3eee4de396b592afea7eb632020587aa4384200ed9bca9585",
			},
			{
				msg:   "4361726c204d656e676572",
				ciper: "51476b0e939b9901d9c265533d2845591813dcca1ce834090f977d",
			},
			{
				msg:   "4a65616e2d426170746973746520536179",
				ciper: "24848a58c0cf7be87fb648166f3ac49cb6e76d08a353d4c4836006d48bc40275f1",
			},
			{
				msg:   "457567656e2042f6686d20766f6e2042617765726b",
				ciper: "95f88b7496841fd0df89d5834b31640bddc9ca51d4b466c929a8833d263c2771d19720a5df",
			},
		}

		sid, err := hex.DecodeString("4a6f686e2047616c74")
		require.NoError(t, err)

		aliceIdentity := generateKeyFromHex(curve, "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
		require.Equal(t, "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a", hex.EncodeToString(aliceIdentity.PublicKey.ToAffineCompressed()[:]))
		aliceE := generateKeyFromHex(curve, "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")

		bobIdentity := generateKeyFromHex(curve, "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
		require.Equal(t, "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62", hex.EncodeToString(bobIdentity.PublicKey.ToAffineCompressed()[:]))
		var aliceSession *k.Participant
		var bobSession *k.Participant

		suite := &noise.Suite{
			Curve: curve,
			Hash:  noise.NOISE_HASH_BLAKE2S,
			Aead:  noise.NOISE_AEAD_CHACHA,
		}
		for i, m := range messages {
			msg, err := hex.DecodeString(m.msg)
			require.NoError(t, err)
			expectedEncryptedMsg, err := hex.DecodeString(m.ciper)
			require.NoError(t, err)

			if i == 0 {
				t.Run("handshake", func(t *testing.T) {
					var aliceToBobRound1Message *noise.P2PMessage
					aliceSession, err = k.NewInitiator(suite, crand.Reader, sid, aliceIdentity, bobIdentity.PublicKey, msg)
					aliceSession.State.Hs.EphemeralKey = aliceE
					require.NoError(t, err)
					bobSession, err = k.NewResponder(suite, crand.Reader, sid, bobIdentity, aliceIdentity.PublicKey, msg)
					require.NoError(t, err)

					aliceToBobRound1Message, err = aliceSession.Round1(nil)
					require.NoError(t, err)

					_, err = bobSession.Round1(aliceToBobRound1Message)
					require.NoError(t, err)

					var cipertext []byte
					cipertext = append(cipertext, aliceToBobRound1Message.Ne.ToAffineCompressed()[:]...)
					cipertext = append(cipertext, aliceToBobRound1Message.Ciphertext[:]...)
					require.Equal(t, expectedEncryptedMsg, cipertext)
				})
			} else {
				t.Run(fmt.Sprintf("exchange message %s", m.msg), func(t *testing.T) {
					encryptedMessage, err := aliceSession.State.Encrypt(msg)
					require.NoError(t, err)
					plaintext, valid, err := bobSession.State.Decrypt(&encryptedMessage)
					require.True(t, valid)
					require.NoError(t, err)
					require.Equal(t, msg, plaintext)

					var cipertext []byte
					cipertext = append(cipertext, encryptedMessage.Ciphertext[:]...)
					require.Equal(t, expectedEncryptedMsg, cipertext)
				})
			}
		}
	})
}

func TestVectorKKPattern(t *testing.T) {
	t.Parallel()
	curve := curve25519.NewCurve()
	// ref: https://github.com/symbolicsoft/noiseexplorer/blob/master/implementations/tests/cacophony.json
	t.Run("case Noise_KK_25519_ChaChaPoly_BLAKE2s", func(t *testing.T) {
		t.Parallel()
		messages := []Message{
			{
				msg:   "4c756477696720766f6e204d69736573",
				ciper: "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944266a5f53784aa3becb0f7485c2759c328937867a4cbaafef07422b0725e098be",
			},
			{
				msg:   "4d757272617920526f746862617264",
				ciper: "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843008aeea5d76d6abcbab87a18502c8a8352d9933ac11e2a7d228038d721e31e",
			},
			{
				msg:   "462e20412e20486179656b",
				ciper: "5f92113edf78c3e56e6d67201f5f9e0c8f2930c3e1ffb64ede0358",
			},
			{
				msg:   "4361726c204d656e676572",
				ciper: "30ebbd9cdcef7f40d99c8cd11e880dac28f5c9e5032c1059b3b56a",
			},
			{
				msg:   "4a65616e2d426170746973746520536179",
				ciper: "b011620dc31f88abd1788db50912952fe45da56e9d0907ab2cbce5f609b58b1cf2",
			},
			{
				msg:   "457567656e2042f6686d20766f6e2042617765726b",
				ciper: "a0661971e9047b28a815c7b1f62fefb471e4d34bc2a5b48149e7f80c3772b8e4aae8b44baa",
			},
		}

		sid, err := hex.DecodeString("4a6f686e2047616c74")
		require.NoError(t, err)

		aliceIdentity := generateKeyFromHex(curve, "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
		require.Equal(t, "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a", hex.EncodeToString(aliceIdentity.PublicKey.ToAffineCompressed()[:]))
		aliceE := generateKeyFromHex(curve, "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")

		bobIdentity := generateKeyFromHex(curve, "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
		require.Equal(t, "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62", hex.EncodeToString(bobIdentity.PublicKey.ToAffineCompressed()[:]))
		bobE := generateKeyFromHex(curve, "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")

		var aliceSession *kk.Participant
		var bobSession *kk.Participant
		var aliceToBobRound1Message *noise.P2PMessage
		var bobToAliceMessage *noise.P2PMessage

		suite := &noise.Suite{
			Curve: curve,
			Hash:  noise.NOISE_HASH_BLAKE2S,
			Aead:  noise.NOISE_AEAD_CHACHA,
		}
		for i, m := range messages {

			msg, err := hex.DecodeString(m.msg)
			require.NoError(t, err)
			expectedEncryptedMsg, err := hex.DecodeString(m.ciper)
			require.NoError(t, err)

			if i <= 1 {
				t.Run(fmt.Sprintf("handshake round %d", i+1), func(t *testing.T) {
					if i == 0 {
						msg2, err := hex.DecodeString(messages[i+1].msg)
						require.NoError(t, err)

						aliceSession, err = kk.NewInitiator(suite, crand.Reader, sid, aliceIdentity, bobIdentity.PublicKey, msg, msg2)
						require.NoError(t, err)
						aliceSession.State.Hs.EphemeralKey = aliceE
						bobSession, err = kk.NewResponder(suite, crand.Reader, sid, bobIdentity, aliceIdentity.PublicKey, msg, msg2)
						require.NoError(t, err)
						bobSession.State.Hs.EphemeralKey = bobE

						aliceToBobRound1Message, err = aliceSession.Round1(nil)
						require.NoError(t, err)

						bobToAliceMessage, err = bobSession.Round1(aliceToBobRound1Message)
						require.NoError(t, err)

						var cipertext []byte
						cipertext = append(cipertext, aliceToBobRound1Message.Ne.ToAffineCompressed()[:]...)
						cipertext = append(cipertext, aliceToBobRound1Message.Ciphertext[:]...)
						require.Equal(t, expectedEncryptedMsg, cipertext)
					} else {
						bobToAliceMessage, err = aliceSession.Round2(bobToAliceMessage)
						var cipertext []byte
						cipertext = append(cipertext, bobToAliceMessage.Ne.ToAffineCompressed()[:]...)
						cipertext = append(cipertext, bobToAliceMessage.Ciphertext[:]...)
						require.Equal(t, expectedEncryptedMsg, cipertext)
					}
				})
			} else {
				t.Run(fmt.Sprintf("exchange message %s", m.msg), func(t *testing.T) {
					var senderSession *kk.Participant
					var receiverSession *kk.Participant
					if i%2 == 0 {
						senderSession = aliceSession
						receiverSession = bobSession
					} else {
						senderSession = bobSession
						receiverSession = aliceSession
					}

					encryptedMessage, err := senderSession.State.Encrypt(msg)
					require.NoError(t, err)

					var cipertext []byte
					cipertext = append(cipertext, encryptedMessage.Ciphertext[:]...)
					require.Equal(t, expectedEncryptedMsg, cipertext)

					plaintext, valid, err := receiverSession.State.Decrypt(&encryptedMessage)
					require.True(t, valid)
					require.NoError(t, err)
					require.Equal(t, msg, plaintext)
				})
			}
		}
	})
}

func generateKeyFromHex(curve curves.Curve, hexKey string) noise.Signer {
	privateKey, err := hex.DecodeString(hexKey)
	if err != nil {
		panic(err)
	}
	var key noise.Signer
	key.PrivateKey = curve.ScalarField().Element()
	key.PrivateKey, err = key.PrivateKey.SetBytes(privateKey)
	if err != nil {
		panic(err)
	}
	key.PublicKey = curve.ScalarBaseMult(key.PrivateKey)
	return key
}
