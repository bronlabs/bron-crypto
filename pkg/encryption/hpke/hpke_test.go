package hpke_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

// TestHighLevelAPI_BaseMode_BasicFlow tests the basic encryption/decryption flow
func TestHighLevelAPI_BaseMode_BasicFlow(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	// Test message
	plaintext := []byte("Hello, HPKE!")
	aad := []byte("additional data")

	// Create encrypter (Base mode - no options needed)
	encrypter, err := scheme.Encrypter()
	require.NoError(t, err)

	// Encrypt
	ciphertext, capsule, err := encrypter.Seal(plaintext, receiverPublicKey, aad, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
	require.NotNil(t, capsule)

	// Create decrypter with capsule
	decrypter, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
	)
	require.NoError(t, err)

	// Decrypt
	recovered, err := decrypter.Open(ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, []byte(recovered))

	// Test with wrong AAD should fail
	_, err = decrypter.Open(ciphertext, []byte("wrong aad"))
	require.Error(t, err)
}

// TestHighLevelAPI_WithTestVectors_BaseMode tests Base mode with RFC test vectors
func TestHighLevelAPI_WithTestVectors_BaseMode(t *testing.T) {
	curve := p256.NewCurve()

	for _, suiteVectors := range internal.TestVectors {
		for _, authSuite := range suiteVectors.Auths {
			if authSuite.Mode != hpke.Base {
				continue
			}
			if authSuite.Setup.KEMID != hpke.DHKEM_P256_HKDF_SHA256 {
				continue
			}
			if authSuite.Setup.KDFID != hpke.KDF_HKDF_SHA256 {
				continue // Only test SHA-256 KDF for now
			}

			t.Run(suiteVectors.Name+"_Base", func(t *testing.T) {
				suite, err := hpke.NewCipherSuite(
					authSuite.Setup.KEMID,
					authSuite.Setup.KDFID,
					authSuite.Setup.AEADID,
				)
				require.NoError(t, err)

				scheme, err := hpke.NewScheme(curve, suite)
				require.NoError(t, err)

				// Derive receiver keys from test vector IKM
				receiverSK, err := curve.ScalarField().FromBytes(authSuite.Setup.SkRm)
				require.NoError(t, err)

				receiverPrivateKey := internal.NewPrivateKey(receiverSK)

				// Parse capsule from test vector
				ephemeralPK, err := curve.FromUncompressed(authSuite.Setup.Enc)
				require.NoError(t, err)
				capsule := internal.NewPublicKey(ephemeralPK)

				// Test only first encryption (seq 0) since high-level API doesn't expose sequence control
				if len(authSuite.Encryptions) > 0 {
					encTest := authSuite.Encryptions[0] // Use first encryption (seq 0)
					t.Run("encryption_seq0", func(t *testing.T) {
						// Create decrypter with capsule
						decrypter, err := scheme.Decrypter(receiverPrivateKey,
							hpke.DecryptingWithApplicationInfo[*p256.Point](authSuite.Setup.Info),
							hpke.DecryptingWithCapsule(capsule),
						)
						require.NoError(t, err)

						// Decrypt test vector ciphertext
						plaintext, err := decrypter.Open(encTest.Ct, encTest.Aad)
						require.NoError(t, err)
						require.Equal(t, encTest.Pt, []byte(plaintext))
					})
				}

				// Test exports
				for i, exportTest := range authSuite.Exports {
					t.Run("export_"+string(rune('0'+i)), func(t *testing.T) {
						decrypter, err := scheme.Decrypter(receiverPrivateKey,
							hpke.DecryptingWithApplicationInfo[*p256.Point](authSuite.Setup.Info),
							hpke.DecryptingWithCapsule(capsule),
						)
						require.NoError(t, err)

						// Export key
						exported, err := decrypter.Export(exportTest.ExporterContext, uint(exportTest.L))
						require.NoError(t, err)
						require.Equal(t, exportTest.ExportedValue, exported.Bytes())
					})
				}
			})
		}
	}
}

// TestHighLevelAPI_AuthMode_WithTestVectors tests Auth mode with RFC test vectors
func TestHighLevelAPI_AuthMode_WithTestVectors(t *testing.T) {
	curve := p256.NewCurve()

	for _, suiteVectors := range internal.TestVectors {
		for _, authSuite := range suiteVectors.Auths {
			if authSuite.Mode != hpke.Auth {
				continue
			}
			if authSuite.Setup.KEMID != hpke.DHKEM_P256_HKDF_SHA256 {
				continue
			}
			if authSuite.Setup.KDFID != hpke.KDF_HKDF_SHA256 {
				continue // Only test SHA-256 KDF for now
			}

			t.Run(suiteVectors.Name+"_Auth", func(t *testing.T) {
				suite, err := hpke.NewCipherSuite(
					authSuite.Setup.KEMID,
					authSuite.Setup.KDFID,
					authSuite.Setup.AEADID,
				)
				require.NoError(t, err)

				scheme, err := hpke.NewScheme(curve, suite)
				require.NoError(t, err)

				// Derive receiver keys
				receiverSK, err := curve.ScalarField().FromBytes(authSuite.Setup.SkRm)
				require.NoError(t, err)
				receiverPrivateKey := internal.NewPrivateKey(receiverSK)

				// Parse sender's static public key
				senderPK, err := curve.FromUncompressed(authSuite.Setup.PkSm)
				require.NoError(t, err)
				senderPublicKey := internal.NewPublicKey(senderPK)

				// Parse capsule
				ephemeralPK, err := curve.FromUncompressed(authSuite.Setup.Enc)
				require.NoError(t, err)
				capsule := internal.NewPublicKey(ephemeralPK)

				// Test only first encryption (seq 0) since high-level API doesn't expose sequence control
				if len(authSuite.Encryptions) > 0 {
					encTest := authSuite.Encryptions[0] // Use first encryption (seq 0)
					t.Run("decryption_seq0", func(t *testing.T) {
						decrypter, err := scheme.Decrypter(receiverPrivateKey,
							hpke.DecryptingWithApplicationInfo[*p256.Point](authSuite.Setup.Info),
							hpke.DecryptingWithCapsule(capsule),
							hpke.DecryptingWithAuthentication(senderPublicKey),
						)
						require.NoError(t, err)

						plaintext, err := decrypter.Open(encTest.Ct, encTest.Aad)
						require.NoError(t, err)
						require.Equal(t, encTest.Pt, []byte(plaintext))
					})
				}
			})
		}
	}
}

// TestHighLevelAPI_RoundTrip tests end-to-end encryption/decryption
func TestHighLevelAPI_RoundTrip(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	// Generate keys
	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty message", []byte("x")[:0], []byte("aad")}, // Use slice of non-empty to get []byte{} not nil
		{"small message", []byte("Hello!"), []byte("metadata")},
		{"larger message", []byte("The quick brown fox jumps over the lazy dog"), []byte("context")},
		{"no aad", []byte("message without aad"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter, err := scheme.Encrypter()
			require.NoError(t, err)

			ciphertext, capsule, err := encrypter.Seal(tt.plaintext, receiverPublicKey, tt.aad, rand.Reader)
			require.NoError(t, err)

			decrypter, err := scheme.Decrypter(receiverPrivateKey,
				hpke.DecryptingWithCapsule(capsule),
			)
			require.NoError(t, err)

			recovered, err := decrypter.Open(ciphertext, tt.aad)
			require.NoError(t, err)
			// For empty plaintext, recovered might be nil instead of []byte{}
			if len(tt.plaintext) == 0 {
				require.Empty(t, recovered)
			} else {
				require.Equal(t, tt.plaintext, []byte(recovered))
			}
		})
	}
}

// TestHighLevelAPI_Export tests the Export functionality
func TestHighLevelAPI_Export(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	// Create encrypter with caching enabled
	encrypter, err := scheme.Encrypter(
		hpke.EncryptingWhileCachingRecentContextualInfo[*p256.Point](),
	)
	require.NoError(t, err)

	plaintext := []byte("message")
	ct, capsule, err := encrypter.Seal(plaintext, receiverPublicKey, nil, rand.Reader)
	require.NoError(t, err)

	// Export from sender
	exportedSender, err := encrypter.Export([]byte("exporter context"), 32)
	require.NoError(t, err)
	require.Len(t, exportedSender.Bytes(), 32)

	// Setup receiver and export
	decrypter, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
	)
	require.NoError(t, err)

	pt, err := decrypter.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, plaintext, []byte(pt))

	exportedReceiver, err := decrypter.Export([]byte("exporter context"), 32)
	require.NoError(t, err)
	require.Equal(t, exportedSender.Bytes(), exportedReceiver.Bytes(), "sender and receiver exports should match")

	// Different context should give different export
	exportedDifferent, err := decrypter.Export([]byte("different context"), 32)
	require.NoError(t, err)
	require.NotEqual(t, exportedSender.Bytes(), exportedDifferent.Bytes())
}

// TestHighLevelAPI_PSKMode tests pre-shared key mode
func TestHighLevelAPI_PSKMode(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	// Shared PSK
	psk, err := encryption.NewSymmetricKey([]byte("pre-shared-key-32-bytes-long!!!"))
	require.NoError(t, err)
	pskId := []byte("my-psk-id")

	plaintext := []byte("PSK protected message")

	// Encrypt with PSK
	encrypter, err := scheme.Encrypter(
		hpke.EncryptingWithPreSharedKey[*p256.Point](pskId, psk),
	)
	require.NoError(t, err)

	ct, capsule, err := encrypter.Encrypt(plaintext, receiverPublicKey, rand.Reader)
	require.NoError(t, err)

	// Decrypt with PSK
	decrypter, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
		hpke.DecryptingWithPreSharedKey[*p256.Point](pskId, psk),
	)
	require.NoError(t, err)

	pt, err := decrypter.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, plaintext, []byte(pt))

	// Test with wrong PSK should fail
	wrongPSK, err := encryption.NewSymmetricKey([]byte("wrong-psk-key-32-bytes-long!!!!"))
	require.NoError(t, err)

	decrypterWrong, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
		hpke.DecryptingWithPreSharedKey[*p256.Point](pskId, wrongPSK),
	)
	require.NoError(t, err)

	_, err = decrypterWrong.Decrypt(ct)
	require.Error(t, err, "decryption with wrong PSK should fail")
}

// TestHighLevelAPI_AuthMode tests authenticated encryption
func TestHighLevelAPI_AuthMode(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	// Generate sender key pair
	senderSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	senderPK := curve.ScalarBaseMul(senderSK)

	senderPrivateKey := internal.NewPrivateKey(senderSK)
	senderPublicKey := internal.NewPublicKey(senderPK)

	// Generate receiver key pair
	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	plaintext := []byte("Authenticated message")

	// Encrypt with authentication
	encrypter, err := scheme.Encrypter(
		hpke.EncryptingWithAuthentication[*p256.Point](senderPrivateKey),
	)
	require.NoError(t, err)

	ct, capsule, err := encrypter.Encrypt(plaintext, receiverPublicKey, rand.Reader)
	require.NoError(t, err)

	// Decrypt with authentication
	decrypter, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
		hpke.DecryptingWithAuthentication(senderPublicKey),
	)
	require.NoError(t, err)

	pt, err := decrypter.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, plaintext, []byte(pt))

	// Test with wrong sender public key should fail
	wrongSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	wrongPK := curve.ScalarBaseMul(wrongSK)
	wrongSenderPublicKey := internal.NewPublicKey(wrongPK)

	decrypterWrong, err := scheme.Decrypter(receiverPrivateKey,
		hpke.DecryptingWithCapsule(capsule),
		hpke.DecryptingWithAuthentication(wrongSenderPublicKey),
	)
	require.NoError(t, err)

	_, err = decrypterWrong.Decrypt(ct)
	require.Error(t, err, "decryption with wrong sender key should fail")
}

// TestHighLevelAPI_MultipleMessages tests that each encryption uses a new ephemeral key
func TestHighLevelAPI_MultipleMessages(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	receiverSK, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	receiverPK := curve.ScalarBaseMul(receiverSK)

	receiverPrivateKey := internal.NewPrivateKey(receiverSK)
	receiverPublicKey := internal.NewPublicKey(receiverPK)

	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message"),
	}

	capsules := make([]*internal.PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar], 0)

	// Each encryption creates a new ephemeral key
	for i, msg := range messages {
		t.Run("message_"+string(rune('0'+i)), func(t *testing.T) {
			encrypter, err := scheme.Encrypter()
			require.NoError(t, err)

			ct, capsule, err := encrypter.Encrypt(msg, receiverPublicKey, rand.Reader)
			require.NoError(t, err)

			// Verify capsules are different
			for _, prevCapsule := range capsules {
				require.False(t, capsule.Value().Equal(prevCapsule.Value()), "each encryption should use different ephemeral key")
			}
			capsules = append(capsules, capsule)

			decrypter, err := scheme.Decrypter(receiverPrivateKey,
				hpke.DecryptingWithCapsule(capsule),
			)
			require.NoError(t, err)

			pt, err := decrypter.Decrypt(ct)
			require.NoError(t, err)
			require.Equal(t, msg, []byte(pt))
		})
	}
}

// TestHighLevelAPI_ErrorCases tests error handling
func TestHighLevelAPI_ErrorCases(t *testing.T) {
	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	t.Run("nil receiver public key", func(t *testing.T) {
		encrypter, err := scheme.Encrypter()
		require.NoError(t, err)

		_, _, err = encrypter.Encrypt([]byte("msg"), nil, rand.Reader)
		require.Error(t, err)
	})

	t.Run("nil receiver private key", func(t *testing.T) {
		_, err := scheme.Decrypter(nil)
		require.Error(t, err)
	})

	t.Run("export without caching", func(t *testing.T) {
		encrypter, err := scheme.Encrypter() // No caching option
		require.NoError(t, err)

		receiverSK, err := curve.ScalarField().Random(rand.Reader)
		require.NoError(t, err)
		receiverPK := curve.ScalarBaseMul(receiverSK)
		receiverPublicKey := internal.NewPublicKey(receiverPK)

		_, _, err = encrypter.Encrypt([]byte("msg"), receiverPublicKey, rand.Reader)
		require.NoError(t, err)

		_, err = encrypter.Export([]byte("context"), 32)
		require.Error(t, err, "export should fail without caching")
	})

	t.Run("zero length export", func(t *testing.T) {
		receiverSK, err := curve.ScalarField().Random(rand.Reader)
		require.NoError(t, err)
		receiverPK := curve.ScalarBaseMul(receiverSK)

		receiverPrivateKey := internal.NewPrivateKey(receiverSK)
		receiverPublicKey := internal.NewPublicKey(receiverPK)

		encrypter, err := scheme.Encrypter()
		require.NoError(t, err)

		_, capsule, err := encrypter.Encrypt([]byte("msg"), receiverPublicKey, rand.Reader)
		require.NoError(t, err)

		decrypter, err := scheme.Decrypter(receiverPrivateKey,
			hpke.DecryptingWithCapsule(capsule),
		)
		require.NoError(t, err)

		_, err = decrypter.Export([]byte("context"), 0)
		require.Error(t, err, "export with zero length should fail")
	})
}
