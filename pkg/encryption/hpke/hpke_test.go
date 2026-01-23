package hpke_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

// Helper to generate key pairs
func generateKeyPair[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, suite *hpke.CipherSuite, curve curves.Curve[P, B, S]) (*internal.PrivateKey[S], *internal.PublicKey[P, B, S]) {
	t.Helper()
	kdf, err := internal.NewKDF(suite.KDFID())
	require.NoError(t, err)
	dhkem, err := internal.NewDHKEM(curve, kdf)
	require.NoError(t, err)
	sk, pk, err := dhkem.GenerateKeyPair(pcg.NewRandomised())
	require.NoError(t, err)
	return sk, pk
}

// TestHPKE_BaseMode_Roundtrip tests basic encryption/decryption roundtrip
func TestHPKE_BaseMode_Roundtrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		setupScheme func(t *testing.T) (any, *hpke.CipherSuite)
	}{
		{
			name: "P256_AES128GCM_SHA256",
			setupScheme: func(t *testing.T) (any, *hpke.CipherSuite) {
				t.Helper()
				curve := p256.NewCurve()
				suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
				require.NoError(t, err)
				scheme, err := hpke.NewScheme(curve, suite)
				require.NoError(t, err)
				return scheme, suite
			},
		},
		{
			name: "X25519_ChaCha20Poly1305_SHA256",
			setupScheme: func(t *testing.T) (any, *hpke.CipherSuite) {
				t.Helper()
				curve := curve25519.NewPrimeSubGroup()
				suite, err := hpke.NewCipherSuite(hpke.DHKEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_CHACHA_20_POLY_1305)
				require.NoError(t, err)
				scheme, err := hpke.NewScheme(curve, suite)
				require.NoError(t, err)
				return scheme, suite
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, suite := tc.setupScheme(t)

			// Test with P256
			if tc.name == "P256_AES128GCM_SHA256" {
				curve := p256.NewCurve()

				// Generate receiver key pair
				receiverSk, receiverPk := generateKeyPair(t, suite, curve)

				// Test message
				plaintext := []byte("Hello, HPKE!")
				info := []byte("test info")

				// Sender: Setup and encrypt
				senderCtx, err := hpke.SetupBaseS(suite, receiverPk, info, pcg.NewRandomised())
				require.NoError(t, err)
				ciphertext, err := senderCtx.Seal(plaintext, nil)
				require.NoError(t, err)
				require.NotEqual(t, plaintext, ciphertext)

				// Receiver: Setup and decrypt
				receiverCtx, err := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)
				require.NoError(t, err)
				decrypted, err := receiverCtx.Open(ciphertext, nil)
				require.NoError(t, err)
				require.Equal(t, plaintext, decrypted)
			}

			// Test with X25519
			if tc.name == "X25519_ChaCha20Poly1305_SHA256" {
				curve := curve25519.NewPrimeSubGroup()

				// Generate receiver key pair
				receiverSk, receiverPk := generateKeyPair(t, suite, curve)

				// Test message
				plaintext := []byte("Hello, HPKE!")
				info := []byte("test info")

				// Sender: Setup and encrypt
				senderCtx, err := hpke.SetupBaseS(suite, receiverPk, info, pcg.NewRandomised())
				require.NoError(t, err)
				ciphertext, err := senderCtx.Seal(plaintext, nil)
				require.NoError(t, err)
				require.NotEqual(t, plaintext, ciphertext)

				// Receiver: Setup and decrypt
				receiverCtx, err := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)
				require.NoError(t, err)
				decrypted, err := receiverCtx.Open(ciphertext, nil)
				require.NoError(t, err)
				require.Equal(t, plaintext, decrypted)
			}
		})
	}
}

// TestHPKE_AuthMode_Roundtrip tests authenticated encryption/decryption
func TestHPKE_AuthMode_Roundtrip(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	// Generate sender key pair
	senderSk, senderPk := generateKeyPair(t, suite, curve)

	// Test message
	plaintext := []byte("Authenticated message")
	info := []byte("auth test")

	// Sender: Setup with authentication and encrypt
	senderCtx, err := hpke.SetupAuthS(suite, receiverPk, senderSk, info, pcg.NewRandomised())
	require.NoError(t, err)
	ciphertext, err := senderCtx.Seal(plaintext, nil)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	// Receiver: Setup with sender's public key and decrypt
	receiverCtx, err := hpke.SetupAuthR(suite, receiverSk, senderCtx.Capsule, senderPk, info)
	require.NoError(t, err)
	decrypted, err := receiverCtx.Open(ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestHPKE_PSKMode_Roundtrip tests PSK-based encryption/decryption
func TestHPKE_PSKMode_Roundtrip(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	// Pre-shared key
	psk := make([]byte, 32)
	_, err = pcg.NewRandomised().Read(psk)
	require.NoError(t, err)
	pskID := []byte("test-psk-id")
	info := []byte("psk test")

	// Test message
	plaintext := []byte("PSK encrypted message")

	// Sender: Setup with PSK and encrypt
	senderCtx, err := hpke.SetupPSKS(suite, receiverPk, psk, pskID, info, pcg.NewRandomised())
	require.NoError(t, err)
	ciphertext, err := senderCtx.Seal(plaintext, nil)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	// Receiver: Setup with PSK and decrypt
	receiverCtx, err := hpke.SetupPSKR(suite, receiverSk, senderCtx.Capsule, psk, pskID, info)
	require.NoError(t, err)
	decrypted, err := receiverCtx.Open(ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestHPKE_AuthPSKMode_Roundtrip tests authenticated PSK encryption/decryption
func TestHPKE_AuthPSKMode_Roundtrip(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	// Generate sender key pair
	senderSk, senderPk := generateKeyPair(t, suite, curve)

	// Pre-shared key
	psk := make([]byte, 32)
	_, err = pcg.NewRandomised().Read(psk)
	require.NoError(t, err)
	pskID := []byte("test-authpsk-id")
	info := []byte("authpsk test")

	// Test message
	plaintext := []byte("AuthPSK encrypted message")

	// Sender: Setup with Auth+PSK and encrypt
	senderCtx, err := hpke.SetupAuthPSKS(suite, receiverPk, senderSk, psk, pskID, info, pcg.NewRandomised())
	require.NoError(t, err)
	ciphertext, err := senderCtx.Seal(plaintext, nil)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	// Receiver: Setup with Auth+PSK and decrypt
	receiverCtx, err := hpke.SetupAuthPSKR(suite, receiverSk, senderCtx.Capsule, senderPk, psk, pskID, info)
	require.NoError(t, err)
	decrypted, err := receiverCtx.Open(ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestHPKE_MultipleMessages tests encrypting multiple messages with same context
func TestHPKE_MultipleMessages(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	info := []byte("multi message test")

	// Setup contexts
	senderCtx, err := hpke.SetupBaseS(suite, receiverPk, info, pcg.NewRandomised())
	require.NoError(t, err)
	receiverCtx, err := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)
	require.NoError(t, err)

	// Encrypt and decrypt multiple messages
	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message"),
	}

	for _, msg := range messages {
		ct, err := senderCtx.Seal(msg, nil)
		require.NoError(t, err)

		pt, err := receiverCtx.Open(ct, nil)
		require.NoError(t, err)
		require.Equal(t, msg, pt)
	}
}

// TestHPKE_WithAAD tests encryption with additional authenticated data
func TestHPKE_WithAAD(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	plaintext := []byte("Message with AAD")
	aad := []byte("additional authenticated data")
	info := []byte("aad test")

	// Setup and encrypt with AAD
	senderCtx, err := hpke.SetupBaseS(suite, receiverPk, info, pcg.NewRandomised())
	require.NoError(t, err)
	ciphertext, err := senderCtx.Seal(plaintext, aad)
	require.NoError(t, err)

	// Decrypt with correct AAD
	receiverCtx, err := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)
	require.NoError(t, err)
	decrypted, err := receiverCtx.Open(ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// Attempt to decrypt with wrong AAD should fail
	wrongAAD := []byte("wrong aad")
	_, err = receiverCtx.Open(ciphertext, wrongAAD)
	require.Error(t, err, "Decryption should fail with wrong AAD")
}

// TestHPKE_Encrypter_API tests the high-level Encrypter API
func TestHPKE_Encrypter_API(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)
	scheme, err := hpke.NewScheme(curve, suite)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	// Create encrypter
	encrypter, err := scheme.Encrypter()
	require.NoError(t, err)

	plaintext := []byte("Test message")

	// Encrypt
	ciphertext, capsule, err := encrypter.Encrypt(plaintext, receiverPk, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.NotNil(t, capsule)

	// Create decrypter and decrypt
	decrypter, err := scheme.Decrypter(receiverSk, hpke.DecryptingWithCapsule(capsule))
	require.NoError(t, err)

	decrypted, err := decrypter.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

// TestHPKE_Export tests the key export functionality
func TestHPKE_Export(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk := generateKeyPair(t, suite, curve)

	info := []byte("export test")

	// Setup contexts
	senderCtx, err := hpke.SetupBaseS(suite, receiverPk, info, pcg.NewRandomised())
	require.NoError(t, err)
	receiverCtx, err := hpke.SetupBaseR(suite, receiverSk, senderCtx.Capsule, info)
	require.NoError(t, err)

	// Export keys from both contexts
	exporterContext := []byte("exporter context")
	length := 32

	senderExport, err := senderCtx.Export(exporterContext, length)
	require.NoError(t, err)
	require.Len(t, senderExport, length)

	receiverExport, err := receiverCtx.Export(exporterContext, length)
	require.NoError(t, err)
	require.Len(t, receiverExport, length)

	// Exported secrets should match
	require.Equal(t, senderExport, receiverExport)
}

// TestHPKE_InvalidInputs tests error handling
func TestHPKE_InvalidInputs(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	t.Run("NilCurve", func(t *testing.T) {
		t.Parallel()
		_, err := hpke.NewScheme[*p256.Point, *p256.BaseFieldElement, *p256.Scalar](nil, suite)
		require.Error(t, err)
	})

	t.Run("NilCipherSuite", func(t *testing.T) {
		t.Parallel()
		_, err := hpke.NewScheme(curve, nil)
		require.Error(t, err)
	})

	t.Run("InvalidCipherSuite", func(t *testing.T) {
		t.Parallel()
		// Try to create cipher suite with invalid parameters
		_, err := hpke.NewCipherSuite(hpke.DHKEM_RESERVED, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
		require.Error(t, err)
	})
}

// TestHPKE_CipherSuiteIdentifiers tests cipher suite properties
func TestHPKE_CipherSuiteIdentifiers(t *testing.T) {
	t.Parallel()

	suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
	require.NoError(t, err)

	require.Equal(t, hpke.DHKEM_P256_HKDF_SHA256, suite.KEMID())
	require.Equal(t, hpke.KDF_HKDF_SHA256, suite.KDFID())
	require.Equal(t, hpke.AEAD_AES_128_GCM, suite.AEADID())
}

// TestHPKE_SymmetricKey tests symmetric key generation
func TestHPKE_SymmetricKey(t *testing.T) {
	t.Parallel()

	keyBytes := make([]byte, 16)
	_, err := pcg.NewRandomised().Read(keyBytes)
	require.NoError(t, err)

	key, err := encryption.NewSymmetricKey(keyBytes)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, keyBytes, key.Bytes())
}

// TestHPKE_Keygen tests the key generator
func TestHPKE_Keygen(t *testing.T) {
	t.Parallel()

	t.Run("P256", func(t *testing.T) {
		t.Parallel()

		curve := p256.NewCurve()
		suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
		require.NoError(t, err)

		scheme, err := hpke.NewScheme(curve, suite)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		require.NotNil(t, kg)

		sk, pk, err := kg.Generate(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, sk)
		require.NotNil(t, pk)

		// Use generated keys for encryption/decryption roundtrip
		plaintext := []byte("Hello from keygen test!")
		info := []byte("test info")

		senderCtx, err := hpke.SetupBaseS(suite, pk, info, pcg.NewRandomised())
		require.NoError(t, err)
		ciphertext, err := senderCtx.Seal(plaintext, nil)
		require.NoError(t, err)

		receiverCtx, err := hpke.SetupBaseR(suite, sk, senderCtx.Capsule, info)
		require.NoError(t, err)
		decrypted, err := receiverCtx.Open(ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()

		curve := curve25519.NewPrimeSubGroup()
		suite, err := hpke.NewCipherSuite(hpke.DHKEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_CHACHA_20_POLY_1305)
		require.NoError(t, err)

		scheme, err := hpke.NewScheme(curve, suite)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		require.NotNil(t, kg)

		sk, pk, err := kg.Generate(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, sk)
		require.NotNil(t, pk)

		// Use generated keys for encryption/decryption roundtrip
		plaintext := []byte("Hello from X25519 keygen test!")
		info := []byte("test info")

		senderCtx, err := hpke.SetupBaseS(suite, pk, info, pcg.NewRandomised())
		require.NoError(t, err)
		ciphertext, err := senderCtx.Seal(plaintext, nil)
		require.NoError(t, err)

		receiverCtx, err := hpke.SetupBaseR(suite, sk, senderCtx.Capsule, info)
		require.NoError(t, err)
		decrypted, err := receiverCtx.Open(ciphertext, nil)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})

	t.Run("GenerateWithSeed", func(t *testing.T) {
		t.Parallel()

		curve := p256.NewCurve()
		suite, err := hpke.NewCipherSuite(hpke.DHKEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM)
		require.NoError(t, err)

		scheme, err := hpke.NewScheme(curve, suite)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)

		// Generate deterministic keys from seed
		seed := make([]byte, 32)
		_, err = pcg.NewRandomised().Read(seed)
		require.NoError(t, err)

		sk1, pk1, err := kg.GenerateWithSeed(seed)
		require.NoError(t, err)

		// Same seed should produce same keys
		sk2, pk2, err := kg.GenerateWithSeed(seed)
		require.NoError(t, err)

		require.Equal(t, sk1.Bytes(), sk2.Bytes())
		require.Equal(t, pk1.Bytes(), pk2.Bytes())
	})
}
