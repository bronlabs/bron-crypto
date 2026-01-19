package internal

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
)

// TestDHKEM_Encap_Decap_Roundtrip tests basic encapsulation/decapsulation
func TestDHKEM_Encap_Decap_Roundtrip(t *testing.T) {
	t.Parallel()

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		// Generate receiver key pair
		receiverSk, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)

		// Encapsulate
		sharedSecretEncap, ephemeralPk, err := kem.Encap(receiverPk, crand.Reader)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretEncap)
		require.NotNil(t, ephemeralPk)

		// Decapsulate
		sharedSecretDecap, err := kem.Decap(receiverSk, ephemeralPk)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretDecap)

		// Shared secrets should match
		require.Equal(t, sharedSecretEncap, sharedSecretDecap)
	})

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		// Generate receiver key pair
		receiverSk, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)

		// Encapsulate
		sharedSecretEncap, ephemeralPk, err := kem.Encap(receiverPk, crand.Reader)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretEncap)
		require.NotNil(t, ephemeralPk)

		// Decapsulate
		sharedSecretDecap, err := kem.Decap(receiverSk, ephemeralPk)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretDecap)

		// Shared secrets should match
		require.Equal(t, sharedSecretEncap, sharedSecretDecap)
	})
}

// TestDHKEM_AuthEncap_AuthDecap_Roundtrip tests authenticated encapsulation/decapsulation
func TestDHKEM_AuthEncap_AuthDecap_Roundtrip(t *testing.T) {
	t.Parallel()

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		// Generate keys
		receiverSk, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)
		senderSk, senderPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)

		// Authenticated encapsulation
		sharedSecretEncap, ephemeralPk, err := kem.AuthEncap(receiverPk, senderSk, crand.Reader)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretEncap)

		// Authenticated decapsulation
		sharedSecretDecap, err := kem.AuthDecap(receiverSk, senderPk, ephemeralPk)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretDecap)

		// Shared secrets should match
		require.Equal(t, sharedSecretEncap, sharedSecretDecap)
	})

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		// Generate keys
		receiverSk, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)
		senderSk, senderPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)

		// Authenticated encapsulation
		sharedSecretEncap, ephemeralPk, err := kem.AuthEncap(receiverPk, senderSk, crand.Reader)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretEncap)

		// Authenticated decapsulation
		sharedSecretDecap, err := kem.AuthDecap(receiverSk, senderPk, ephemeralPk)
		require.NoError(t, err)
		require.NotEmpty(t, sharedSecretDecap)

		// Shared secrets should match
		require.Equal(t, sharedSecretEncap, sharedSecretDecap)
	})
}

// TestDHKEM_DeriveKeyPair_Deterministic tests that DeriveKeyPair is deterministic
func TestDHKEM_DeriveKeyPair_Deterministic(t *testing.T) {
	t.Parallel()

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		ikm := make([]byte, 32)
		_, err := crand.Read(ikm)
		require.NoError(t, err)

		// Derive key pair twice with same IKM
		sk1, pk1, err := kem.DeriveKeyPair(ikm)
		require.NoError(t, err)

		sk2, pk2, err := kem.DeriveKeyPair(ikm)
		require.NoError(t, err)

		// Keys should be identical
		require.Equal(t, sk1.Bytes(), sk2.Bytes())
		require.Equal(t, pk1.Bytes(), pk2.Bytes())
	})

	t.Run("X25519", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		ikm := make([]byte, 32)
		_, err := crand.Read(ikm)
		require.NoError(t, err)

		// Derive key pair twice with same IKM
		sk1, pk1, err := kem.DeriveKeyPair(ikm)
		require.NoError(t, err)

		sk2, pk2, err := kem.DeriveKeyPair(ikm)
		require.NoError(t, err)

		// Keys should be identical
		require.Equal(t, sk1.Bytes(), sk2.Bytes())
		require.Equal(t, pk1.Bytes(), pk2.Bytes())
	})
}

// TestDHKEM_KeySizes tests that key sizes match specification
func TestDHKEM_KeySizes(t *testing.T) {
	t.Parallel()

	t.Run("P256_Sizes", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		require.Equal(t, 32, kem.NSecret())
		require.Equal(t, 65, kem.NEnc())
		require.Equal(t, 65, kem.NPk())
		require.Equal(t, 32, kem.NSk())
		require.Equal(t, DHKEM_P256_HKDF_SHA256, kem.ID())
	})

	t.Run("X25519_Sizes", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		require.Equal(t, 32, kem.NSecret())
		require.Equal(t, 32, kem.NEnc())
		require.Equal(t, 32, kem.NPk())
		require.Equal(t, 32, kem.NSk())
		require.Equal(t, DHKEM_X25519_HKDF_SHA256, kem.ID())
	})
}

// TestCipherSuite_Creation tests cipher suite creation and validation
func TestCipherSuite_Creation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		kemID   KEMID
		kdfID   KDFID
		aeadID  AEADID
		wantErr bool
	}{
		{
			name:    "Valid_P256_SHA256_AES128",
			kemID:   DHKEM_P256_HKDF_SHA256,
			kdfID:   KDF_HKDF_SHA256,
			aeadID:  AEAD_AES_128_GCM,
			wantErr: false,
		},
		{
			name:    "Valid_X25519_SHA256_ChaCha20",
			kemID:   DHKEM_X25519_HKDF_SHA256,
			kdfID:   KDF_HKDF_SHA256,
			aeadID:  AEAD_CHACHA_20_POLY_1305,
			wantErr: false,
		},
		{
			name:    "Invalid_KEM_Reserved",
			kemID:   DHKEM_RESERVED,
			kdfID:   KDF_HKDF_SHA256,
			aeadID:  AEAD_AES_128_GCM,
			wantErr: true,
		},
		{
			name:    "Invalid_KDF_Reserved",
			kemID:   DHKEM_P256_HKDF_SHA256,
			kdfID:   KDF_HKDF_RESERVED,
			aeadID:  AEAD_AES_128_GCM,
			wantErr: true,
		},
		{
			name:    "Invalid_AEAD_Reserved",
			kemID:   DHKEM_P256_HKDF_SHA256,
			kdfID:   KDF_HKDF_SHA256,
			aeadID:  AEAD_RESERVED,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			suite, err := NewCipherSuite(tc.kemID, tc.kdfID, tc.aeadID)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, suite)
			} else {
				require.NoError(t, err)
				require.NotNil(t, suite)
				require.Equal(t, tc.kemID, suite.KEMID())
				require.Equal(t, tc.kdfID, suite.KDFID())
				require.Equal(t, tc.aeadID, suite.AEADID())
			}
		})
	}
}

// TestContexts_SequenceNumber tests that sequence numbers increment correctly
func TestContexts_SequenceNumber(t *testing.T) {
	t.Parallel()

	kem := NewP256HKDFSha256KEM()
	suite, err := NewCipherSuite(DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	receiverSk, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
	require.NoError(t, err)

	info := []byte("sequence test")

	// Setup contexts
	senderCtx, err := NewSenderContext(Base, suite, receiverPk, nil, info, nil, nil, crand.Reader)
	require.NoError(t, err)
	receiverCtx, err := NewReceiverContext(Base, suite, receiverSk, senderCtx.Capsule, nil, info, nil, nil)
	require.NoError(t, err)

	// Encrypt and decrypt multiple messages, checking sequence numbers
	for i := range 5 {
		msg := []byte("Message " + string(rune(i)))
		ct, err := senderCtx.Seal(msg, nil)
		require.NoError(t, err)

		pt, err := receiverCtx.Open(ct, nil)
		require.NoError(t, err)
		require.Equal(t, msg, pt)
	}
}

// TestKDF_LabeledExtract tests labelled extract function
func TestKDF_LabeledExtract(t *testing.T) {
	t.Parallel()

	t.Run("SHA256", func(t *testing.T) {
		t.Parallel()
		kdf := NewKDFSHA256()

		suiteID := []byte("KEM")
		salt := []byte("test salt")
		label := []byte("test label")
		ikm := []byte("input keying material")

		prk := kdf.labeledExtract(suiteID, salt, label, ikm)
		require.NotEmpty(t, prk)
		require.Len(t, prk, kdf.Nh())

		// Deterministic check
		prk2 := kdf.labeledExtract(suiteID, salt, label, ikm)
		require.Equal(t, prk, prk2)
	})

	t.Run("SHA512", func(t *testing.T) {
		t.Parallel()
		kdf := NewKDFSHA512()

		suiteID := []byte("KEM")
		salt := []byte("test salt")
		label := []byte("test label")
		ikm := []byte("input keying material")

		prk := kdf.labeledExtract(suiteID, salt, label, ikm)
		require.NotEmpty(t, prk)
		require.Len(t, prk, kdf.Nh())

		// Deterministic check
		prk2 := kdf.labeledExtract(suiteID, salt, label, ikm)
		require.Equal(t, prk, prk2)
	})
}

// TestKDF_LabeledExpand tests labelled expand function
func TestKDF_LabeledExpand(t *testing.T) {
	t.Parallel()

	kdf := NewKDFSHA256()

	suiteID := []byte("KEM")
	prk := make([]byte, kdf.Nh())
	_, err := crand.Read(prk)
	require.NoError(t, err)

	label := []byte("test label")
	info := []byte("context info")
	length := 32

	expanded := kdf.labeledExpand(suiteID, prk, label, info, length)
	require.NotEmpty(t, expanded)
	require.Len(t, expanded, length)

	// Deterministic check
	expanded2 := kdf.labeledExpand(suiteID, prk, label, info, length)
	require.Equal(t, expanded, expanded2)

	// Different lengths should produce different outputs
	expanded3 := kdf.labeledExpand(suiteID, prk, label, info, 64)
	require.NotEqual(t, expanded, expanded3)
	require.Len(t, expanded3, 64)
}

// TestAEAD_Encryption tests AEAD encryption/decryption
func TestAEAD_Encryption(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		aeadID AEADID
		keyLen int
	}{
		{"AES128GCM", AEAD_AES_128_GCM, 16},
		{"AES256GCM", AEAD_AES_256_GCM, 32},
		{"ChaCha20Poly1305", AEAD_CHACHA_20_POLY_1305, 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme, err := NewAEAD(tc.aeadID)
			require.NoError(t, err)

			// Generate random key
			key := make([]byte, tc.keyLen)
			_, err = crand.Read(key)
			require.NoError(t, err)

			aead, err := scheme.New(key)
			require.NoError(t, err)

			// Test encryption/decryption
			nonce := make([]byte, aead.NonceSize())
			_, err = crand.Read(nonce)
			require.NoError(t, err)

			plaintext := []byte("Test message for AEAD")
			aad := []byte("additional data")

			ciphertext := aead.Seal(nil, nonce, plaintext, aad)
			require.NotEmpty(t, ciphertext)

			decrypted, err := aead.Open(nil, nonce, ciphertext, aad)
			require.NoError(t, err)
			require.Equal(t, plaintext, decrypted)

			// Wrong AAD should fail
			wrongAAD := []byte("wrong aad")
			_, err = aead.Open(nil, nonce, ciphertext, wrongAAD)
			require.Error(t, err)
		})
	}
}

// TestPrivateKey_PublicKey_Creation tests key creation
func TestPrivateKey_PublicKey_Creation(t *testing.T) {
	t.Parallel()

	t.Run("P256_Keys", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		scalar, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)

		ikm := scalar.Bytes()
		sk, err := NewPrivateKey(curve.ScalarField(), ikm)
		require.NoError(t, err)
		require.NotNil(t, sk)
		require.Equal(t, ikm, sk.Bytes())

		point := curve.ScalarBaseMul(scalar)
		pk, err := NewPublicKey(point)
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("X25519_Keys", func(t *testing.T) {
		t.Parallel()
		curve := curve25519.NewPrimeSubGroup()
		scalar, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)

		ikm := scalar.Bytes()
		sk, err := NewPrivateKey(curve.ScalarField(), ikm)
		require.NoError(t, err)
		require.NotNil(t, sk)

		point := curve.ScalarBaseMul(scalar)
		pk, err := NewPublicKey(point)
		require.NoError(t, err)
		require.NotNil(t, pk)
	})
}

// TestContext_NonceReuse tests that nonce reuse is detected
func TestContext_NonceReuse(t *testing.T) {
	t.Parallel()

	kem := NewP256HKDFSha256KEM()
	suite, err := NewCipherSuite(DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM)
	require.NoError(t, err)

	// Generate receiver key pair
	_, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
	require.NoError(t, err)

	info := []byte("nonce reuse test")

	// Setup sender context
	senderCtx, err := NewSenderContext(Base, suite, receiverPk, nil, info, nil, nil, crand.Reader)
	require.NoError(t, err)

	// Encrypt a message
	msg1 := []byte("First message")
	_, err = senderCtx.Seal(msg1, nil)
	require.NoError(t, err)

	// Manually reset sequence to 0 to simulate nonce reuse
	oldSeq := senderCtx.ctx.sequence
	senderCtx.ctx.sequence = 0

	// This should fail due to nonce reuse
	_, err = senderCtx.Seal([]byte("Reused nonce"), nil)
	require.Error(t, err, "Should detect nonce reuse")

	// Restore sequence
	senderCtx.ctx.sequence = oldSeq
}

// TestDHKEM_InvalidInputs tests error handling
func TestDHKEM_InvalidInputs(t *testing.T) {
	t.Parallel()

	t.Run("NilPRNG", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		// Nil PRNG
		_, receiverPk, err := kem.GenerateKeyPair(crand.Reader)
		require.NoError(t, err)

		_, _, err = kem.Encap(receiverPk, nil)
		require.Error(t, err)
	})

	t.Run("ShortIKM", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		// IKM shorter than NSk
		shortIKM := make([]byte, kem.NSk()-1)
		_, _, err := kem.DeriveKeyPair(shortIKM)
		require.Error(t, err, "Should reject short IKM")
	})
}

// TestKDF_HashLength tests that hash lengths are correct
func TestKDF_HashLength(t *testing.T) {
	t.Parallel()

	t.Run("SHA256", func(t *testing.T) {
		t.Parallel()
		kdf := NewKDFSHA256()
		require.Equal(t, 32, kdf.Nh())
		require.Equal(t, KDF_HKDF_SHA256, kdf.ID())
	})

	t.Run("SHA512", func(t *testing.T) {
		t.Parallel()
		kdf := NewKDFSHA512()
		require.Equal(t, 64, kdf.Nh())
		require.Equal(t, KDF_HKDF_SHA512, kdf.ID())
	})
}

// TestDHKEM_ExtractAndExpand tests the extractAndExpand function
func TestDHKEM_ExtractAndExpand(t *testing.T) {
	t.Parallel()

	kem := NewP256HKDFSha256KEM()

	dhBytes := make([]byte, 32)
	_, err := crand.Read(dhBytes)
	require.NoError(t, err)

	kemContext := []byte("kem context")

	sharedSecret := kem.extractAndExpand(dhBytes, kemContext)
	require.NotEmpty(t, sharedSecret)
	require.Len(t, sharedSecret, kem.kdf.Nh())

	// Should be deterministic
	sharedSecret2 := kem.extractAndExpand(dhBytes, kemContext)
	require.Equal(t, sharedSecret, sharedSecret2)

	// Different context should produce different output
	kemContext2 := []byte("different context")
	sharedSecret3 := kem.extractAndExpand(dhBytes, kemContext2)
	require.NotEqual(t, sharedSecret, sharedSecret3)
}
