package internal //nolint:testpackage // to test unexported identifiers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// TestPrivateKey_CBOR tests CBOR marshalling of private keys
func TestPrivateKey_CBOR(t *testing.T) {
	t.Parallel()

	t.Run("P256_PrivateKey", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		sk, _, err := kem.GenerateKeyPair(pcg.NewRandomised())
		require.NoError(t, err)

		// Marshal
		cborData, err := sk.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, cborData)

		// Unmarshal
		sk2 := new(PrivateKey[*p256.Scalar])
		err = sk2.UnmarshalCBOR(cborData)
		require.NoError(t, err)

		// Verify equality
		require.Equal(t, sk.Bytes(), sk2.Bytes())
		require.True(t, sk.Value().Equal(sk2.Value()))
	})

	t.Run("X25519_PrivateKey", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		sk, _, err := kem.GenerateKeyPair(pcg.NewRandomised())
		require.NoError(t, err)

		// Marshal
		cborData, err := sk.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, cborData)

		// Unmarshal
		sk2 := new(PrivateKey[*curve25519.Scalar])
		err = sk2.UnmarshalCBOR(cborData)
		require.NoError(t, err)

		// Verify equality
		require.Equal(t, sk.Bytes(), sk2.Bytes())
		require.True(t, sk.Value().Equal(sk2.Value()))
	})
}

// TestPublicKey_CBOR tests CBOR marshalling of public keys
func TestPublicKey_CBOR(t *testing.T) {
	t.Parallel()

	t.Run("P256_PublicKey", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		_, pk, err := kem.GenerateKeyPair(pcg.NewRandomised())
		require.NoError(t, err)

		// Marshal
		cborData, err := pk.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, cborData)

		// Unmarshal
		pk2 := new(PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
		err = pk2.UnmarshalCBOR(cborData)
		require.NoError(t, err)

		// Verify equality
		require.Equal(t, pk.Bytes(), pk2.Bytes())
		require.True(t, pk.Equal(pk2))
	})

	t.Run("X25519_PublicKey", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		_, pk, err := kem.GenerateKeyPair(pcg.NewRandomised())
		require.NoError(t, err)

		// Marshal
		cborData, err := pk.MarshalCBOR()
		require.NoError(t, err)
		require.NotEmpty(t, cborData)

		// Unmarshal
		pk2 := new(PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.BaseFieldElement, *curve25519.Scalar])
		err = pk2.UnmarshalCBOR(cborData)
		require.NoError(t, err)

		// Verify equality
		require.Equal(t, pk.Bytes(), pk2.Bytes())
		require.True(t, pk.Equal(pk2))
	})
}

// TestCipherSuite_CBOR tests CBOR marshalling of cipher suites
func TestCipherSuite_CBOR(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		kemID  KEMID
		kdfID  KDFID
		aeadID AEADID
	}{
		{
			name:   "P256_SHA256_AES128",
			kemID:  DHKEM_P256_HKDF_SHA256,
			kdfID:  KDF_HKDF_SHA256,
			aeadID: AEAD_AES_128_GCM,
		},
		{
			name:   "X25519_SHA256_ChaCha20",
			kemID:  DHKEM_X25519_HKDF_SHA256,
			kdfID:  KDF_HKDF_SHA256,
			aeadID: AEAD_CHACHA_20_POLY_1305,
		},
		{
			name:   "P256_SHA512_AES256",
			kemID:  DHKEM_P256_HKDF_SHA256,
			kdfID:  KDF_HKDF_SHA512,
			aeadID: AEAD_AES_256_GCM,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite, err := NewCipherSuite(tc.kemID, tc.kdfID, tc.aeadID)
			require.NoError(t, err)

			// Marshal
			cborData, err := suite.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, cborData)

			// Unmarshal
			suite2 := new(CipherSuite)
			err = suite2.UnmarshalCBOR(cborData)
			require.NoError(t, err)

			// Verify
			require.Equal(t, suite.KEMID(), suite2.KEMID())
			require.Equal(t, suite.KDFID(), suite2.KDFID())
			require.Equal(t, suite.AEADID(), suite2.AEADID())
		})
	}
}

// TestCipherSuite_CBOR_InvalidData tests error handling for invalid CBOR
func TestCipherSuite_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		modify  func(*CipherSuite)
		wantErr bool
	}{
		{
			name: "ReservedKEM",
			modify: func(cs *CipherSuite) {
				cs.kem = DHKEM_RESERVED
			},
			wantErr: true,
		},
		{
			name: "ReservedKDF",
			modify: func(cs *CipherSuite) {
				cs.kdf = KDF_HKDF_RESERVED
			},
			wantErr: true,
		},
		{
			name: "ReservedAEAD",
			modify: func(cs *CipherSuite) {
				cs.aead = AEAD_RESERVED
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite, err := NewCipherSuite(DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM)
			require.NoError(t, err)

			// Modify before marshalling
			tc.modify(suite)

			// Marshal
			cborData, err := suite.MarshalCBOR()
			require.NoError(t, err)

			// Unmarshal should fail for invalid values
			suite2 := new(CipherSuite)
			err = suite2.UnmarshalCBOR(cborData)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestKeyPair_CBOR_Roundtrip tests multiple CBOR roundtrips
func TestKeyPair_CBOR_Roundtrip(t *testing.T) {
	t.Parallel()

	t.Run("P256_MultipleRoundtrips", func(t *testing.T) {
		t.Parallel()
		kem := NewP256HKDFSha256KEM()

		for range 5 {
			sk, pk, err := kem.GenerateKeyPair(pcg.NewRandomised())
			require.NoError(t, err)

			// Private key roundtrip
			skCBOR, err := sk.MarshalCBOR()
			require.NoError(t, err)
			sk2 := new(PrivateKey[*p256.Scalar])
			err = sk2.UnmarshalCBOR(skCBOR)
			require.NoError(t, err)
			require.Equal(t, sk.Bytes(), sk2.Bytes())

			// Public key roundtrip
			pkCBOR, err := pk.MarshalCBOR()
			require.NoError(t, err)
			pk2 := new(PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
			err = pk2.UnmarshalCBOR(pkCBOR)
			require.NoError(t, err)
			require.Equal(t, pk.Bytes(), pk2.Bytes())

			// Second roundtrip to ensure determinism
			skCBOR2, err := sk2.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, skCBOR, skCBOR2, "CBOR encoding should be deterministic")

			pkCBOR2, err := pk2.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, pkCBOR, pkCBOR2, "CBOR encoding should be deterministic")
		}
	})

	t.Run("X25519_MultipleRoundtrips", func(t *testing.T) {
		t.Parallel()
		kem := NewX25519HKDFSha256KEM()

		for range 5 {
			sk, pk, err := kem.GenerateKeyPair(pcg.NewRandomised())
			require.NoError(t, err)

			// Private key roundtrip
			skCBOR, err := sk.MarshalCBOR()
			require.NoError(t, err)
			sk2 := new(PrivateKey[*curve25519.Scalar])
			err = sk2.UnmarshalCBOR(skCBOR)
			require.NoError(t, err)
			require.Equal(t, sk.Bytes(), sk2.Bytes())

			// Public key roundtrip
			pkCBOR, err := pk.MarshalCBOR()
			require.NoError(t, err)
			pk2 := new(PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.BaseFieldElement, *curve25519.Scalar])
			err = pk2.UnmarshalCBOR(pkCBOR)
			require.NoError(t, err)
			require.Equal(t, pk.Bytes(), pk2.Bytes())

			// Second roundtrip to ensure determinism
			skCBOR2, err := sk2.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, skCBOR, skCBOR2, "CBOR encoding should be deterministic")

			pkCBOR2, err := pk2.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, pkCBOR, pkCBOR2, "CBOR encoding should be deterministic")
		}
	})
}

// TestCipherSuite_CBOR_Roundtrip tests cipher suite CBOR roundtrip
func TestCipherSuite_CBOR_Roundtrip(t *testing.T) {
	t.Parallel()

	suites := []struct {
		name   string
		kemID  KEMID
		kdfID  KDFID
		aeadID AEADID
	}{
		{"P256_SHA256_AES128", DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM},
		{"X25519_SHA256_ChaCha20", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA_20_POLY_1305},
		{"P256_SHA512_AES256", DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA512, AEAD_AES_256_GCM},
		{"X25519_SHA512_AES128", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA512, AEAD_AES_128_GCM},
	}

	for _, suite := range suites {
		t.Run(suite.name, func(t *testing.T) {
			t.Parallel()

			cs, err := NewCipherSuite(suite.kemID, suite.kdfID, suite.aeadID)
			require.NoError(t, err)

			// First roundtrip
			cbor1, err := cs.MarshalCBOR()
			require.NoError(t, err)

			cs2 := new(CipherSuite)
			err = cs2.UnmarshalCBOR(cbor1)
			require.NoError(t, err)

			// Second roundtrip
			cbor2, err := cs2.MarshalCBOR()
			require.NoError(t, err)

			cs3 := new(CipherSuite)
			err = cs3.UnmarshalCBOR(cbor2)
			require.NoError(t, err)

			// All should be equal
			require.Equal(t, cs.KEMID(), cs2.KEMID())
			require.Equal(t, cs.KDFID(), cs2.KDFID())
			require.Equal(t, cs.AEADID(), cs2.AEADID())
			require.Equal(t, cbor1, cbor2, "CBOR encoding should be deterministic")
		})
	}
}

// TestPrivateKey_CBOR_InvalidData tests error handling
func TestPrivateKey_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("EmptyData", func(t *testing.T) {
		t.Parallel()
		sk := new(PrivateKey[*p256.Scalar])
		err := sk.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("InvalidCBOR", func(t *testing.T) {
		t.Parallel()
		sk := new(PrivateKey[*p256.Scalar])
		err := sk.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

// TestPublicKey_CBOR_InvalidData tests error handling for public keys
func TestPublicKey_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("EmptyData", func(t *testing.T) {
		t.Parallel()
		pk := new(PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
		err := pk.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("InvalidCBOR", func(t *testing.T) {
		t.Parallel()
		pk := new(PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar])
		err := pk.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}
