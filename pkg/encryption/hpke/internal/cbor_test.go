package internal

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/stretchr/testify/require"
)

func TestPrivateKeyCBOR_P256(t *testing.T) {
	curve := p256.NewCurve()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	require.False(t, sk.IsZero())

	originalKey, err := NewPrivateKey(sk)
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PrivateKey[*p256.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Bytes(), restoredKey.Bytes())
}

func TestPrivateKeyCBOR_X25519(t *testing.T) {
	curve := curve25519.NewPrimeSubGroup()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	require.False(t, sk.IsZero())

	originalKey, err := NewPrivateKey(sk)
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PrivateKey[*curve25519.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Bytes(), restoredKey.Bytes())
}

func TestPublicKeyCBOR_P256(t *testing.T) {
	curve := p256.NewCurve()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	require.False(t, sk.IsZero())
	pk := curve.ScalarBaseMul(sk)

	originalKey, err := NewPublicKey(pk)
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PublicKey[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Bytes(), restoredKey.Bytes())
}

func TestPublicKeyCBOR_X25519(t *testing.T) {
	curve := curve25519.NewPrimeSubGroup()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	require.False(t, sk.IsZero())
	pk := curve.ScalarBaseMul(sk)

	originalKey, err := NewPublicKey(pk)
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.BaseFieldElement, *curve25519.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Bytes(), restoredKey.Bytes())
}

func TestCipherSuiteCBOR(t *testing.T) {
	tests := []struct {
		name string
		cs   *CipherSuite
	}{
		{
			name: "P256-SHA256-AES128",
			cs: &CipherSuite{
				kem:  DHKEM_P256_HKDF_SHA256,
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_AES_128_GCM,
			},
		},
		{
			name: "X25519-SHA256-ChaCha20",
			cs: &CipherSuite{
				kem:  DHKEM_X25519_HKDF_SHA256,
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_CHACHA_20_POLY_1305,
			},
		},
		{
			name: "P256-SHA512-AES256",
			cs: &CipherSuite{
				kem:  DHKEM_P256_HKDF_SHA256,
				kdf:  KDF_HKDF_SHA512,
				aead: AEAD_AES_256_GCM,
			},
		},
		{
			name: "ExportOnly",
			cs: &CipherSuite{
				kem:  DHKEM_P256_HKDF_SHA256,
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_EXPORT_ONLY,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to CBOR
			data, err := tt.cs.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var restored CipherSuite
			err = restored.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Verify the cipher suites match
			require.Equal(t, tt.cs.kem, restored.kem)
			require.Equal(t, tt.cs.kdf, restored.kdf)
			require.Equal(t, tt.cs.aead, restored.aead)
		})
	}
}

func TestCipherSuiteCBOR_InvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		cs      *CipherSuite
		wantErr bool
	}{
		{
			name: "Reserved KEM",
			cs: &CipherSuite{
				kem:  DHKEM_RESERVED,
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_AES_128_GCM,
			},
			wantErr: true,
		},
		{
			name: "Reserved KDF",
			cs: &CipherSuite{
				kem:  DHKEM_P256_HKDF_SHA256,
				kdf:  KDF_HKDF_RESERVED,
				aead: AEAD_AES_128_GCM,
			},
			wantErr: true,
		},
		{
			name: "Reserved AEAD",
			cs: &CipherSuite{
				kem:  DHKEM_P256_HKDF_SHA256,
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_RESERVED,
			},
			wantErr: true,
		},
		{
			name: "Unknown KEM",
			cs: &CipherSuite{
				kem:  KEMID(0xFFFF),
				kdf:  KDF_HKDF_SHA256,
				aead: AEAD_AES_128_GCM,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to CBOR (should succeed)
			data, err := tt.cs.MarshalCBOR()
			require.NoError(t, err)

			// Unmarshal from CBOR (should fail with validation error)
			var restored CipherSuite
			err = restored.UnmarshalCBOR(data)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPrivateKeyCBOR_WithDerivedIkm(t *testing.T) {
	// Test with X25519 where ikm might differ from v.Bytes() due to clamping
	kem := NewX25519HKDFSha256KEM()

	// Use test vector IKM
	ikmE := []byte{
		0x90, 0x9a, 0x9b, 0x35, 0xd3, 0xdc, 0x47, 0x13,
		0xa5, 0xe7, 0x2a, 0x4d, 0xa2, 0x74, 0xb5, 0x5d,
		0x3d, 0x38, 0x21, 0xa3, 0x7e, 0x5d, 0x09, 0x9e,
		0x74, 0xa6, 0x47, 0xdb, 0x58, 0x3a, 0x90, 0x4b,
	}

	sk, _, err := kem.DeriveKeyPair(ikmE)
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := sk.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PrivateKey[*curve25519.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, sk.Equal(&restoredKey))
	require.Equal(t, sk.Bytes(), restoredKey.Bytes())
}
