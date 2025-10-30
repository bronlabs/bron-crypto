package key_agreement

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/stretchr/testify/require"
)

func TestPrivateKeyCBOR_P256(t *testing.T) {
	curve := p256.NewCurve()

	// Generate a random private key
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)

	originalKey, err := NewPrivateKey(sk, "ECSVDP-DHC")
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
	require.Equal(t, originalKey.Type(), restoredKey.Type())
	require.True(t, originalKey.Value().Equal(restoredKey.Value()))
}

func TestPrivateKeyCBOR_X25519(t *testing.T) {
	curve := curve25519.NewPrimeSubGroup()

	// Generate a random private key
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)

	originalKey, err := NewPrivateKey(sk, "X25519")
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
	require.Equal(t, originalKey.Type(), restoredKey.Type())
	require.True(t, originalKey.Value().Equal(restoredKey.Value()))
}

func TestPublicKeyCBOR_P256(t *testing.T) {
	curve := p256.NewCurve()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	pk := curve.ScalarBaseMul(sk)

	originalKey, err := NewPublicKey(pk, "ECSVDP-DHC")
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PublicKey[*p256.Point, *p256.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Type(), restoredKey.Type())
	require.True(t, originalKey.Value().Equal(restoredKey.Value()))
}

func TestPublicKeyCBOR_X25519(t *testing.T) {
	curve := curve25519.NewPrimeSubGroup()

	// Generate a key pair
	sk, err := curve.ScalarField().Random(rand.Reader)
	require.NoError(t, err)
	pk := curve.ScalarBaseMul(sk)

	originalKey, err := NewPublicKey(pk, "X25519")
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := originalKey.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var restoredKey PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.Scalar]
	err = restoredKey.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Verify the keys match
	require.True(t, originalKey.Equal(&restoredKey))
	require.Equal(t, originalKey.Type(), restoredKey.Type())
	require.True(t, originalKey.Value().Equal(restoredKey.Value()))
}

func TestSharedKeyCBOR(t *testing.T) {
	tests := []struct {
		name     string
		keyBytes []byte
		keyType  Type
	}{
		{
			name:     "ECSVDP-DHC with 32 bytes",
			keyBytes: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
			keyType:  "ECSVDP-DHC",
		},
		{
			name:     "X25519 with 32 bytes",
			keyBytes: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
			keyType:  "X25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalKey, err := NewSharedKey(tt.keyBytes, tt.keyType)
			require.NoError(t, err)

			// Marshal to CBOR
			data, err := originalKey.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var restoredKey SharedKey
			err = restoredKey.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Verify the keys match
			require.True(t, originalKey.Equal(&restoredKey))
			require.Equal(t, originalKey.Type(), restoredKey.Type())
			require.Equal(t, originalKey.Bytes(), restoredKey.Bytes())
		})
	}
}

func TestPrivateKeyCBOR_InvalidInputs(t *testing.T) {
	curve := p256.NewCurve()

	t.Run("Zero private key should fail validation", func(t *testing.T) {
		sk := curve.ScalarField().Zero()

		// NewPrivateKey should fail
		_, err := NewPrivateKey(sk, "ECSVDP-DHC")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid private key")
	})

	t.Run("Invalid CBOR data", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF, 0xFF}

		var restoredKey PrivateKey[*p256.Scalar]
		err := restoredKey.UnmarshalCBOR(invalidData)
		require.Error(t, err)
	})
}

func TestPublicKeyCBOR_InvalidInputs(t *testing.T) {
	curve := p256.NewCurve()

	t.Run("Identity point should fail validation", func(t *testing.T) {
		// Create identity point by multiplying by zero
		sk := curve.ScalarField().Zero()
		pk := curve.ScalarBaseMul(sk)

		// NewPublicKey should fail
		_, err := NewPublicKey(pk, "ECSVDP-DHC")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid public key")
	})

	t.Run("Invalid CBOR data", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF, 0xFF}

		var restoredKey PublicKey[*p256.Point, *p256.Scalar]
		err := restoredKey.UnmarshalCBOR(invalidData)
		require.Error(t, err)
	})
}

func TestSharedKeyCBOR_InvalidInputs(t *testing.T) {
	t.Run("Zero shared key should fail validation", func(t *testing.T) {
		zeroBytes := make([]byte, 32)

		// NewSharedKey should fail
		_, err := NewSharedKey(zeroBytes, "ECSVDP-DHC")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid shared key")
	})

	t.Run("Invalid CBOR data", func(t *testing.T) {
		invalidData := []byte{0xFF, 0xFF, 0xFF}

		var restoredKey SharedKey
		err := restoredKey.UnmarshalCBOR(invalidData)
		require.Error(t, err)
	})
}

func TestPrivateKeyCBOR_RoundTrip(t *testing.T) {
	// Test with multiple iterations to ensure consistency
	curve := p256.NewCurve()

	for i := 0; i < 10; i++ {
		sk, err := curve.ScalarField().Random(rand.Reader)
		require.NoError(t, err)

		originalKey, err := NewPrivateKey(sk, "ECSVDP-DHC")
		require.NoError(t, err)

		// First round trip
		data1, err := originalKey.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey1 PrivateKey[*p256.Scalar]
		err = restoredKey1.UnmarshalCBOR(data1)
		require.NoError(t, err)

		// Second round trip
		data2, err := restoredKey1.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey2 PrivateKey[*p256.Scalar]
		err = restoredKey2.UnmarshalCBOR(data2)
		require.NoError(t, err)

		// All should be equal
		require.True(t, originalKey.Equal(&restoredKey1))
		require.True(t, originalKey.Equal(&restoredKey2))
		require.True(t, restoredKey1.Equal(&restoredKey2))

		// CBOR data should be identical
		require.Equal(t, data1, data2)
	}
}

func TestPublicKeyCBOR_RoundTrip(t *testing.T) {
	// Test with multiple iterations to ensure consistency
	curve := curve25519.NewPrimeSubGroup()

	for i := 0; i < 10; i++ {
		sk, err := curve.ScalarField().Random(rand.Reader)
		require.NoError(t, err)
		pk := curve.ScalarBaseMul(sk)

		originalKey, err := NewPublicKey(pk, "X25519")
		require.NoError(t, err)

		// First round trip
		data1, err := originalKey.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey1 PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.Scalar]
		err = restoredKey1.UnmarshalCBOR(data1)
		require.NoError(t, err)

		// Second round trip
		data2, err := restoredKey1.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey2 PublicKey[*curve25519.PrimeSubGroupPoint, *curve25519.Scalar]
		err = restoredKey2.UnmarshalCBOR(data2)
		require.NoError(t, err)

		// All should be equal
		require.True(t, originalKey.Equal(&restoredKey1))
		require.True(t, originalKey.Equal(&restoredKey2))
		require.True(t, restoredKey1.Equal(&restoredKey2))

		// CBOR data should be identical
		require.Equal(t, data1, data2)
	}
}

func TestSharedKeyCBOR_RoundTrip(t *testing.T) {
	// Test with multiple iterations to ensure consistency
	for i := 0; i < 10; i++ {
		keyBytes := make([]byte, 32)
		_, err := rand.Read(keyBytes)
		require.NoError(t, err)

		originalKey, err := NewSharedKey(keyBytes, "X25519")
		require.NoError(t, err)

		// First round trip
		data1, err := originalKey.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey1 SharedKey
		err = restoredKey1.UnmarshalCBOR(data1)
		require.NoError(t, err)

		// Second round trip
		data2, err := restoredKey1.MarshalCBOR()
		require.NoError(t, err)

		var restoredKey2 SharedKey
		err = restoredKey2.UnmarshalCBOR(data2)
		require.NoError(t, err)

		// All should be equal
		require.True(t, originalKey.Equal(&restoredKey1))
		require.True(t, originalKey.Equal(&restoredKey2))
		require.True(t, restoredKey1.Equal(&restoredKey2))

		// CBOR data should be identical
		require.Equal(t, data1, data2)
	}
}
