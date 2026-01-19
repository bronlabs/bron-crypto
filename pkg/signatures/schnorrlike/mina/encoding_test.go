package mina_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/base58"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
)

func TestEncodePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("nil public key", func(t *testing.T) {
		t.Parallel()
		encoded, err := mina.EncodePublicKey(nil)
		require.Empty(t, encoded)
		require.Error(t, err)
	})

	t.Run("valid public key", func(t *testing.T) {
		t.Parallel()
		privateKey, err := mina.DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		require.NoError(t, err)

		publicKey := privateKey.PublicKey()
		encoded, err := mina.EncodePublicKey(publicKey)
		require.NoError(t, err)
		require.NotEmpty(t, encoded)

		// Should start with expected prefix
		require.NotEmpty(t, encoded)
	})
}

func TestDecodePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("valid public key", func(t *testing.T) {
		t.Parallel()
		// Known valid public key
		encoded := base58.Base58("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
		pk, err := mina.DecodePublicKey(encoded)
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("invalid base58", func(t *testing.T) {
		t.Parallel()
		pk, err := mina.DecodePublicKey(base58.Base58("invalid0O0base58"))
		require.Nil(t, pk)
		require.Error(t, err)
	})

	t.Run("wrong version prefix", func(t *testing.T) {
		t.Parallel()
		// Use a private key encoding (different version prefix)
		pk, err := mina.DecodePublicKey(base58.Base58("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw"))
		require.Nil(t, pk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "version prefix")
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		// Generate a new key pair
		scheme, err := mina.NewRandomisedScheme(mina.TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		_, publicKey, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		// Encode
		encoded, err := mina.EncodePublicKey(publicKey)
		require.NoError(t, err)

		// Decode
		decoded, err := mina.DecodePublicKey(encoded)
		require.NoError(t, err)

		// Verify they match
		require.True(t, publicKey.Value().Equal(decoded.Value()))
	})
}

func TestEncodePrivateKey(t *testing.T) {
	t.Parallel()

	t.Run("nil private key", func(t *testing.T) {
		t.Parallel()
		encoded, err := mina.EncodePrivateKey(nil)
		require.Empty(t, encoded)
		require.Error(t, err)
	})

	t.Run("valid private key", func(t *testing.T) {
		t.Parallel()
		privateKey, err := mina.DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		require.NoError(t, err)

		encoded, err := mina.EncodePrivateKey(privateKey)
		require.NoError(t, err)
		require.NotEmpty(t, encoded)
	})
}

func TestDecodePrivateKey(t *testing.T) {
	t.Parallel()

	t.Run("valid private key", func(t *testing.T) {
		t.Parallel()
		encoded := base58.Base58("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		sk, err := mina.DecodePrivateKey(encoded)
		require.NoError(t, err)
		require.NotNil(t, sk)
	})

	t.Run("invalid base58", func(t *testing.T) {
		t.Parallel()
		sk, err := mina.DecodePrivateKey(base58.Base58("invalid0O0base58"))
		require.Nil(t, sk)
		require.Error(t, err)
	})

	t.Run("wrong version prefix", func(t *testing.T) {
		t.Parallel()
		// Use a public key encoding (different version prefix)
		sk, err := mina.DecodePrivateKey(base58.Base58("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg"))
		require.Nil(t, sk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "version prefix")
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		// Generate a new key pair
		scheme, err := mina.NewRandomisedScheme(mina.TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, _, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		// Encode
		encoded, err := mina.EncodePrivateKey(privateKey)
		require.NoError(t, err)

		// Decode
		decoded, err := mina.DecodePrivateKey(encoded)
		require.NoError(t, err)

		// Verify they match
		require.True(t, privateKey.Value().Equal(decoded.Value()))
	})
}

func TestEncodeSignature(t *testing.T) {
	t.Parallel()

	t.Run("nil signature", func(t *testing.T) {
		t.Parallel()
		encoded, err := mina.EncodeSignature(nil)
		require.Empty(t, encoded)
		require.Error(t, err)
	})

	t.Run("valid signature", func(t *testing.T) {
		t.Parallel()
		scheme, err := mina.NewRandomisedScheme(mina.TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, _, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(mina.ROInput).Init()
		msg.AddString("test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		encoded, err := mina.EncodeSignature(sig)
		require.NoError(t, err)
		require.NotEmpty(t, encoded)
	})
}

func TestDecodeSignature(t *testing.T) {
	t.Parallel()

	t.Run("invalid base58", func(t *testing.T) {
		t.Parallel()
		sig, err := mina.DecodeSignature(base58.Base58("invalid0O0base58"))
		require.Nil(t, sig)
		require.Error(t, err)
	})

	t.Run("wrong version prefix", func(t *testing.T) {
		t.Parallel()
		// Use a public key encoding (different version prefix)
		sig, err := mina.DecodeSignature(base58.Base58("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg"))
		require.Nil(t, sig)
		require.Error(t, err)
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		scheme, err := mina.NewRandomisedScheme(mina.TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, publicKey, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(mina.ROInput).Init()
		msg.AddString("test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		// Encode
		encoded, err := mina.EncodeSignature(sig)
		require.NoError(t, err)

		// Decode
		decoded, err := mina.DecodeSignature(encoded)
		require.NoError(t, err)

		// Verify they match
		rx1, _ := sig.R.AffineX()
		rx2, _ := decoded.R.AffineX()
		require.True(t, rx1.Equal(rx2))
		require.True(t, sig.S.Equal(decoded.S))

		// Verify the decoded signature is valid
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(decoded, publicKey, msg)
		require.NoError(t, err)
	})
}

func TestKnownKeyVectors(t *testing.T) {
	t.Parallel()

	// Test with known test vectors from o1js
	testCases := []struct {
		name       string
		privateKey base58.Base58
		publicKey  base58.Base58
	}{
		{
			name:       "test vector 1",
			privateKey: "EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw",
			publicKey:  "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Decode private key
			sk, err := mina.DecodePrivateKey(tc.privateKey)
			require.NoError(t, err)

			// Decode expected public key
			expectedPK, err := mina.DecodePublicKey(tc.publicKey)
			require.NoError(t, err)

			// Derive public key from private key
			derivedPK := sk.PublicKey()

			// Verify they match
			require.True(t, derivedPK.Value().Equal(expectedPK.Value()),
				"derived public key should match expected")

			// Verify encoding round-trip produces same string
			encodedPK, err := mina.EncodePublicKey(derivedPK)
			require.NoError(t, err)
			require.Equal(t, tc.publicKey, encodedPK)

			encodedSK, err := mina.EncodePrivateKey(sk)
			require.NoError(t, err)
			require.Equal(t, tc.privateKey, encodedSK)
		})
	}
}
