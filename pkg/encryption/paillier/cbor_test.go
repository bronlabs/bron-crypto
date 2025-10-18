package paillier_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/stretchr/testify/require"
)

func TestPlaintext_CBOR(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()

	// Test with several different plaintexts
	testCases := []struct {
		name      string
		createPt  func() *paillier.Plaintext
	}{
		{
			name: "zero",
			createPt: func() *paillier.Plaintext {
				return ps.Zero()
			},
		},
		{
			name: "random",
			createPt: func() *paillier.Plaintext {
				pt, _ := ps.Sample(nil, nil, crand.Reader)
				return pt
			},
		},
		{
			name: "from_nat",
			createPt: func() *paillier.Plaintext {
				n := numct.NewNat(12345)
				pt, _ := ps.FromNat(n)
				return pt
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.createPt()

			// Marshal
			data, err := serde.MarshalCBOR(original)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal
			decoded, err := serde.UnmarshalCBOR[*paillier.Plaintext](data)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			// Verify equality
			require.True(t, original.Equal(decoded))
			require.True(t, original.N().Equal(decoded.N()))
		})
	}
}

func TestNonce_CBOR(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	ns := pk.NonceSpace()

	// Sample a random nonce
	original, err := ns.Sample(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.Nonce](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify the values match
	require.True(t, original.Value().Equal(decoded.Value()))
}

func TestCiphertext_CBOR(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Create a plaintext and encrypt it
	ps := pk.PlaintextSpace()
	plaintext, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	original, nonce, err := enc.Encrypt(plaintext, pk, crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.Ciphertext](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify the values match
	require.True(t, original.Equal(decoded))

	// Verify decryption still works
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(decoded)
	require.NoError(t, err)
	require.True(t, plaintext.Equal(decrypted))

	// Verify we can still encrypt with the deserialized nonce
	reEncrypted, err := enc.EncryptWithNonce(plaintext, pk, nonce)
	require.NoError(t, err)
	require.True(t, original.Equal(reEncrypted))
}

func TestPublicKey_CBOR(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	_, original, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.PublicKey](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify equality
	require.True(t, original.Equal(decoded))
	require.True(t, original.N().Nat().Equal(decoded.N().Nat()) == ct.True)

	// Verify we can use the decoded key
	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	plaintext := decoded.PlaintextSpace().Zero()
	_, _, err = enc.Encrypt(plaintext, decoded, crand.Reader)
	require.NoError(t, err)
}

func TestPrivateKey_CBOR(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	original, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.PrivateKey](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify equality
	require.True(t, original.Equal(decoded))

	// Verify we can use the decoded key for decryption
	ps := decoded.PublicKey().PlaintextSpace()
	plaintext, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ciphertext, _, err := enc.Encrypt(plaintext, decoded.PublicKey(), crand.Reader)
	require.NoError(t, err)

	dec, err := scheme.Decrypter(decoded)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)

	require.True(t, plaintext.Equal(decrypted))
}

func TestRoundTrip_EncryptDecrypt_WithSerialization(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Create and encrypt a plaintext
	ps := pk.PlaintextSpace()
	original, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ciphertext, nonce, err := enc.Encrypt(original, pk, crand.Reader)
	require.NoError(t, err)

	// Serialize plaintext
	plaintextData, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	// Serialize ciphertext
	ciphertextData, err := serde.MarshalCBOR(ciphertext)
	require.NoError(t, err)

	// Serialize nonce
	nonceData, err := serde.MarshalCBOR(nonce)
	require.NoError(t, err)

	// Serialize keys
	skData, err := serde.MarshalCBOR(sk)
	require.NoError(t, err)
	pkData, err := serde.MarshalCBOR(pk)
	require.NoError(t, err)

	// Deserialize everything
	decodedPlaintext, err := serde.UnmarshalCBOR[*paillier.Plaintext](plaintextData)
	require.NoError(t, err)
	decodedCiphertext, err := serde.UnmarshalCBOR[*paillier.Ciphertext](ciphertextData)
	require.NoError(t, err)
	decodedNonce, err := serde.UnmarshalCBOR[*paillier.Nonce](nonceData)
	require.NoError(t, err)
	decodedSk, err := serde.UnmarshalCBOR[*paillier.PrivateKey](skData)
	require.NoError(t, err)
	decodedPk, err := serde.UnmarshalCBOR[*paillier.PublicKey](pkData)
	require.NoError(t, err)

	// Verify plaintexts match
	require.True(t, original.Equal(decodedPlaintext))

	// Decrypt with deserialized key
	dec, err := scheme.Decrypter(decodedSk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(decodedCiphertext)
	require.NoError(t, err)
	require.True(t, decodedPlaintext.Equal(decrypted))

	// Re-encrypt with deserialized nonce and verify equality
	reEncrypted, err := enc.EncryptWithNonce(decodedPlaintext, decodedPk, decodedNonce)
	require.NoError(t, err)
	require.True(t, decodedCiphertext.Equal(reEncrypted))
}

func TestCBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("Plaintext_InvalidData", func(t *testing.T) {
		_, err := serde.UnmarshalCBOR[*paillier.Plaintext]([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("Nonce_InvalidData", func(t *testing.T) {
		_, err := serde.UnmarshalCBOR[*paillier.Nonce]([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("Ciphertext_InvalidData", func(t *testing.T) {
		_, err := serde.UnmarshalCBOR[*paillier.Ciphertext]([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("PublicKey_InvalidData", func(t *testing.T) {
		_, err := serde.UnmarshalCBOR[*paillier.PublicKey]([]byte{0x00})
		require.Error(t, err)
	})

	t.Run("PrivateKey_InvalidData", func(t *testing.T) {
		_, err := serde.UnmarshalCBOR[*paillier.PrivateKey]([]byte{0x00})
		require.Error(t, err)
	})
}

func TestHomomorphicOperations_AfterDeserialization(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()

	// Create two plaintexts
	pt1, err := ps.FromNat(numct.NewNat(100))
	require.NoError(t, err)
	pt2, err := ps.FromNat(numct.NewNat(200))
	require.NoError(t, err)

	// Encrypt both
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
	require.NoError(t, err)
	ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
	require.NoError(t, err)

	// Serialize the ciphertexts
	ct1Data, err := serde.MarshalCBOR(ct1)
	require.NoError(t, err)
	ct2Data, err := serde.MarshalCBOR(ct2)
	require.NoError(t, err)

	// Deserialize
	decodedCt1, err := serde.UnmarshalCBOR[*paillier.Ciphertext](ct1Data)
	require.NoError(t, err)
	decodedCt2, err := serde.UnmarshalCBOR[*paillier.Ciphertext](ct2Data)
	require.NoError(t, err)

	// Perform homomorphic addition on deserialized ciphertexts
	ctSum := decodedCt1.Mul(decodedCt2)

	// Decrypt and verify
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ctSum)
	require.NoError(t, err)

	// Expected result: 100 + 200 = 300
	expected, err := ps.FromNat(numct.NewNat(300))
	require.NoError(t, err)
	require.True(t, expected.Equal(decrypted))
}

func TestSelfEncryption_AfterDeserialization(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	ps := sk.PublicKey().PlaintextSpace()
	plaintext, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)

	// Serialize the private key
	skData, err := serde.MarshalCBOR(sk)
	require.NoError(t, err)

	// Deserialize
	decodedSk, err := serde.UnmarshalCBOR[*paillier.PrivateKey](skData)
	require.NoError(t, err)

	// Use deserialized key for self-encryption
	senc, err := scheme.SelfEncrypter(decodedSk)
	require.NoError(t, err)
	ciphertext, nonce, err := senc.SelfEncrypt(plaintext, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, nonce)

	// Decrypt and verify
	dec, err := scheme.Decrypter(decodedSk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)
	require.True(t, plaintext.Equal(decrypted))
}

func TestPublicKey_DerivedFields_AfterDeserialization(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	_, original, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Access spaces to trigger caching
	_ = original.PlaintextSpace()
	_ = original.NonceSpace()
	_ = original.CiphertextSpace()

	// Serialize
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	// Deserialize
	decoded, err := serde.UnmarshalCBOR[*paillier.PublicKey](data)
	require.NoError(t, err)

	// Verify derived fields work (they should be lazily reconstructed)
	ps := decoded.PlaintextSpace()
	require.NotNil(t, ps)
	require.True(t, original.N().Nat().Equal(decoded.N().Nat()) == ct.True)

	ns := decoded.NonceSpace()
	require.NotNil(t, ns)

	cs := decoded.CiphertextSpace()
	require.NotNil(t, cs)

	// Verify we can create values in each space
	pt, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, pt)

	n, err := ns.Sample(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, n)

	c, err := cs.Sample(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func TestPrivateKey_Precomputation_AfterDeserialization(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	original, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// Serialize
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)

	// Deserialize
	decoded, err := serde.UnmarshalCBOR[*paillier.PrivateKey](data)
	require.NoError(t, err)

	// Verify precomputation happened (by checking we can decrypt)
	ps := decoded.PublicKey().PlaintextSpace()
	plaintext, err := ps.Sample(nil, nil, crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ciphertext, _, err := enc.Encrypt(plaintext, decoded.PublicKey(), crand.Reader)
	require.NoError(t, err)

	// Decryption requires hp and hq to be precomputed
	dec, err := scheme.Decrypter(decoded)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)

	require.True(t, plaintext.Equal(decrypted))
}

func TestZeroValuedPlaintext_CBOR(t *testing.T) {
	t.Parallel()

	// Test that new(paillier.Plaintext) can be serialized/deserialized
	// This is important for the range proof which uses dummy plaintexts
	original := new(paillier.Plaintext)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.Plaintext](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Both should have nil fields
	require.Nil(t, original.Value())
	require.Nil(t, decoded.Value())
	require.Nil(t, original.N())
	require.Nil(t, decoded.N())
}

func TestZeroValuedNonce_CBOR(t *testing.T) {
	t.Parallel()

	// Test that new(paillier.Nonce) can be serialized/deserialized
	original := new(paillier.Nonce)

	// Marshal
	data, err := serde.MarshalCBOR(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	decoded, err := serde.UnmarshalCBOR[*paillier.Nonce](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Both should have nil Value
	require.Nil(t, original.Value())
	require.Nil(t, decoded.Value())
}
