package mina //nolint:testpackage // to test unexported identifiers

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDeterministicVariant(t *testing.T) {
	t.Parallel()

	t.Run("nil private key", func(t *testing.T) {
		t.Parallel()
		v, err := NewDeterministicVariant(TestNet, nil)
		require.Nil(t, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("valid private key", func(t *testing.T) {
		t.Parallel()
		privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		require.NoError(t, err)

		v, err := NewDeterministicVariant(TestNet, privateKey)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.True(t, v.IsDeterministic())
	})
}

func TestNewRandomisedVariant(t *testing.T) {
	t.Parallel()

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		v, err := NewRandomisedVariant(TestNet, nil)
		require.Nil(t, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("valid prng", func(t *testing.T) {
		t.Parallel()
		v, err := NewRandomisedVariant(TestNet, crand.Reader)
		require.NoError(t, err)
		require.NotNil(t, v)
		require.False(t, v.IsDeterministic())
	})
}

func TestVariantType(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	v, err := NewDeterministicVariant(TestNet, privateKey)
	require.NoError(t, err)

	require.Equal(t, VariantType, v.Type())
}

func TestVariantHashFunc(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	v, err := NewDeterministicVariant(TestNet, privateKey)
	require.NoError(t, err)

	hashFn := v.HashFunc()
	require.NotNil(t, hashFn)

	// Create a hash and verify it returns a valid hasher
	h := hashFn()
	require.NotNil(t, h)

	// Poseidon hash expects data length to be a multiple of 32 bytes
	data := make([]byte, 32)
	copy(data, []byte("test"))
	_, err = h.Write(data)
	require.NoError(t, err)
	sum := h.Sum(nil)
	require.NotEmpty(t, sum)
}

func TestFieldTo255Bits(t *testing.T) {
	t.Parallel()

	// Test with a known field element (value 1)
	one := group.BaseField().One()

	bits := fieldTo255Bits(one)
	require.Len(t, bits, 255)
	// For value 1, only the first bit should be set in LSB-first order
	require.True(t, bits[0])
	for i := 1; i < 255; i++ {
		require.False(t, bits[i], "bit %d should be false", i)
	}
}

func TestScalarTo255Bits(t *testing.T) {
	t.Parallel()

	one := sf.One()
	bits := scalarTo255Bits(one)
	require.Len(t, bits, 255)
	// For value 1, only the first bit should be set in LSB-first order
	require.True(t, bits[0])
	for i := 1; i < 255; i++ {
		require.False(t, bits[i], "bit %d should be false", i)
	}
}

// scalarFromUint64 creates a scalar from a uint64 for testing purposes.
func scalarFromUint64(v uint64) *Scalar {
	bytes := make([]byte, 32)
	for i := range 8 {
		bytes[31-i] = byte(v >> (i * 8))
	}
	s, _ := sf.FromBytes(bytes)
	return s
}

func TestBitsToBytes(t *testing.T) {
	t.Parallel()

	t.Run("empty bits", func(t *testing.T) {
		t.Parallel()
		result := bitsToBytes(nil)
		require.Empty(t, result)
	})

	t.Run("single byte", func(t *testing.T) {
		t.Parallel()
		// 8 bits representing 0b11000011 = 195 in LSB-first order
		bits := []bool{true, true, false, false, false, false, true, true}
		result := bitsToBytes(bits)
		require.Len(t, result, 1)
		require.Equal(t, byte(0b11000011), result[0])
	})

	t.Run("partial byte", func(t *testing.T) {
		t.Parallel()
		// 5 bits: 10101 in LSB-first = 0b10101 = 21
		bits := []bool{true, false, true, false, true}
		result := bitsToBytes(bits)
		require.Len(t, result, 1)
		require.Equal(t, byte(0b10101), result[0])
	})

	t.Run("multiple bytes", func(t *testing.T) {
		t.Parallel()
		// 16 bits: byte0=0xFF, byte1=0x00
		bits := make([]bool, 16)
		for i := range 8 {
			bits[i] = true
		}
		result := bitsToBytes(bits)
		require.Len(t, result, 2)
		require.Equal(t, byte(0xFF), result[0])
		require.Equal(t, byte(0x00), result[1])
	})
}

func TestComputeNonceCommitment(t *testing.T) {
	t.Parallel()

	t.Run("deterministic mode without message", func(t *testing.T) {
		t.Parallel()
		privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		require.NoError(t, err)

		v, err := NewDeterministicVariant(TestNet, privateKey)
		require.NoError(t, err)

		// Should fail because msg is nil
		R, k, err := v.ComputeNonceCommitment()
		require.Nil(t, R)
		require.Nil(t, k)
		require.Error(t, err)
	})

	t.Run("deterministic mode with message", func(t *testing.T) {
		t.Parallel()
		privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
		require.NoError(t, err)

		v, err := NewDeterministicVariant(TestNet, privateKey)
		require.NoError(t, err)

		// Set message
		msg := new(ROInput).Init()
		msg.AddString("test message")
		v.msg = msg

		R, k, err := v.ComputeNonceCommitment()
		require.NoError(t, err)
		require.NotNil(t, R)
		require.NotNil(t, k)

		// Verify R has even y-coordinate
		ry, err := R.AffineY()
		require.NoError(t, err)
		require.False(t, ry.IsOdd(), "R should have even y-coordinate")
	})

	t.Run("randomised mode", func(t *testing.T) {
		t.Parallel()
		v, err := NewRandomisedVariant(TestNet, crand.Reader)
		require.NoError(t, err)

		R, k, err := v.ComputeNonceCommitment()
		require.NoError(t, err)
		require.NotNil(t, R)
		require.NotNil(t, k)

		// Verify R has even y-coordinate
		ry, err := R.AffineY()
		require.NoError(t, err)
		require.False(t, ry.IsOdd(), "R should have even y-coordinate")
	})
}

func TestComputeChallenge(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	v, err := NewDeterministicVariant(TestNet, privateKey)
	require.NoError(t, err)

	publicKey := privateKey.PublicKey()
	R := group.ScalarBaseMul(sf.One())
	msg := new(ROInput).Init()
	msg.AddString("test")

	t.Run("nil nonce commitment", func(t *testing.T) {
		t.Parallel()
		e, err := v.ComputeChallenge(nil, publicKey.V, msg)
		require.Nil(t, e)
		require.Error(t, err)
	})

	t.Run("nil public key", func(t *testing.T) {
		t.Parallel()
		e, err := v.ComputeChallenge(R, nil, msg)
		require.Nil(t, e)
		require.Error(t, err)
	})

	t.Run("nil message", func(t *testing.T) {
		t.Parallel()
		e, err := v.ComputeChallenge(R, publicKey.V, nil)
		require.Nil(t, e)
		require.Error(t, err)
	})

	t.Run("valid inputs", func(t *testing.T) {
		t.Parallel()
		e, err := v.ComputeChallenge(R, publicKey.V, msg)
		require.NoError(t, err)
		require.NotNil(t, e)
		require.False(t, e.IsZero())
	})
}

func TestComputeResponse(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	v, err := NewDeterministicVariant(TestNet, privateKey)
	require.NoError(t, err)

	skValue := privateKey.V
	nonce := sf.One()
	challenge := scalarFromUint64(42)

	t.Run("nil private key value", func(t *testing.T) {
		t.Parallel()
		s, err := v.ComputeResponse(nil, nonce, challenge)
		require.Nil(t, s)
		require.Error(t, err)
	})

	t.Run("nil nonce", func(t *testing.T) {
		t.Parallel()
		s, err := v.ComputeResponse(skValue, nil, challenge)
		require.Nil(t, s)
		require.Error(t, err)
	})

	t.Run("nil challenge", func(t *testing.T) {
		t.Parallel()
		s, err := v.ComputeResponse(skValue, nonce, nil)
		require.Nil(t, s)
		require.Error(t, err)
	})

	t.Run("valid inputs", func(t *testing.T) {
		t.Parallel()
		s, err := v.ComputeResponse(skValue, nonce, challenge)
		require.NoError(t, err)
		require.NotNil(t, s)
		// s = k + e*x
		expected := nonce.Add(challenge.Mul(skValue))
		require.True(t, s.Equal(expected))
	})
}

func TestSerializeSignature(t *testing.T) {
	t.Parallel()

	t.Run("nil signature", func(t *testing.T) {
		t.Parallel()
		data, err := SerializeSignature(nil)
		require.Nil(t, data)
		require.Error(t, err)
	})

	t.Run("nil signature via variant method", func(t *testing.T) {
		t.Parallel()
		v, err := NewRandomisedVariant(TestNet, crand.Reader)
		require.NoError(t, err)

		data, err := v.SerializeSignature(nil)
		require.Nil(t, data)
		require.Error(t, err)
	})

	t.Run("valid signature via variant method", func(t *testing.T) {
		t.Parallel()
		scheme, err := NewRandomisedScheme(TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, _, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(ROInput).Init()
		msg.AddString("test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		v, err := NewRandomisedVariant(TestNet, crand.Reader)
		require.NoError(t, err)

		data, err := v.SerializeSignature(sig)
		require.NoError(t, err)
		require.Len(t, data, SignatureSize)
	})

	t.Run("valid signature", func(t *testing.T) {
		t.Parallel()
		// Create a valid signature
		scheme, err := NewRandomisedScheme(TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, _, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(ROInput).Init()
		msg.AddString("test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		data, err := SerializeSignature(sig)
		require.NoError(t, err)
		require.Len(t, data, SignatureSize)
	})
}

func TestDeserializeSignature(t *testing.T) {
	t.Parallel()

	t.Run("wrong size", func(t *testing.T) {
		t.Parallel()
		sig, err := DeserializeSignature(make([]byte, 32))
		require.Nil(t, sig)
		require.Error(t, err)
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()
		// Create a valid signature
		scheme, err := NewRandomisedScheme(TestNet, crand.Reader)
		require.NoError(t, err)

		kg, err := scheme.Keygen()
		require.NoError(t, err)
		privateKey, publicKey, err := kg.Generate(crand.Reader)
		require.NoError(t, err)

		signer, err := scheme.Signer(privateKey)
		require.NoError(t, err)

		msg := new(ROInput).Init()
		msg.AddString("test")

		sig, err := signer.Sign(msg)
		require.NoError(t, err)

		// Serialise
		data, err := SerializeSignature(sig)
		require.NoError(t, err)

		// Deserialize
		sig2, err := DeserializeSignature(data)
		require.NoError(t, err)

		// Verify they match
		rx1, _ := sig.R.AffineX()
		rx2, _ := sig2.R.AffineX()
		require.True(t, rx1.Equal(rx2))
		require.True(t, sig.S.Equal(sig2.S))

		// Verify the deserialized signature is valid
		verifier, err := scheme.Verifier()
		require.NoError(t, err)
		err = verifier.Verify(sig2, publicKey, msg)
		require.NoError(t, err)
	})
}

// TestCorrectAdditiveSecretShareParity tests the MPC parity correction for secret shares.
func TestCorrectAdditiveSecretShareParity(t *testing.T) {
	t.Parallel()

	v, err := NewRandomisedVariant(TestNet, crand.Reader)
	require.NoError(t, err)

	// This should be a no-op for Mina
	result, err := v.CorrectAdditiveSecretShareParity(nil, nil)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestCorrectPartialNonceParity tests the MPC parity correction for partial nonces.
func TestCorrectPartialNonceParity(t *testing.T) {
	t.Parallel()

	v, err := NewRandomisedVariant(TestNet, crand.Reader)
	require.NoError(t, err)

	t.Run("nil nonce commitment", func(t *testing.T) {
		t.Parallel()
		R, k, err := v.CorrectPartialNonceParity(nil, sf.One())
		require.Nil(t, R)
		require.Nil(t, k)
		require.Error(t, err)
	})

	t.Run("nil local nonce", func(t *testing.T) {
		t.Parallel()
		aggR := group.ScalarBaseMul(sf.One())
		R, k, err := v.CorrectPartialNonceParity(aggR, nil)
		require.Nil(t, R)
		require.Nil(t, k)
		require.Error(t, err)
	})

	t.Run("even y nonce commitment", func(t *testing.T) {
		t.Parallel()
		// Create a nonce commitment with even y
		localK := scalarFromUint64(42)
		localR := group.ScalarBaseMul(localK)

		// Find a k that gives even y
		ry, _ := localR.AffineY()
		if ry.IsOdd() {
			localK = localK.Neg()
			localR = group.ScalarBaseMul(localK)
		}

		correctedR, correctedK, err := v.CorrectPartialNonceParity(localR, localK)
		require.NoError(t, err)
		require.NotNil(t, correctedR)
		require.NotNil(t, correctedK)

		// Should not be negated
		require.True(t, localK.Equal(correctedK))
	})

	t.Run("odd y nonce commitment", func(t *testing.T) {
		t.Parallel()
		// Create a nonce commitment with odd y
		localK := scalarFromUint64(42)
		localR := group.ScalarBaseMul(localK)

		// Find a k that gives odd y
		ry, _ := localR.AffineY()
		if !ry.IsOdd() {
			localK = localK.Neg()
			localR = group.ScalarBaseMul(localK)
		}

		correctedR, correctedK, err := v.CorrectPartialNonceParity(localR, localK)
		require.NoError(t, err)
		require.NotNil(t, correctedR)
		require.NotNil(t, correctedK)

		// Should be negated
		require.True(t, localK.Neg().Equal(correctedK))
	})
}

// badReader is an io.Reader that always fails.
type badReader struct{}

func (badReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// TestRandomisedNonceCommitmentWithBadReader tests nonce commitment generation with a failing PRNG.
func TestRandomisedNonceCommitmentWithBadReader(t *testing.T) {
	t.Parallel()

	v, err := NewRandomisedVariant(TestNet, badReader{})
	require.NoError(t, err)

	R, k, err := v.ComputeNonceCommitment()
	require.Nil(t, R)
	require.Nil(t, k)
	require.Error(t, err)
}

// TestDeterministicNonceIsConsistent verifies that the same message produces the same nonce.
func TestDeterministicNonceIsConsistent(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	msg := new(ROInput).Init()
	msg.AddString("consistent nonce test")

	var nonces []*Scalar
	for range 3 {
		v, err := NewDeterministicVariant(TestNet, privateKey)
		require.NoError(t, err)
		v.msg = msg

		R, k, err := v.ComputeNonceCommitment()
		require.NoError(t, err)
		require.NotNil(t, R)
		nonces = append(nonces, k)
	}

	// All nonces should be equal
	for i := 1; i < len(nonces); i++ {
		require.True(t, nonces[0].Equal(nonces[i]), "nonces should be consistent")
	}
}

// TestDifferentMessagesProduceDifferentNonces verifies nonce uniqueness.
func TestDifferentMessagesProduceDifferentNonces(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	messages := []string{"message1", "message2", "message3"}
	var nonces []*Scalar

	for _, m := range messages {
		v, err := NewDeterministicVariant(TestNet, privateKey)
		require.NoError(t, err)

		msg := new(ROInput).Init()
		msg.AddString(m)
		v.msg = msg

		_, k, err := v.ComputeNonceCommitment()
		require.NoError(t, err)
		nonces = append(nonces, k)
	}

	// All nonces should be different
	for i := range nonces {
		for j := i + 1; j < len(nonces); j++ {
			// Note: nonces might be negated due to even y correction,
			// so we check that neither k nor -k matches
			kNeg := nonces[j].Neg()
			require.False(t, nonces[i].Equal(nonces[j]) || nonces[i].Equal(kNeg),
				"different messages should produce different nonces")
		}
	}
}

// TestDifferentNetworksProduceDifferentNonces verifies network separation.
func TestDifferentNetworksProduceDifferentNonces(t *testing.T) {
	t.Parallel()

	privateKey, err := DecodePrivateKey("EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw")
	require.NoError(t, err)

	msg := new(ROInput).Init()
	msg.AddString("network separation test")

	networks := []NetworkID{TestNet, MainNet}
	var nonces []*Scalar

	for _, nid := range networks {
		v, err := NewDeterministicVariant(nid, privateKey)
		require.NoError(t, err)
		v.msg = msg

		_, k, err := v.ComputeNonceCommitment()
		require.NoError(t, err)
		nonces = append(nonces, k)
	}

	// Nonces should be different for different networks
	kNeg := nonces[1].Neg()
	require.False(t, nonces[0].Equal(nonces[1]) || nonces[0].Equal(kNeg),
		"different networks should produce different nonces")
}

// TestReversedBytes tests the reversedBytes helper function.
func TestReversedBytes(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		result := reversedBytes(nil)
		require.Empty(t, result)
	})

	t.Run("single byte", func(t *testing.T) {
		t.Parallel()
		result := reversedBytes([]byte{0x42})
		require.Equal(t, []byte{0x42}, result)
	})

	t.Run("multiple bytes", func(t *testing.T) {
		t.Parallel()
		result := reversedBytes([]byte{0x01, 0x02, 0x03, 0x04})
		require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, result)
	})

	t.Run("does not modify original", func(t *testing.T) {
		t.Parallel()
		original := []byte{0x01, 0x02, 0x03}
		originalCopy := bytes.Clone(original)
		_ = reversedBytes(original)
		require.Equal(t, originalCopy, original)
	})
}
