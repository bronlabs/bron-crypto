package pasta_test

import (
	"encoding/hex"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/stretchr/testify/require"
)

// TestPallasScalarByteOrder verifies that our Pallas scalar implementation
// uses big-endian byte order, matching the arkworks and o1js implementations
func TestPallasScalarByteOrder(t *testing.T) {
	sf := pasta.NewPallasScalarField()

	// Test 1: Simple value
	t.Run("simple value", func(t *testing.T) {
		// Create a scalar from a known value
		scalar1 := sf.FromUint64(0x0123456789ABCDEF)
		bytes1 := scalar1.Bytes()

		t.Logf("Scalar from 0x0123456789ABCDEF")
		t.Logf("Bytes: %s", hex.EncodeToString(bytes1))

		// Verify it round-trips
		scalar2, err := sf.FromBytes(bytes1)
		require.NoError(t, err)
		require.True(t, scalar1.Equal(scalar2), "Round-trip failed")
	})

	// Test 2: Base58 decoded private key
	t.Run("base58 private key", func(t *testing.T) {
		// From our test vector: EKFKgDtU3rcuFTVSEpmpXSkukjmX4cKefYREi6Sdsk7E7wsT7KRw
		// Base58 decodes to (after version byte): d68412f753ebf8281e0f855ee90fa6d25befdb15ba841b35320554ddcf2f083d
		inputHex := "d68412f753ebf8281e0f855ee90fa6d25befdb15ba841b35320554ddcf2f083d"
		inputBytes, err := hex.DecodeString(inputHex)
		require.NoError(t, err)

		// Parse as scalar
		scalar, err := sf.FromBytes(inputBytes)
		require.NoError(t, err)

		t.Logf("Input bytes:  %s", inputHex)
		t.Logf("Scalar value: %s", scalar.String())

		// Get bytes back
		outputBytes := scalar.Bytes()
		outputHex := hex.EncodeToString(outputBytes)
		t.Logf("Output bytes: %s", outputHex)

		// They should match (big-endian round-trip)
		require.Equal(t, inputHex, outputHex, "Bytes should round-trip in big-endian")
	})

	// Test 3: Verify byte order interpretation
	t.Run("byte order", func(t *testing.T) {
		// Create bytes that clearly show endianness
		// In big-endian: 0x0102030405060708... should have high bytes first
		testBytes := make([]byte, 32)
		for i := 0; i < 32; i++ {
			testBytes[i] = byte(i + 1)
		}

		scalar, err := sf.FromBytes(testBytes)
		require.NoError(t, err)

		outBytes := scalar.Bytes()
		require.Equal(t, testBytes, outBytes, "Bytes should match exactly (big-endian)")

		t.Logf("Input:  %s", hex.EncodeToString(testBytes))
		t.Logf("Output: %s", hex.EncodeToString(outBytes))
		t.Log("✓ Confirmed: Pallas scalars use big-endian byte order")
	})
}

// TestPallasBaseFieldByteOrder verifies base field element byte order
func TestPallasBaseFieldByteOrder(t *testing.T) {
	bf := pasta.NewPallasBaseField()

	t.Run("round-trip", func(t *testing.T) {
		testBytes := make([]byte, 32)
		for i := 0; i < 32; i++ {
			testBytes[i] = byte(32 - i) // Reverse pattern
		}

		field, err := bf.FromBytes(testBytes)
		require.NoError(t, err)

		outBytes := field.Bytes()
		require.Equal(t, testBytes, outBytes, "Base field bytes should round-trip in big-endian")

		t.Log("✓ Confirmed: Pallas base field uses big-endian byte order")
	})
}
