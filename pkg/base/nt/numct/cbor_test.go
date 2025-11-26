//go:build !purego && !nobignum

package numct_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/stretchr/testify/require"
)

func TestNat_CBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"small", 42},
		{"medium", 65535},
		{"large", ^uint64(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original Nat
			original := numct.NewNat(tt.value)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.Nat
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.True(t, original.Equal(&recovered) == ct.True)
			require.Equal(t, original.Uint64(), recovered.Uint64())
		})
	}
}

func TestNat_CBOR_LargeValue(t *testing.T) {
	t.Parallel()

	// Test with a large value that requires multiple limbs
	original := numct.NewNatFromBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})

	// Marshal to CBOR
	data, err := original.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recovered numct.Nat
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Compare values
	require.True(t, original.Equal(&recovered) == ct.True)
	require.Equal(t, original.Bytes(), recovered.Bytes())
}

func TestInt_CBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value int64
	}{
		{"zero", 0},
		{"positive_one", 1},
		{"negative_one", -1},
		{"positive_small", 42},
		{"negative_small", -42},
		{"positive_large", 2147483647},
		{"negative_large", -2147483648},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original Int
			original := numct.NewInt(tt.value)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.Int
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.True(t, original.Equal(&recovered) == ct.True)
			require.Equal(t, original.Big().Int64(), recovered.Big().Int64())
			require.Equal(t, original.IsNegative(), recovered.IsNegative())
		})
	}
}

func TestInt_CBOR_LargeValue(t *testing.T) {
	t.Parallel()

	// Test with a large positive value
	// Sign-magnitude format: first byte is sign (0=positive), rest is magnitude
	originalPos := numct.NewIntFromBytes([]byte{
		0x00, // sign byte = 0 (positive)
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.Equal(t, ct.False, originalPos.IsNegative())

	// Marshal to CBOR
	dataPos, err := originalPos.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recoveredPos numct.Int
	err = recoveredPos.UnmarshalCBOR(dataPos)
	require.NoError(t, err)

	// Compare values
	require.True(t, originalPos.Equal(&recoveredPos) == ct.True)
	require.Equal(t, originalPos.Bytes(), recoveredPos.Bytes())

	// Test with a negative value
	originalNeg := originalPos.Clone()
	originalNeg.Neg(originalNeg)
	require.Equal(t, ct.True, originalNeg.IsNegative())

	// Marshal to CBOR
	dataNeg, err := originalNeg.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recoveredNeg numct.Int
	err = recoveredNeg.UnmarshalCBOR(dataNeg)
	require.NoError(t, err)

	// Compare values
	require.True(t, originalNeg.Equal(&recoveredNeg) == ct.True)
	require.True(t, recoveredNeg.IsNegative() == ct.True)
}

func TestModulus_CBOR(t *testing.T) {
	t.Parallel()

	// Test with various moduli values
	values := []uint64{
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
		53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
		65537, // Fermat prime F4
	}

	for _, v := range values {
		t.Run("value_"+string(rune(v)), func(t *testing.T) {
			// Create original modulus
			n := numct.NewNat(v)
			original, ok := numct.NewModulus(n)
			require.True(t, ok == ct.True, "Failed to create modulus for value %d", v)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.Modulus
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.BitLen(), recovered.BitLen())
		})
	}
}

func TestModulus_CBOR_EvenModulus(t *testing.T) {
	t.Parallel()

	// Test with even moduli
	evenValues := []uint64{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 100, 1000}

	for _, v := range evenValues {
		t.Run("even_value_"+string(rune(v)), func(t *testing.T) {
			// Create original modulus
			n := numct.NewNat(v)
			original, ok := numct.NewModulus(n)
			require.True(t, ok == ct.True, "Failed to create modulus for even value %d", v)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.Modulus
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.BitLen(), recovered.BitLen())
		})
	}
}

func TestModulus_CBOR_RoundTrip_Operations(t *testing.T) {
	t.Parallel()

	// Create a modulus and test operations after serialization
	n := numct.NewNat(97)
	original, ok := numct.NewModulus(n)
	require.True(t, ok == ct.True)

	// Marshal and unmarshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)

	var recovered numct.Modulus
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Test operations work correctly after deserialization
	a := numct.NewNat(42)
	b := numct.NewNat(13)

	// Test ModAdd
	var sumOrig, sumRecov numct.Nat
	original.ModAdd(&sumOrig, a, b)
	recovered.ModAdd(&sumRecov, a, b)
	require.True(t, sumOrig.Equal(&sumRecov) == ct.True)

	// Test ModMul
	var prodOrig, prodRecov numct.Nat
	original.ModMul(&prodOrig, a, b)
	recovered.ModMul(&prodRecov, a, b)
	require.True(t, prodOrig.Equal(&prodRecov) == ct.True)

	// Test ModInv
	var invOrig, invRecov numct.Nat
	okOrig := original.ModInv(&invOrig, a)
	okRecov := recovered.ModInv(&invRecov, a)
	require.Equal(t, okOrig, okRecov)
	require.True(t, invOrig.Equal(&invRecov) == ct.True)

	// Test ModExp
	exp := numct.NewNat(3)
	var expOrig, expRecov numct.Nat
	original.ModExp(&expOrig, a, exp)
	recovered.ModExp(&expRecov, a, exp)
	require.True(t, expOrig.Equal(&expRecov) == ct.True)
}

func TestNat_CBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty_bytes", func(t *testing.T) {
		// Test unmarshaling invalid data
		var n numct.Nat
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		// Test unmarshaling corrupted CBOR data
		var n numct.Nat
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("nil_handling", func(t *testing.T) {
		// Test that nil values are handled properly
		var n *numct.Nat
		require.Panics(t, func() {
			_, _ = n.MarshalCBOR()
		})
	})
}

func TestInt_CBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty_bytes", func(t *testing.T) {
		// Test unmarshaling invalid data
		var i numct.Int
		err := i.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		// Test unmarshaling corrupted CBOR data
		var i numct.Int
		err := i.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

func TestModulus_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("empty_bytes", func(t *testing.T) {
		var m numct.Modulus
		err := m.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		var m numct.Modulus
		err := m.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("zero_modulus", func(t *testing.T) {
		// Creating a modulus with zero should fail
		zero := numct.NewNat(0)
		_, ok := numct.NewModulus(zero)
		require.Equal(t, ct.False, ok, "Should not be able to create modulus from zero")
	})
}

func TestNat_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	n := numct.NewNat(42)

	data1, err1 := n.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := n.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestInt_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	i := numct.NewInt(-42)

	data1, err1 := i.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := i.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestModulus_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	n := numct.NewNat(97)
	m, _ := numct.NewModulus(n)

	data1, err1 := m.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := m.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func BenchmarkNat_CBOR(b *testing.B) {
	n := numct.NewNat(1234567890)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := n.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := n.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered numct.Nat
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkModulus_CBOR(b *testing.B) {
	n := numct.NewNat(65537)
	m, _ := numct.NewModulus(n)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := m.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := m.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered numct.Modulus
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
