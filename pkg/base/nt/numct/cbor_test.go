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
	originalPos := numct.NewIntFromBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})

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

func TestModulusOddPrime_CBOR(t *testing.T) {
	t.Parallel()

	// Test with various odd prime moduli (note: 2 is excluded as it's even)
	primes := []uint64{
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
		53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
		65537, // Fermat prime F4
	}

	for _, p := range primes {
		t.Run("prime_"+string(rune(p)), func(t *testing.T) {
			// Create original modulus
			n := numct.NewNat(p)
			original, ok := numct.NewModulusOddPrime(n)
			require.True(t, ok == ct.True, "Failed to create modulus for prime %d", p)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.ModulusOddPrime
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.BitLen(), recovered.BitLen())
		})
	}
}

func TestModulusOddPrimeBasic_CBOR(t *testing.T) {
	t.Parallel()

	// Create original modulus
	n := numct.NewNat(97) // prime
	original, ok := numct.NewModulusOddPrime(n)
	require.True(t, ok == ct.True)

	// Get the basic version
	basicOriginal := &original.ModulusOddPrimeBasic

	// Marshal to CBOR
	data, err := basicOriginal.MarshalCBOR()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var recovered numct.ModulusOddPrimeBasic
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Compare values
	require.Equal(t, basicOriginal.Bytes(), recovered.Bytes())
	require.Equal(t, basicOriginal.Big().Uint64(), recovered.Big().Uint64())
}

func TestModulusOdd_CBOR(t *testing.T) {
	t.Parallel()

	// Test with various odd moduli (not necessarily prime)
	oddValues := []uint64{
		3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
		33, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59,
		61, 63, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87,
		89, 91, 93, 95, 97, 99,
	}

	for _, v := range oddValues {
		t.Run("odd_"+string(rune(v)), func(t *testing.T) {
			// Create original modulus
			n := numct.NewNat(v)
			original, ok := numct.NewModulusOdd(n)
			require.True(t, ok == ct.True, "Failed to create modulus for odd value %d", v)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.ModulusOdd
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.BitLen(), recovered.BitLen())
		})
	}
}

func TestModulusOddBasic_CBOR(t *testing.T) {
	t.Parallel()

	// Test with various odd values (not necessarily prime)
	// Note: We use prime values here since ModulusOddPrime is the public way
	// to create these structures
	oddPrimes := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31}

	for _, v := range oddPrimes {
		t.Run("odd_"+string(rune(v)), func(t *testing.T) {
			// Create a ModulusOddPrime and extract its basic component
			n := numct.NewNat(v)
			mod, ok := numct.NewModulusOddPrime(n)
			require.True(t, ok == ct.True)

			// Get the ModulusOddPrimeBasic inside it
			// Then cast to ModulusOddBasic which wraps it
			originalPrimeBasic := &mod.ModulusOddPrimeBasic
			original := &numct.ModulusOddBasic{
				ModulusOddPrimeBasic: *originalPrimeBasic,
			}

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.ModulusOddBasic
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
		})
	}
}

func TestModulusBasic_CBOR(t *testing.T) {
	t.Parallel()

	// Test with various odd prime values
	// Note: ModulusBasic can handle any non-zero value, but we use primes
	// since that's the public way to create the underlying structures
	values := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31}

	for _, v := range values {
		t.Run("value_"+string(rune(v)), func(t *testing.T) {
			// Create a ModulusOddPrime and extract its basic component
			n := numct.NewNat(v)
			mod, ok := numct.NewModulusOddPrime(n)
			require.True(t, ok == ct.True)

			// Build ModulusBasic from ModulusOddPrimeBasic
			originalPrimeBasic := &mod.ModulusOddPrimeBasic
			original := &numct.ModulusBasic{
				ModulusOddBasic: numct.ModulusOddBasic{
					ModulusOddPrimeBasic: *originalPrimeBasic,
				},
			}

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered numct.ModulusBasic
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Bytes(), recovered.Bytes())
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
		})
	}
}

func TestModulus_CBOR_RoundTrip_Operations(t *testing.T) {
	t.Parallel()

	// Create a modulus and test operations after serialization
	n := numct.NewNat(97)
	original, ok := numct.NewModulusOddPrime(n)
	require.True(t, ok == ct.True)

	// Marshal and unmarshal
	data, err := original.MarshalCBOR()
	require.NoError(t, err)

	var recovered numct.ModulusOddPrime
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

func TestModulus_CBOR_Polymorphic(t *testing.T) {
	t.Parallel()

	// Test that we can serialize different modulus types and recover them
	t.Run("interface_serialization", func(t *testing.T) {
		// Create different modulus types
		prime := numct.NewNat(97)
		modPrime, okPrime := numct.NewModulusOddPrime(prime)
		require.True(t, okPrime == ct.True)

		odd := numct.NewNat(15) // 3*5, odd but not prime
		modOdd, okOdd := numct.NewModulusOdd(odd)
		require.True(t, okOdd == ct.True)

		// Test that each can be serialized and deserialized
		testModulusRoundTrip := func(name string, mod numct.Modulus) {
			t.Run(name, func(t *testing.T) {
				// We need type-specific serialization for interface types
				// This is a limitation - interfaces need wrapper types for proper CBOR
				switch m := mod.(type) {
				case *numct.ModulusOddPrime:
					data, err := m.MarshalCBOR()
					require.NoError(t, err)

					var recovered numct.ModulusOddPrime
					err = recovered.UnmarshalCBOR(data)
					require.NoError(t, err)

					require.Equal(t, m.Bytes(), recovered.Bytes())

				case *numct.ModulusOdd:
					data, err := m.MarshalCBOR()
					require.NoError(t, err)

					var recovered numct.ModulusOdd
					err = recovered.UnmarshalCBOR(data)
					require.NoError(t, err)

					require.Equal(t, m.Bytes(), recovered.Bytes())

				default:
					t.Fatalf("Unknown modulus type: %T", mod)
				}
			})
		}

		testModulusRoundTrip("ModulusOddPrime", modPrime)
		testModulusRoundTrip("ModulusOdd", modOdd)
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
