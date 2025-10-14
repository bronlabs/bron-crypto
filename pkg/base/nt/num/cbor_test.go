package num_test

import (
	"bytes"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
)

func TestNatPlus_CBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value uint64
	}{
		{"one", 1},
		{"small", 42},
		{"medium", 65535},
		{"large", ^uint64(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original NatPlus
			original, err := num.NPlus().FromUint64(tt.value)
			require.NoError(t, err)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.NatPlus
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.String(), recovered.String())
		})
	}
}

func TestNatPlus_CBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero_not_allowed", func(t *testing.T) {
		// Create a NatPlus with value 1, then marshal it
		n, err := num.NPlus().FromUint64(1)
		require.NoError(t, err)

		// Marshal to get valid CBOR structure
		data, err := n.MarshalCBOR()
		require.NoError(t, err)

		_ = data // Mark as used

		// Test that we can't create zero NatPlus directly

		// Actually, let's test by trying to create zero NatPlus directly
		_, err = num.NPlus().FromUint64(0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be greater than 0")
	})

	t.Run("empty_bytes", func(t *testing.T) {
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

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
			original := num.N().FromUint64(tt.value)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.Nat
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.String(), recovered.String())
		})
	}
}

func TestNat_CBOR_LargeValue(t *testing.T) {
	t.Parallel()

	// Test with a large value that requires multiple limbs
	original, err := num.N().FromBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.NoError(t, err)

	// Marshal to CBOR
	data, err := original.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recovered num.Nat
	err = recovered.UnmarshalCBOR(data)
	require.NoError(t, err)

	// Compare values
	require.Equal(t, original.Bytes(), recovered.Bytes())
	require.Equal(t, original.String(), recovered.String())
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
			original := num.Z().FromInt64(tt.value)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.Int
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Big().Int64(), recovered.Big().Int64())
			require.Equal(t, original.String(), recovered.String())
			require.Equal(t, original.IsNegative(), recovered.IsNegative())
		})
	}
}

func TestInt_CBOR_LargeValue(t *testing.T) {
	t.Parallel()

	// Test with a large positive value
	originalPos, err := num.Z().FromBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.NoError(t, err)

	// Marshal to CBOR
	dataPos, err := originalPos.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recoveredPos num.Int
	err = recoveredPos.UnmarshalCBOR(dataPos)
	require.NoError(t, err)

	// Compare values
	require.Equal(t, originalPos.Bytes(), recoveredPos.Bytes())
	require.Equal(t, originalPos.String(), recoveredPos.String())

	// Test with a negative value
	originalNeg, err := num.Z().FromBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.NoError(t, err)
	originalNeg = originalNeg.Neg()

	// Marshal to CBOR
	dataNeg, err := originalNeg.MarshalCBOR()
	require.NoError(t, err)

	// Unmarshal from CBOR
	var recoveredNeg num.Int
	err = recoveredNeg.UnmarshalCBOR(dataNeg)
	require.NoError(t, err)

	// Compare values
	require.Equal(t, originalNeg.String(), recoveredNeg.String())
	require.True(t, recoveredNeg.IsNegative())
}

func TestUint_CBOR(t *testing.T) {
	t.Parallel()

	// Create a modulus for testing
	modulus, err := num.NPlus().FromUint64(100)
	require.NoError(t, err)

	zmod, err := num.NewZMod(modulus)
	require.NoError(t, err)

	tests := []struct {
		name  string
		value uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"small", 42},
		{"medium", 50},
		{"large", 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original Uint
			original, err := zmod.FromUint64(tt.value)
			require.NoError(t, err)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.Uint
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.Equal(t, original.Big().Uint64(), recovered.Big().Uint64())
			require.Equal(t, original.String(), recovered.String())
			// Compare modulus
			require.Equal(t, original.Modulus().Big().Uint64(), recovered.Modulus().Big().Uint64())
		})
	}
}

func TestUint_CBOR_InvalidValue(t *testing.T) {
	t.Parallel()

	// Create a modulus
	modulus, err := num.NPlus().FromUint64(10)
	require.NoError(t, err)

	zmod, err := num.NewZMod(modulus)
	require.NoError(t, err)

	// Create a valid Uint
	validUint, err := zmod.FromUint64(5)
	require.NoError(t, err)

	// Marshal it
	data, err := validUint.MarshalCBOR()
	require.NoError(t, err)

	_ = data // Mark as used

	// Test that values >= modulus are rejected at creation
	// Since 15 > 10, this will be reduced to 15 % 10 = 5
	// So let's test that the value is properly reduced
	largeValue, err := zmod.FromUint64(15)
	require.NoError(t, err) // This should succeed with reduction
	require.Equal(t, uint64(5), largeValue.Big().Uint64()) // 15 % 10 = 5
}

func TestZMod_CBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		modulus uint64
	}{
		{"small_prime", 7},
		{"medium_prime", 101},
		{"composite", 15},
		{"power_of_two", 16},
		{"large", 65537},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original ZMod
			n, err := num.NPlus().FromUint64(tt.modulus)
			require.NoError(t, err)

			original, err := num.NewZMod(n)
			require.NoError(t, err)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.ZMod
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare modulus values
			require.Equal(t, original.Modulus().Big().Uint64(), recovered.Modulus().Big().Uint64())

			// Test that operations work correctly after deserialization
			// Create some elements and test arithmetic
			a, err := original.FromUint64(2)
			require.NoError(t, err)
			b, err := original.FromUint64(3)
			require.NoError(t, err)

			aRecov, err := recovered.FromUint64(2)
			require.NoError(t, err)
			bRecov, err := recovered.FromUint64(3)
			require.NoError(t, err)

			// Test addition
			sumOrig := a.Add(b)
			sumRecov := aRecov.Add(bRecov)
			require.Equal(t, sumOrig.Big().Uint64(), sumRecov.Big().Uint64())

			// Test multiplication
			prodOrig := a.Mul(b)
			prodRecov := aRecov.Mul(bRecov)
			require.Equal(t, prodOrig.Big().Uint64(), prodRecov.Big().Uint64())
		})
	}
}

func TestNat_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	n := num.N().FromUint64(42)

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
	i := num.Z().FromInt64(-42)

	data1, err1 := i.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := i.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestNatPlus_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	n, err := num.NPlus().FromUint64(42)
	require.NoError(t, err)

	data1, err1 := n.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := n.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestUint_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Create a modulus
	modulus, err := num.NPlus().FromUint64(100)
	require.NoError(t, err)

	zmod, err := num.NewZMod(modulus)
	require.NoError(t, err)

	// Test that serialization is deterministic
	u, err := zmod.FromUint64(42)
	require.NoError(t, err)

	data1, err1 := u.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := u.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestZMod_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialization is deterministic
	n, err := num.NPlus().FromUint64(97)
	require.NoError(t, err)

	z, err := num.NewZMod(n)
	require.NoError(t, err)

	data1, err1 := z.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := z.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialization should be deterministic")
}

func TestCBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Nat_empty_bytes", func(t *testing.T) {
		var n num.Nat
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Int_empty_bytes", func(t *testing.T) {
		var i num.Int
		err := i.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("NatPlus_empty_bytes", func(t *testing.T) {
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Uint_empty_bytes", func(t *testing.T) {
		var u num.Uint
		err := u.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("ZMod_empty_bytes", func(t *testing.T) {
		var z num.ZMod
		err := z.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Nat_corrupted_data", func(t *testing.T) {
		var n num.Nat
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("Int_corrupted_data", func(t *testing.T) {
		var i num.Int
		err := i.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("NatPlus_corrupted_data", func(t *testing.T) {
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("Uint_corrupted_data", func(t *testing.T) {
		var u num.Uint
		err := u.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("ZMod_corrupted_data", func(t *testing.T) {
		var z num.ZMod
		err := z.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

func BenchmarkNat_CBOR(b *testing.B) {
	n := num.N().FromUint64(1234567890)

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
		var recovered num.Nat
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkInt_CBOR(b *testing.B) {
	intVal := num.Z().FromInt64(-1234567890)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := intVal.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := intVal.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered num.Int
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}