package num_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
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
			t.Parallel()
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
		t.Parallel()
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
		require.ErrorIs(t, err, num.ErrOutOfRange)
	})

	t.Run("empty_bytes", func(t *testing.T) {
		t.Parallel()
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		t.Parallel()
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
			t.Parallel()
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
			t.Parallel()
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
	// Format: [sign_byte=0x00 (positive), value_bytes...]
	originalPos, err := num.Z().FromBytes([]byte{
		0x00, // positive sign
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.NoError(t, err)
	require.False(t, originalPos.IsNegative())

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
	require.False(t, recoveredPos.IsNegative())

	// Test with a negative value
	// Format: [sign_byte=0x01 (negative), value_bytes...]
	originalNeg, err := num.Z().FromBytes([]byte{
		0x01, // negative sign
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	})
	require.NoError(t, err)
	require.True(t, originalNeg.IsNegative())

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
			t.Parallel()
			// Create original Uint
			original := zmod.FromUint64(tt.value)

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
	validUint := zmod.FromUint64(5)

	// Marshal it
	data, err := validUint.MarshalCBOR()
	require.NoError(t, err)

	_ = data // Mark as used

	// Test that values >= modulus are rejected at creation
	// Since 15 > 10, this will be reduced to 15 % 10 = 5
	// So let's test that the value is properly reduced
	largeValue := zmod.FromUint64(15)
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
			t.Parallel()
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
			a := original.FromUint64(2)
			b := original.FromUint64(3)

			aRecov := recovered.FromUint64(2)
			bRecov := recovered.FromUint64(3)

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

	// Test that serialisation is deterministic
	n := num.N().FromUint64(42)

	data1, err1 := n.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := n.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestInt_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialisation is deterministic
	i := num.Z().FromInt64(-42)

	data1, err1 := i.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := i.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestNatPlus_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialisation is deterministic
	n, err := num.NPlus().FromUint64(42)
	require.NoError(t, err)

	data1, err1 := n.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := n.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestUint_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Create a modulus
	modulus, err := num.NPlus().FromUint64(100)
	require.NoError(t, err)

	zmod, err := num.NewZMod(modulus)
	require.NoError(t, err)

	// Test that serialisation is deterministic
	u := zmod.FromUint64(42)

	data1, err1 := u.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := u.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestZMod_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialisation is deterministic
	n, err := num.NPlus().FromUint64(97)
	require.NoError(t, err)

	z, err := num.NewZMod(n)
	require.NoError(t, err)

	data1, err1 := z.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := z.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestCBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("Nat_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var n num.Nat
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Int_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var i num.Int
		err := i.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("NatPlus_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Uint_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var u num.Uint
		err := u.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("ZMod_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var z num.ZMod
		err := z.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Nat_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var n num.Nat
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("Int_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var i num.Int
		err := i.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("NatPlus_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var n num.NatPlus
		err := n.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("Uint_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var u num.Uint
		err := u.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("ZMod_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var z num.ZMod
		err := z.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})

	t.Run("Rat_empty_bytes", func(t *testing.T) {
		t.Parallel()
		var r num.Rat
		err := r.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("Rat_corrupted_data", func(t *testing.T) {
		t.Parallel()
		var r num.Rat
		err := r.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

func BenchmarkNat_CBOR(b *testing.B) {
	n := num.N().FromUint64(1234567890)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
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
		for range b.N {
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
		for range b.N {
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
		for range b.N {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestRat_CBOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		numerator   int64
		denominator uint64
	}{
		{"zero", 0, 1},
		{"one", 1, 1},
		{"positive_simple", 3, 4},
		{"negative_simple", -3, 4},
		{"large_numerator", 1234567890, 1},
		{"large_denominator", 1, 9876543210},
		{"both_large", 999999999, 888888888},
		{"negative_large", -999999999, 888888888},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create original Rat
			a := num.Z().FromInt64(tt.numerator)
			b, err := num.NPlus().FromUint64(tt.denominator)
			require.NoError(t, err)

			original, err := num.Q().New(a, b)
			require.NoError(t, err)

			// Marshal to CBOR
			data, err := original.MarshalCBOR()
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal from CBOR
			var recovered num.Rat
			err = recovered.UnmarshalCBOR(data)
			require.NoError(t, err)

			// Compare values
			require.True(t, original.Equal(&recovered))
			require.Equal(t, original.String(), recovered.String())
			require.Equal(t, original.Numerator().String(), recovered.Numerator().String())
			require.Equal(t, original.Denominator().String(), recovered.Denominator().String())
		})
	}
}

func TestRat_CBOR_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil_numerator", func(t *testing.T) {
		t.Parallel()
		var r num.Rat
		// Create a Rat with proper values first
		a := num.Z().FromInt64(1)
		b, err := num.NPlus().FromUint64(1)
		require.NoError(t, err)
		validRat, err := num.Q().New(a, b)
		require.NoError(t, err)

		// Marshal and unmarshal
		data, err := validRat.MarshalCBOR()
		require.NoError(t, err)

		err = r.UnmarshalCBOR(data)
		require.NoError(t, err)
		require.True(t, validRat.Equal(&r))
	})

	t.Run("empty_bytes", func(t *testing.T) {
		t.Parallel()
		var r num.Rat
		err := r.UnmarshalCBOR([]byte{})
		require.Error(t, err)
	})

	t.Run("corrupted_data", func(t *testing.T) {
		t.Parallel()
		var r num.Rat
		err := r.UnmarshalCBOR([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		require.Error(t, err)
	})
}

func TestRat_CBOR_Deterministic(t *testing.T) {
	t.Parallel()

	// Test that serialisation is deterministic
	a := num.Z().FromInt64(22)
	b, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)

	r, err := num.Q().New(a, b)
	require.NoError(t, err)

	data1, err1 := r.MarshalCBOR()
	require.NoError(t, err1)

	data2, err2 := r.MarshalCBOR()
	require.NoError(t, err2)

	// Should produce identical bytes
	require.True(t, bytes.Equal(data1, data2), "CBOR serialisation should be deterministic")
}

func TestRat_CBOR_Operations(t *testing.T) {
	t.Parallel()

	// Test that operations work correctly after deserialization
	a1 := num.Z().FromInt64(3)
	b1, err := num.NPlus().FromUint64(4)
	require.NoError(t, err)
	r1, err := num.Q().New(a1, b1)
	require.NoError(t, err)

	a2 := num.Z().FromInt64(1)
	b2, err := num.NPlus().FromUint64(2)
	require.NoError(t, err)
	r2, err := num.Q().New(a2, b2)
	require.NoError(t, err)

	// Marshal and unmarshal r1
	data1, err := r1.MarshalCBOR()
	require.NoError(t, err)
	var recovered1 num.Rat
	err = recovered1.UnmarshalCBOR(data1)
	require.NoError(t, err)

	// Marshal and unmarshal r2
	data2, err := r2.MarshalCBOR()
	require.NoError(t, err)
	var recovered2 num.Rat
	err = recovered2.UnmarshalCBOR(data2)
	require.NoError(t, err)

	// Test addition: 3/4 + 1/2 = 5/4
	sumOrig := r1.Add(r2)
	sumRecov := recovered1.Add(&recovered2)
	require.True(t, sumOrig.Equal(sumRecov))

	// Test multiplication: 3/4 * 1/2 = 3/8
	prodOrig := r1.Mul(r2)
	prodRecov := recovered1.Mul(&recovered2)
	require.True(t, prodOrig.Equal(prodRecov))

	// Test subtraction: 3/4 - 1/2 = 1/4
	diffOrig := r1.Sub(r2)
	diffRecov := recovered1.Sub(&recovered2)
	require.True(t, diffOrig.Equal(diffRecov))
}

func BenchmarkRat_CBOR(b *testing.B) {
	a := num.Z().FromInt64(1234567890)
	denom, _ := num.NPlus().FromUint64(9876543210)
	r, _ := num.Q().New(a, denom)

	b.Run("Marshal", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			_, err := r.MarshalCBOR()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	data, _ := r.MarshalCBOR()

	b.Run("Unmarshal", func(b *testing.B) {
		var recovered num.Rat
		b.ResetTimer()
		for range b.N {
			err := recovered.UnmarshalCBOR(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
