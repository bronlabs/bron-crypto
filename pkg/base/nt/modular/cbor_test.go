package modular_test

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

func TestSimpleModulus_CBOR(t *testing.T) {
	t.Parallel()

	// Create a modulus n = 143 = 11 * 13
	n := numct.NewNat(143)
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)

	// Create SimpleModulus
	simple, ok2 := modular.NewSimple(m)
	require.Equal(t, ct.True, ok2)
	require.NotNil(t, simple)

	// Marshal to CBOR
	data, err := cbor.Marshal(simple)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var decoded modular.SimpleModulus
	err = cbor.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify the modulus matches
	require.True(t, simple.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test that operations work on decoded value
	a := numct.NewNat(5)
	b := numct.NewNat(7)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	simple.ModMul(out1, a, b)
	decoded.ModMul(out2, a, b)

	require.True(t, out1.Equal(out2) == ct.True, "ModMul results should match")
}

func TestOddPrimeFactors_CBOR(t *testing.T) {
	t.Parallel()

	// Create OddPrimeFactors with p=11, q=13
	p := numct.NewNat(11)
	q := numct.NewNat(13)

	original, ok := modular.NewOddPrimeFactors(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, original)

	// Marshal to CBOR
	data, err := cbor.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var decoded modular.OddPrimeFactors
	err = cbor.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify the modulus matches (n = p*q = 143)
	require.True(t, original.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test that operations work on decoded value
	a := numct.NewNat(5)
	b := numct.NewNat(7)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	original.ModMul(out1, a, b)
	decoded.ModMul(out2, a, b)

	require.True(t, out1.Equal(out2) == ct.True, "ModMul results should match")

	// Test ModExp
	base := numct.NewNat(2)
	exp := numct.NewNat(10)
	out1 = numct.NewNat(0)
	out2 = numct.NewNat(0)

	original.ModExp(out1, base, exp)
	decoded.ModExp(out2, base, exp)

	require.True(t, out1.Equal(out2) == ct.True, "ModExp results should match")
}

func TestOddPrimeSquareFactors_CBOR(t *testing.T) {
	t.Parallel()

	// Create OddPrimeSquareFactors with p=7, q=11
	p := numct.NewNat(7)
	q := numct.NewNat(11)

	original, ok := modular.NewOddPrimeSquareFactors(p, q)
	require.Equal(t, ct.True, ok)
	require.NotNil(t, original)

	// Marshal to CBOR
	data, err := cbor.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal from CBOR
	var decoded modular.OddPrimeSquareFactors
	err = cbor.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify the modulus matches (n^2 = (p*q)^2 = 77^2 = 5929)
	require.True(t, original.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test that operations work on decoded value
	a := numct.NewNat(100)
	b := numct.NewNat(200)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	original.ModMul(out1, a, b)
	decoded.ModMul(out2, a, b)

	require.True(t, out1.Equal(out2) == ct.True, "ModMul results should match")

	// Test ModExp
	base := numct.NewNat(5)
	exp := numct.NewNat(10)
	out1 = numct.NewNat(0)
	out2 = numct.NewNat(0)

	original.ModExp(out1, base, exp)
	decoded.ModExp(out2, base, exp)

	require.True(t, out1.Equal(out2) == ct.True, "ModExp results should match")
}

func TestArithmetic_InterfaceSerialization_SimpleModulus(t *testing.T) {
	t.Parallel()

	// Create a SimpleModulus
	n := numct.NewNat(143)
	m, ok := numct.NewModulus(n)
	require.Equal(t, ct.True, ok)

	original, ok2 := modular.NewSimple(m)
	require.Equal(t, ct.True, ok2)

	// Test serialising through the Arithmetic interface
	var arith modular.Arithmetic = original

	// Marshal using serde which handles interface serialisation
	data, err := serde.MarshalCBOR(arith)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal back to Arithmetic interface
	decoded, err := serde.UnmarshalCBOR[modular.Arithmetic](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify it's a SimpleModulus
	decodedSimple, okType := decoded.(*modular.SimpleModulus)
	require.True(t, okType, "decoded should be *SimpleModulus")
	require.NotNil(t, decodedSimple)

	// Verify the modulus matches
	require.True(t, original.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test operations
	a := numct.NewNat(5)
	b := numct.NewNat(7)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	arith.ModMul(out1, a, b)
	decoded.ModMul(out2, a, b)

	require.True(t, out1.Equal(out2) == ct.True)
}

func TestArithmetic_InterfaceSerialization_OddPrimeFactors(t *testing.T) {
	t.Parallel()

	// Create OddPrimeFactors
	p := numct.NewNat(11)
	q := numct.NewNat(13)

	original, ok := modular.NewOddPrimeFactors(p, q)
	require.Equal(t, ct.True, ok)

	// Test serialising through the Arithmetic interface
	var arith modular.Arithmetic = original

	// Marshal using serde which handles interface serialisation
	data, err := serde.MarshalCBOR(arith)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal back to Arithmetic interface
	decoded, err := serde.UnmarshalCBOR[modular.Arithmetic](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify it's an OddPrimeFactors
	decodedOPF, okType := decoded.(*modular.OddPrimeFactors)
	require.True(t, okType, "decoded should be *OddPrimeFactors")
	require.NotNil(t, decodedOPF)

	// Verify the modulus matches
	require.True(t, original.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test operations
	a := numct.NewNat(5)
	exp := numct.NewNat(10)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	arith.ModExp(out1, a, exp)
	decoded.ModExp(out2, a, exp)

	require.True(t, out1.Equal(out2) == ct.True)
}

func TestArithmetic_InterfaceSerialization_OddPrimeSquareFactors(t *testing.T) {
	t.Parallel()

	// Create OddPrimeSquareFactors
	p := numct.NewNat(7)
	q := numct.NewNat(11)

	original, ok := modular.NewOddPrimeSquareFactors(p, q)
	require.Equal(t, ct.True, ok)

	// Test serialising through the Arithmetic interface
	var arith modular.Arithmetic = original

	// Marshal using serde which handles interface serialisation
	data, err := serde.MarshalCBOR(arith)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal back to Arithmetic interface
	decoded, err := serde.UnmarshalCBOR[modular.Arithmetic](data)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify it's an OddPrimeSquareFactors
	decodedOPSF, okType := decoded.(*modular.OddPrimeSquareFactors)
	require.True(t, okType, "decoded should be *OddPrimeSquareFactors")
	require.NotNil(t, decodedOPSF)

	// Verify the modulus matches
	require.True(t, original.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

	// Test operations
	a := numct.NewNat(100)
	exp := numct.NewNat(5)
	out1 := numct.NewNat(0)
	out2 := numct.NewNat(0)

	arith.ModExp(out1, a, exp)
	decoded.ModExp(out2, a, exp)

	require.True(t, out1.Equal(out2) == ct.True)
}

func TestArithmetic_RoundTrip_AllTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		arith modular.Arithmetic
	}{
		{
			name: "SimpleModulus",
			arith: func() modular.Arithmetic {
				n := numct.NewNat(143)
				m, _ := numct.NewModulus(n)
				s, _ := modular.NewSimple(m)
				return s
			}(),
		},
		{
			name: "OddPrimeFactors",
			arith: func() modular.Arithmetic {
				p := numct.NewNat(11)
				q := numct.NewNat(13)
				opf, _ := modular.NewOddPrimeFactors(p, q)
				return opf
			}(),
		},
		{
			name: "OddPrimeSquareFactors",
			arith: func() modular.Arithmetic {
				p := numct.NewNat(7)
				q := numct.NewNat(11)
				opsf, _ := modular.NewOddPrimeSquareFactors(p, q)
				return opsf
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Marshal
			data, err := serde.MarshalCBOR(tc.arith)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Unmarshal
			decoded, err := serde.UnmarshalCBOR[modular.Arithmetic](data)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			// Verify modulus matches
			require.True(t, tc.arith.Modulus().Nat().Equal(decoded.Modulus().Nat()) == ct.True)

			// Test that operations produce the same results
			a := numct.NewNat(123)
			b := numct.NewNat(456)
			out1 := numct.NewNat(0)
			out2 := numct.NewNat(0)

			tc.arith.ModMul(out1, a, b)
			decoded.ModMul(out2, a, b)

			require.True(t, out1.Equal(out2) == ct.True, "ModMul results should match")
		})
	}
}

func TestCBOR_InvalidData(t *testing.T) {
	t.Parallel()

	t.Run("SimpleModulus_InvalidData", func(t *testing.T) {
		var s modular.SimpleModulus
		err := cbor.Unmarshal([]byte{0x00}, &s)
		require.Error(t, err)
	})

	t.Run("OddPrimeFactors_InvalidData", func(t *testing.T) {
		var opf modular.OddPrimeFactors
		err := cbor.Unmarshal([]byte{0x00}, &opf)
		require.Error(t, err)
	})

	t.Run("OddPrimeSquareFactors_InvalidData", func(t *testing.T) {
		var opsf modular.OddPrimeSquareFactors
		err := cbor.Unmarshal([]byte{0x00}, &opsf)
		require.Error(t, err)
	})
}
