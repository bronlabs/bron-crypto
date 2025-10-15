package znstar_test

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/stretchr/testify/require"
)

func TestNewUnitGroupOfUnknownOrder(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		modulus uint64
		wantErr bool
	}{
		{"modulus 15", 15, false},
		{"modulus 35", 35, false},
		{"modulus 77", 77, false},
		{"modulus 2", 2, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := num.NPlus().FromUint64(tc.modulus)
			require.NoError(t, err)

			// Use OddPrimeFactors as the arithmetic type
			uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, uzmod)
			require.True(t, uzmod.Order().IsUnknown())
			require.Equal(t, m, uzmod.Modulus())
		})
	}
}

func TestNewUnit(t *testing.T) {
	t.Parallel()

	m, err := num.NPlus().FromUint64(15)
	require.NoError(t, err)

	uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
	require.NoError(t, err)

	zmod, err := num.NewZMod(m)
	require.NoError(t, err)

	// Test creating units
	tests := []struct {
		name    string
		value   uint64
		wantErr bool
	}{
		{"unit 2", 2, false},    // gcd(2, 15) = 1
		{"unit 4", 4, false},    // gcd(4, 15) = 1
		{"unit 7", 7, false},    // gcd(7, 15) = 1
		{"non-unit 3", 3, true}, // gcd(3, 15) = 3
		{"non-unit 5", 5, true}, // gcd(5, 15) = 5
		{"non-unit 6", 6, true}, // gcd(6, 15) = 3
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := zmod.FromUint64(tt.value)
			require.NoError(t, err)

			unit, err := uzmod.FromUint(u)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "not coprime")
			} else {
				require.NoError(t, err)
				require.NotNil(t, unit)
				// Check the value
				require.Equal(t, tt.value, unit.Value().Big().Uint64())
			}
		})
	}
}

func TestRSAGroup(t *testing.T) {
	t.Parallel()

	// Test with small primes
	p, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(13)
	require.NoError(t, err)

	rsaGroup, err := znstar.NewRSAGroup(p, q)
	require.NoError(t, err)
	require.NotNil(t, rsaGroup)

	// n = 11 * 13 = 143
	n := p.Mul(q)
	// Compare the string representation since the internal structure may differ
	require.Equal(t, n.String(), rsaGroup.Modulus().String())

	// RSAGroupKnownOrder should have known order: φ(n) = (p-1)(q-1) = 10*12 = 120
	require.False(t, rsaGroup.Order().IsUnknown())
	expectedOrder := p.Lift().Sub(num.Z().FromUint64(1)).Mul(q.Lift().Sub(num.Z().FromUint64(1)))
	require.Equal(t, expectedOrder.Big().String(), rsaGroup.Order().Big().String())
}

func TestRSAGroupOfUnknownOrder(t *testing.T) {
	t.Parallel()

	// Create RSA modulus n = p*q = 11*13 = 143
	n, err := num.NPlus().FromUint64(143)
	require.NoError(t, err)

	rsaGroup, err := znstar.NewRSAGroupOfUnknownOrder(n)
	require.NoError(t, err)
	require.NotNil(t, rsaGroup)

	require.Equal(t, n, rsaGroup.Modulus())
	require.True(t, rsaGroup.Order().IsUnknown())
}

func TestUnitGroupOperations(t *testing.T) {
	t.Parallel()

	m, err := num.NPlus().FromUint64(15)
	require.NoError(t, err)

	uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
	require.NoError(t, err)

	// Test One
	one := uzmod.One()
	require.NotNil(t, one)
	require.Equal(t, uint64(1), one.Value().Big().Uint64())

	// Test OpIdentity
	identity := uzmod.OpIdentity()
	require.True(t, one.Equal(identity))

	// Test Random
	unit, err := uzmod.Random(rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, unit)

	// Verify it's actually a unit (coprime to modulus)
	// The unit's value should be coprime to the modulus
	unitNat := unit.Value()
	require.True(t, unitNat.Coprime(m.Value()) == ct.True)
}

func TestUnitArithmetic(t *testing.T) {
	t.Parallel()

	m, err := num.NPlus().FromUint64(15)
	require.NoError(t, err)

	uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
	require.NoError(t, err)

	zmod, err := num.NewZMod(m)
	require.NoError(t, err)

	// Create units
	u2, err := zmod.FromUint64(2)
	require.NoError(t, err)
	unit2, err := uzmod.FromUint(u2)
	require.NoError(t, err)

	u4, err := zmod.FromUint64(4)
	require.NoError(t, err)
	unit4, err := uzmod.FromUint(u4)
	require.NoError(t, err)

	// Test multiplication
	product := unit2.Op(unit4)
	require.NotNil(t, product)
	// 2 * 4 = 8 (mod 15)
	require.Equal(t, uint64(8), product.Value().Big().Uint64())

	// Test inverse
	inv2, err := unit2.TryInv()
	require.NoError(t, err)
	require.NotNil(t, inv2)

	// Verify: 2 * inv2 ≡ 1 (mod 15)
	// inv2 should be 8 because 2 * 8 = 16 ≡ 1 (mod 15)
	require.Equal(t, uint64(8), inv2.Value().Big().Uint64())

	// Test that multiplying by inverse gives identity
	shouldBeOne := unit2.Op(inv2)
	require.Equal(t, uint64(1), shouldBeOne.Value().Big().Uint64())
}

func TestUnitExponentiation(t *testing.T) {
	t.Parallel()

	m, err := num.NPlus().FromUint64(15)
	require.NoError(t, err)

	uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
	require.NoError(t, err)

	zmod, err := num.NewZMod(m)
	require.NoError(t, err)

	// Create a unit
	u2, err := zmod.FromUint64(2)
	require.NoError(t, err)
	unit2, err := uzmod.FromUint(u2)
	require.NoError(t, err)

	// Test exponentiation: 2^3 = 8 (mod 15)
	exp := num.N().FromUint64(3)
	result := unit2.ScalarExp(exp)
	require.NotNil(t, result)
	require.Equal(t, uint64(8), result.Value().Big().Uint64())

	// Test exponentiation: 2^4 = 16 ≡ 1 (mod 15)
	// This shows that the order of 2 in (Z/15Z)* is 4
	exp4 := num.N().FromUint64(4)
	result4 := unit2.ScalarExp(exp4)
	require.Equal(t, uint64(1), result4.Value().Big().Uint64())
}

func TestPaillierGroup(t *testing.T) {
	t.Parallel()

	// Test with small primes
	p, err := num.NPlus().FromUint64(7)
	require.NoError(t, err)
	q, err := num.NPlus().FromUint64(11)
	require.NoError(t, err)

	paillierGroup, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)
	require.NotNil(t, paillierGroup)

	// n = 7 * 11 = 77
	// Modulus should be n^2 = 5929
	n := p.Mul(q)
	n2 := n.Mul(n)
	// Compare the string representation since the internal structure may differ
	require.Equal(t, n2.String(), paillierGroup.Modulus().String())

	// Test operations on the Paillier group
	one := paillierGroup.One()
	require.NotNil(t, one)
	require.Equal(t, uint64(1), one.Value().Big().Uint64())

	// Test Random unit
	unit, err := paillierGroup.Random(rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, unit)
}

func TestPaillierGroupOfUnknownOrder(t *testing.T) {
	t.Parallel()

	// Create n = 77, n^2 = 5929
	n, err := num.NPlus().FromUint64(77)
	require.NoError(t, err)
	n2 := n.Mul(n) // 5929

	paillierGroup, err := znstar.NewPaillierGroupOfUnknownOrder(n2, n)
	require.NoError(t, err)
	require.NotNil(t, paillierGroup)

	require.Equal(t, n2, paillierGroup.Modulus())
	require.True(t, paillierGroup.Order().IsUnknown())
}

func TestUnitGroupFromUint(t *testing.T) {
	t.Parallel()

	m, err := num.NPlus().FromUint64(15)
	require.NoError(t, err)

	uzmod, err := znstar.NewRSAGroupOfUnknownOrder(m)
	require.NoError(t, err)

	zmod, err := num.NewZMod(m)
	require.NoError(t, err)

	// Test FromUint method
	u2, err := zmod.FromUint64(2)
	require.NoError(t, err)

	unit2, err := uzmod.FromUint(u2)
	require.NoError(t, err)
	require.NotNil(t, unit2)
	require.Equal(t, uint64(2), unit2.Value().Big().Uint64())

	// Test with non-unit should fail
	u3, err := zmod.FromUint64(3)
	require.NoError(t, err)

	_, err = uzmod.FromUint(u3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not coprime")
}
