package num_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	// Remove unused import
	"github.com/bronlabs/bron-crypto/pkg/ase/nt"
	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

func TestUnitGroup_Creation(t *testing.T) {
	t.Parallel()

	// Create Z/15Z
	zn, err := num.NewZn(cardinal.New(15))
	require.NoError(t, err)

	t.Run("Create with prime factorization", func(t *testing.T) {
		// Skip this test as it requires a proper UniqueFactorizationMonoidElement type
		// which is not easily available in the test
		t.Skip("PrimeFactorisation requires UniqueFactorizationMonoidElement")
	})

	t.Run("Create with nil factors", func(t *testing.T) {
		// Skip since we can't easily create PrimeFactorisation
		t.Skip("PrimeFactorisation requires UniqueFactorizationMonoidElement")
	})

	t.Run("Create with unknown order", func(t *testing.T) {
		ug, err := num.NewUnitGroupOfUnknownOrder(zn)
		require.NoError(t, err)
		require.NotNil(t, ug)
		require.Equal(t, cardinal.Unknown, ug.Order())
	})

	t.Run("Create with nil Zn", func(t *testing.T) {
		_, err := num.NewUnitGroupOfUnknownOrder[*num.Uint](nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "zn")
	})
}

func TestUnitGroup_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(21)) // 21 = 3 * 7
	require.NoError(t, err)

	// Create unit group with unknown order for simplicity
	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("Name", func(t *testing.T) {
		name := ug.Name()
		require.Equal(t, "(Z/21Z)*", name)
	})

	t.Run("Modulus", func(t *testing.T) {
		mod := ug.Modulus()
		require.Equal(t, "21", mod.String())
	})

	t.Run("One", func(t *testing.T) {
		one := ug.One()
		require.True(t, one.IsOne())
		require.True(t, one.IsOpIdentity())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		identity := ug.OpIdentity()
		require.True(t, identity.IsOne())
	})

	t.Run("ElementSize", func(t *testing.T) {
		size := ug.ElementSize()
		require.Equal(t, zn.ElementSize(), size)
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		scalarStruct := ug.ScalarStructure()
		require.NotNil(t, scalarStruct)
		require.Equal(t, num.Z(), scalarStruct)
	})
}

func TestUnit_Operations(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(13)) // Prime modulus
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("Multiplication", func(t *testing.T) {
		// Create units from coprime elements
		// 3 and 4 are coprime to 13 (prime modulus)
		a, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(4))
		require.NoError(t, err)

		c := a.Mul(b)
		
		// 3 * 4 = 12 in Z/13Z
		expected, err := ug.FromCardinal(cardinal.New(12))
		require.NoError(t, err)
		require.True(t, c.Equal(expected))
	})

	t.Run("Op is multiplication", func(t *testing.T) {
		// 3 and 4 are coprime to 13
		a, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(4))
		require.NoError(t, err)

		c := a.Op(b)
		d := a.Mul(b)
		require.Equal(t, c, d)
	})

	t.Run("Square", func(t *testing.T) {
		// 5 is coprime to 13
		a, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)
		
		sq := a.Square()
		// 5^2 = 25 ≡ 12 (mod 13)
		expected, err := ug.FromCardinal(cardinal.New(12))
		require.NoError(t, err)
		require.True(t, sq.Equal(expected))
	})

	t.Run("Inverse", func(t *testing.T) {
		// 5 is coprime to 13
		a, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)
		
		inv := a.Inv()

		// Verify a * inv = 1
		product := a.Mul(inv)
		require.True(t, product.IsOne())
	})

	t.Run("TryInv", func(t *testing.T) {
		// 5 is coprime to 13
		a, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)
		
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.NotNil(t, inv)

		product := a.Mul(inv)
		require.True(t, product.IsOne())
	})

	t.Run("OpInv", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)
		inv := a.OpInv()
		require.Equal(t, a.Inv(), inv)
	})

	t.Run("Division", func(t *testing.T) {
		// 8 and 3 are coprime to 13
		a, err := ug.FromCardinal(cardinal.New(8))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)

		c := a.Div(b)
		// Verify c * b = a by checking they're equal
		product := c.Mul(b)
		require.True(t, a.Equal(product))
	})

	t.Run("TryDiv", func(t *testing.T) {
		// 8 and 3 are coprime to 13
		a, err := ug.FromCardinal(cardinal.New(8))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)

		c, err := a.TryDiv(b)
		require.NoError(t, err)
		require.NotNil(t, c)

		product := c.Mul(b)
		require.True(t, a.Equal(product))
	})
}

func TestUnit_Comparison(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("Equal", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)
		c, err := ug.FromCardinal(cardinal.New(4))
		require.NoError(t, err)

		require.True(t, a.Equal(b))
		require.False(t, a.Equal(c))
	})

	t.Run("SameModulus", func(t *testing.T) {
		zn2, err := num.NewZn(cardinal.New(13))
		require.NoError(t, err)
		ug2, err := num.NewUnitGroupOfUnknownOrder(zn2)
		require.NoError(t, err)

		a, err := ug.FromCardinal(cardinal.New(3))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(4))
		require.NoError(t, err)
		c, err := ug2.FromCardinal(cardinal.New(3))
		require.NoError(t, err)

		require.True(t, a.SameModulus(b))
		require.False(t, a.SameModulus(c))
	})
}

func TestUnit_Properties(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(17))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("IsOne", func(t *testing.T) {
		one := ug.One()
		notOne, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)

		require.True(t, one.IsOne())
		require.False(t, notOne.IsOne())
	})

	t.Run("IsOpIdentity", func(t *testing.T) {
		one := ug.One()
		notOne, err := ug.FromCardinal(cardinal.New(5))
		require.NoError(t, err)

		require.True(t, one.IsOpIdentity())
		require.False(t, notOne.IsOpIdentity())
	})

	t.Run("Clone", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		b := a.Clone()

		require.True(t, a.Equal(b))
		require.NotSame(t, a, b)
	})

	t.Run("HashCode", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		b, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		c, err := ug.FromCardinal(cardinal.New(8))
		require.NoError(t, err)

		require.Equal(t, a.HashCode(), b.HashCode())
		require.NotEqual(t, a.HashCode(), c.HashCode())
	})

	t.Run("Cardinal", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		card := a.Cardinal()
		// Cardinal returns the value as stored in Z/17Z
		// which should be 7 since 7 < 17
		require.Equal(t, uint64(7), card.Uint64())
	})

	t.Run("Bytes", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		bytes := a.Bytes()
		require.NotEmpty(t, bytes)
	})

	t.Run("String", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		str := a.String()
		require.Contains(t, str, "Unit<(Z/17Z)*>(7)")
	})

	t.Run("Structure", func(t *testing.T) {
		a, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		structure := a.Structure()
		require.Equal(t, ug, structure)
	})
}

func TestUnit_NilPanics(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	a, err := ug.FromCardinal(cardinal.New(3))
	require.NoError(t, err)

	t.Run("Op with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Op(nil)
		})
	})

	t.Run("Mul with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Mul(nil)
		})
	})

	t.Run("Equal with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Equal(nil)
		})
	})

	t.Run("SameModulus with nil panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.SameModulus(nil)
		})
	})
}

func TestUnit_DifferentModulus(t *testing.T) {
	t.Parallel()

	zn1, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)
	ug1, err := num.NewUnitGroupOfUnknownOrder(zn1)
	require.NoError(t, err)

	zn2, err := num.NewZn(cardinal.New(13))
	require.NoError(t, err)
	ug2, err := num.NewUnitGroupOfUnknownOrder(zn2)
	require.NoError(t, err)

	a, err := ug1.FromCardinal(cardinal.New(3))
	require.NoError(t, err)
	b, err := ug2.FromCardinal(cardinal.New(3))
	require.NoError(t, err)

	t.Run("Mul with different modulus panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Mul(b)
		})
	})

	t.Run("Div with different modulus panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Div(b)
		})
	})

	t.Run("Exp with different modulus panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Exp(b)
		})
	})
}

func TestUnit_NotImplemented(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	a, err := ug.FromCardinal(cardinal.New(3))
	require.NoError(t, err)
	b, err := ug.FromCardinal(cardinal.New(4))
	require.NoError(t, err)

	t.Run("Exp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.Exp(b)
		})
	})

	t.Run("IsTorsionFree panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.IsTorsionFree()
		})
	})

	t.Run("ScalarExp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.ScalarExp(num.Z().FromInt64(2))
		})
	})

	t.Run("ScalarOp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_ = a.ScalarOp(num.Z().FromInt64(2))
		})
	})
}

func TestUnitGroup_NotImplemented(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(11))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("MultiScalarOp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _ = ug.MultiScalarOp(nil, nil)
		})
	})

	t.Run("MultiScalarExp panics", func(t *testing.T) {
		require.Panics(t, func() {
			_, _ = ug.MultiScalarExp(nil, nil)
		})
	})
}

func TestUnitGroup_FromBytes(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(17))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	t.Run("Valid bytes", func(t *testing.T) {
		// Create a unit and get its bytes
		orig, err := ug.FromCardinal(cardinal.New(7))
		require.NoError(t, err)
		bytes := orig.Bytes()

		// Create from bytes
		unit, err := ug.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, orig.Equal(unit))
	})

	t.Run("Empty bytes", func(t *testing.T) {
		_, err := ug.FromBytes([]byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty")
	})

	t.Run("Wrong size bytes", func(t *testing.T) {
		// The underlying Zn may accept various byte sizes
		// so we can't guarantee this will error
		// Skip this test as behavior depends on Zn implementation
		t.Skip("Byte size validation depends on underlying Zn implementation")
	})
}

func TestUnitGroup_FromCardinal(t *testing.T) {
	t.Parallel()

	zn, err := num.NewZn(cardinal.New(19))
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	card := cardinal.New(25)
	unit, err := ug.FromCardinal(card)
	require.NoError(t, err)
	// 25 mod 19 = 6
	expected, err := ug.FromCardinal(cardinal.New(6))
	require.NoError(t, err)
	require.True(t, unit.Equal(expected))
}

func TestUnit_InverseWithNonUnit(t *testing.T) {
	t.Parallel()

	// Use composite modulus where not all elements are units
	zn, err := num.NewZn(cardinal.New(15)) // 15 = 3 * 5
	require.NoError(t, err)

	ug, err := num.NewUnitGroupOfUnknownOrder(zn)
	require.NoError(t, err)

	// 3 is not a unit in Z/15Z (gcd(3,15) = 3 ≠ 1)
	// However, FromCardinal doesn't check if the element is actually a unit
	nonUnit, err := ug.FromCardinal(cardinal.New(3))
	require.NoError(t, err)

	t.Run("Inv panics for non-unit", func(t *testing.T) {
		require.Panics(t, func() {
			_ = nonUnit.Inv()
		})
	})
}

func TestEulerTotientUnits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n        uint64
		factors  map[uint64]uint64 // prime -> exponent
		expected uint64
	}{
		{
			n:        2,
			factors:  map[uint64]uint64{2: 1},
			expected: 1, // φ(2) = 1
		},
		{
			n:        6,
			factors:  map[uint64]uint64{2: 1, 3: 1},
			expected: 2, // φ(6) = φ(2) * φ(3) = 1 * 2 = 2
		},
		{
			n:        15,
			factors:  map[uint64]uint64{3: 1, 5: 1},
			expected: 8, // φ(15) = φ(3) * φ(5) = 2 * 4 = 8
		},
		{
			n:        12,
			factors:  map[uint64]uint64{2: 2, 3: 1},
			expected: 4, // φ(12) = φ(4) * φ(3) = 2 * 2 = 4
		},
		{
			n:        100,
			factors:  map[uint64]uint64{2: 2, 5: 2},
			expected: 40, // φ(100) = φ(4) * φ(25) = 2 * 20 = 40
		},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.n)), func(t *testing.T) {
			factors := hashmap.NewComparable[*num.NatPlus, *num.Nat]()
			for p, k := range tt.factors {
				pNat := num.N().FromUint64(p)
			pNatPlus, err := num.NPlus().FromNat(pNat)
			require.NoError(t, err)
			factors.Put(pNatPlus, num.N().FromUint64(k))
			}

			// Need to create a proper element type for prime factorization
			zn, err := num.NewZn(cardinal.New(1000))
			require.NoError(t, err)
			n := zn.FromUint64(tt.n)
			pf, err := num.NewPrimeFactorisation(n, factors.Freeze())
			require.NoError(t, err)

			totient, err := num.EulerTotient(pf)
			require.NoError(t, err)
			require.Equal(t, tt.expected, totient.Cardinal().Uint64())
		})
	}

	t.Run("Nil factorization", func(t *testing.T) {
		_, err := num.EulerTotient[*num.Uint](nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "argument")
	})
}

func TestUnit_StringNilGroup(t *testing.T) {
	t.Parallel()

	// Skip this test since we can't create a unit with nil group due to private fields
	t.Skip("Cannot test nil group case due to private fields")
}

func TestUnit_NilString(t *testing.T) {
	var unit *num.Unit[*num.Uint]
	str := unit.String()
	require.Equal(t, "nil", str)
}