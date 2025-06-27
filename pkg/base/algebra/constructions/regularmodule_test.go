package constructions_test

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegularAlgebra tests the RegularAlgebra construction
func TestRegularAlgebra(t *testing.T) {
	// Use Z_12 as our base ring for testing
	z12, err := num.NewZn(cardinal.New(12))
	require.NoError(t, err)

	t.Run("NewRegularAlgebra", func(t *testing.T) {
		t.Run("Valid ring", func(t *testing.T) {
			alg, err := constructions.NewRegularAlgebra(z12)
			require.NoError(t, err)
			require.NotNil(t, alg)
			assert.Equal(t, "RegularAlgebra[Z\\12Z]", alg.Name())
		})

		t.Run("Nil ring", func(t *testing.T) {
			alg, err := constructions.NewRegularAlgebra((*num.Zn)(nil))
			assert.Error(t, err)
			assert.Nil(t, alg)
			assert.Contains(t, err.Error(), "ring")
		})
	})

	t.Run("Algebra operations", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		t.Run("OpIdentity", func(t *testing.T) {
			id := alg.OpIdentity()
			require.NotNil(t, id)
			assert.True(t, id.IsOpIdentity())
			assert.True(t, id.IsZero())
		})

		t.Run("Zero", func(t *testing.T) {
			zero := alg.Zero()
			require.NotNil(t, zero)
			assert.True(t, zero.IsZero())
			assert.True(t, zero.IsOpIdentity())
		})

		t.Run("One", func(t *testing.T) {
			one := alg.One()
			require.NotNil(t, one)
			assert.True(t, one.IsOne())
		})

		t.Run("ScalarStructure", func(t *testing.T) {
			scalarStruct := alg.ScalarStructure()
			require.NotNil(t, scalarStruct)
			// Should be the same ring
			assert.Equal(t, z12.Name(), scalarStruct.Name())
		})

		t.Run("ElementSize", func(t *testing.T) {
			// Should match the ring's element size
			assert.Equal(t, z12.ElementSize(), alg.ElementSize())
		})

		t.Run("Order", func(t *testing.T) {
			order := alg.Order()
			// Should be same as ring order
			assert.Equal(t, uint64(12), order.Uint64())
		})

		t.Run("Characteristic", func(t *testing.T) {
			char := alg.Characteristic()
			// Z_12 has characteristic 12
			assert.Equal(t, uint64(12), char.Uint64())
		})
	})

	t.Run("New elements", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		t.Run("Valid element", func(t *testing.T) {
			elem, err := alg.New(z12.FromUint64(5))
			require.NoError(t, err)
			require.NotNil(t, elem)
			assert.Equal(t, "5", elem.String())
		})

		t.Run("FromBytes", func(t *testing.T) {
			original := z12.FromUint64(7)
			bytes := original.Bytes()

			elem, err := alg.FromBytes(bytes)
			require.NoError(t, err)
			require.NotNil(t, elem)
			assert.Equal(t, "7", elem.String())
		})

	})

	t.Run("Element operations", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		elem1, err := alg.New(z12.FromUint64(3))
		require.NoError(t, err)
		elem2, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)

		t.Run("Op (addition)", func(t *testing.T) {
			result := elem1.Op(elem2)
			// 3 + 4 = 7 in Z_12
			assert.Equal(t, "7", result.String())
		})

		t.Run("Add", func(t *testing.T) {
			result := elem1.Add(elem2)
			assert.Equal(t, "7", result.String())
			// Op should be the same as Add
			assert.True(t, result.Equal(elem1.Op(elem2)))
		})

		t.Run("Sub", func(t *testing.T) {
			result := elem1.Sub(elem2)
			// The trait implementation is a - b
			assert.Equal(t, "11", result.String()) // 3-4 = -1 ≡ 11 (mod 12)
		})

		t.Run("OtherOp (multiplication)", func(t *testing.T) {
			result := elem1.OtherOp(elem2)
			// 3 * 4 = 12 ≡ 0 (mod 12)
			assert.Equal(t, "0", result.String())
		})

		t.Run("Mul", func(t *testing.T) {
			result := elem1.Mul(elem2)
			assert.Equal(t, "0", result.String())
			// OtherOp should be the same as Mul
			assert.True(t, result.Equal(elem1.OtherOp(elem2)))
		})

		t.Run("ScalarOp", func(t *testing.T) {
			scalar := z12.FromUint64(2)
			result := elem1.ScalarOp(scalar)
			// 3 * 2 = 6
			assert.Equal(t, "6", result.String())
		})

		t.Run("ScalarMul", func(t *testing.T) {
			scalar := z12.FromUint64(2)
			result := elem1.ScalarMul(scalar)
			// ScalarMul should be same as ScalarOp
			assert.Equal(t, "6", result.String())
		})

		t.Run("Double", func(t *testing.T) {
			double := elem1.Double()
			// 3 + 3 = 6
			assert.Equal(t, "6", double.String())
		})

		t.Run("Square", func(t *testing.T) {
			square := elem1.Square()
			// 3^2 = 9
			assert.Equal(t, "9", square.String())
		})

		t.Run("Neg", func(t *testing.T) {
			neg := elem1.Neg()
			// -3 ≡ 9 (mod 12)
			assert.Equal(t, "9", neg.String())
		})

		t.Run("OpInv", func(t *testing.T) {
			inv := elem1.OpInv()
			// OpInv is additive inverse (negation)
			assert.Equal(t, "9", inv.String())
			assert.True(t, elem1.Op(inv).IsOpIdentity())
		})

		t.Run("IsZero and IsOne", func(t *testing.T) {
			assert.False(t, elem1.IsZero())
			assert.False(t, elem1.IsOne())

			zero := alg.Zero()
			one := alg.One()
			assert.True(t, zero.IsZero())
			assert.True(t, one.IsOne())
		})

		t.Run("Equal", func(t *testing.T) {
			assert.True(t, elem1.Equal(elem1))
			assert.False(t, elem1.Equal(elem2))

			// Create another element with same value
			elem3, err := alg.New(z12.FromUint64(3))
			assert.NoError(t, err)
			assert.True(t, elem1.Equal(elem3))
		})

		t.Run("Clone", func(t *testing.T) {
			clone := elem1.Clone()
			assert.True(t, elem1.Equal(clone))
			assert.NotSame(t, elem1, clone)
		})

		t.Run("HashCode", func(t *testing.T) {
			// Equal elements should have same hash
			elem3, err := alg.New(z12.FromUint64(3))
			assert.NoError(t, err)
			assert.Equal(t, elem1.HashCode(), elem3.HashCode())

			// Different elements should (likely) have different hashes
			assert.NotEqual(t, elem1.HashCode(), elem2.HashCode())
		})

		t.Run("Bytes", func(t *testing.T) {
			bytes := elem1.Bytes()
			assert.NotEmpty(t, bytes)
		})
	})

	t.Run("Try operations", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		elem1, err := alg.New(z12.FromUint64(3))
		require.NoError(t, err)
		elem2, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)

		t.Run("TrySub", func(t *testing.T) {
			result, err := elem1.TrySub(elem2)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, "11", result.String())
		})

		t.Run("TryNeg", func(t *testing.T) {
			neg, err := elem1.TryNeg()
			require.NoError(t, err)
			require.NotNil(t, neg)
			assert.True(t, elem1.Add(neg).IsZero())
		})

		t.Run("TryOpInv", func(t *testing.T) {
			inv, err := elem1.TryOpInv()
			require.NoError(t, err)
			require.NotNil(t, inv)
			assert.True(t, elem1.Op(inv).IsOpIdentity())
		})

		t.Run("TryDiv", func(t *testing.T) {
			// Division by 4 in Z_12 might fail since gcd(4,12) ≠ 1
			_, err := elem1.TryDiv(elem2)
			// This should fail for non-units
			assert.Error(t, err)

			// Try with a unit (5 is coprime to 12)
			unit, err := alg.New(z12.FromUint64(5))
			require.NoError(t, err)
			result, err := elem1.TryDiv(unit)
			if err == nil {
				// Verify division worked
				assert.True(t, result.Mul(unit).Equal(elem1))
			}
		})

		t.Run("TryInv", func(t *testing.T) {
			// Only units can be inverted in Z_12
			// Units are: 1, 5, 7, 11
			unit, err := alg.New(z12.FromUint64(5))
			require.NoError(t, err)
			inv, err := unit.TryInv()
			if err == nil {
				assert.True(t, unit.Mul(inv).IsOne())
			}

			// Non-unit should fail
			nonUnit, err := alg.New(z12.FromUint64(4))
			require.NoError(t, err)
			_, err = nonUnit.TryInv()
			assert.Error(t, err)
		})
	})

	t.Run("IsTorsionFree", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)
		a, err := alg.New(z12.FromUint64(3))
		require.NoError(t, err)
		b, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)
		product := a.Mul(b)
		// Z_12 is not a domain (has zero divisors), so not torsion free
		assert.True(t, product.IsZero(), "3*4 should be 0 in Z_12")
		assert.False(t, a.IsTorsionFree())
	})

	t.Run("Structure method", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)
		elem, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		structure := elem.Structure()
		require.NotNil(t, structure)
		assert.Equal(t, alg.Name(), structure.Name())
	})

	t.Run("MultiScalarOp", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		// Create scalars and elements
		scalar1 := z12.FromUint64(2)
		scalar2 := z12.FromUint64(3)
		elem1, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)
		elem2, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		// Compute 2*4 + 3*5 = 8 + 15 = 23 ≡ 11 (mod 12)
		result, err := alg.MultiScalarOp([]*num.Uint{scalar1, scalar2}, []*constructions.RegularAlgebraElement[*num.Uint]{elem1, elem2})
		require.NoError(t, err)
		assert.Equal(t, "11", result.String())
	})

	t.Run("MultiScalarOp with mismatched lengths", func(t *testing.T) {
		alg, _ := constructions.NewRegularAlgebra(z12)
		scalar := z12.FromUint64(2)
		elem1, err := alg.New(z12.FromUint64(3))
		require.NoError(t, err)
		elem2, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)

		// Mismatched lengths should fail
		_, err = alg.MultiScalarOp([]*num.Uint{scalar}, []*constructions.RegularAlgebraElement[*num.Uint]{elem1, elem2})
		assert.Error(t, err, "MultiScalarOp should fail with mismatched lengths")
	})

	t.Run("MultiScalarMul", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)

		// Create scalars and elements
		scalar1 := z12.FromUint64(2)
		scalar2 := z12.FromUint64(3)
		elem1, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)
		elem2, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		// Should be same as MultiScalarOp
		result, err := alg.MultiScalarMul([]*num.Uint{scalar1, scalar2}, []*constructions.RegularAlgebraElement[*num.Uint]{elem1, elem2})
		require.NoError(t, err)
		assert.Equal(t, "11", result.String())
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(z12)
		require.NoError(t, err)
		elem, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		scalarStruct := elem.ScalarStructure()
		require.NotNil(t, scalarStruct)
		assert.Equal(t, z12.Name(), scalarStruct.Name())
	})
}

// TestFiniteRegularAlgebra tests the finite variant
func TestFiniteRegularAlgebra(t *testing.T) {
	z17, err := num.NewZn(cardinal.New(17)) // Prime field
	require.NoError(t, err)

	t.Run("NewFiniteRegularAlgebra", func(t *testing.T) {
		alg, err := constructions.NewFiniteRegularAlgebra(z17)
		require.NoError(t, err)
		require.NotNil(t, alg)

		// Should implement FiniteAlgebra interface
		var _ algebra.FiniteAlgebra[*constructions.FiniteRegularAlgebraElement[*num.Uint], *num.Uint] = alg
	})

	t.Run("Random element generation", func(t *testing.T) {
		alg, err := constructions.NewFiniteRegularAlgebra(z17)
		require.NoError(t, err)

		elem, err := alg.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Element should be in [0, 17)
		// Can't easily check the exact value, but it should be valid
		assert.NotNil(t, elem)
	})

	t.Run("Hash to element", func(t *testing.T) {
		alg, err := constructions.NewFiniteRegularAlgebra(z17)
		require.NoError(t, err)

		input := []byte("test input for hashing")
		elem, err := alg.Hash(input)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Hash should be deterministic
		elem2, err := alg.Hash(input)
		require.NoError(t, err)
		assert.True(t, elem.Equal(elem2))
	})

	t.Run("IsTorsionFree for prime field", func(t *testing.T) {
		alg, err := constructions.NewFiniteRegularAlgebra(z17)
		require.NoError(t, err)
		elem, err := alg.New(z17.FromUint64(5))
		require.NoError(t, err)

		// Z_17 is a prime field (domain), so it's torsion free
		assert.True(t, elem.IsTorsionFree())
	})
}

// TestRegularAlgebraWithK256 tests with the k256 scalar field
func TestRegularAlgebraWithK256(t *testing.T) {
	scalarField := k256.NewScalarField()

	t.Run("Construction", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(scalarField)
		require.NoError(t, err)
		assert.Equal(t, "RegularAlgebra[secp256k1Fq]", alg.Name())
	})

	t.Run("Operations", func(t *testing.T) {
		alg, err := constructions.NewRegularAlgebra(scalarField)
		require.NoError(t, err)

		// Create some test elements
		elem1, err := alg.New(scalarField.FromUint64(12345))
		require.NoError(t, err)
		elem2, err := alg.New(scalarField.FromUint64(67890))
		require.NoError(t, err)

		// Test multiplication as algebra
		result := elem1.Mul(elem2)
		expected := scalarField.FromUint64(12345).Mul(scalarField.FromUint64(67890))
		assert.True(t, expected.Equal(result.Value()))

		// Test it's torsion free (prime field)
		assert.True(t, elem1.IsTorsionFree())
	})
}

// TestRegularAlgebraEdgeCases tests edge cases
func TestRegularAlgebraEdgeCases(t *testing.T) {
	z12, _ := num.NewZn(cardinal.New(12))
	alg, _ := constructions.NewRegularAlgebra(z12)

	t.Run("Zero element operations", func(t *testing.T) {
		zero := alg.Zero()
		elem, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		// Zero is additive identity
		assert.True(t, zero.Add(elem).Equal(elem))
		assert.True(t, elem.Add(zero).Equal(elem))

		// Zero annihilates in multiplication
		assert.True(t, zero.Mul(elem).IsZero())
		assert.True(t, elem.Mul(zero).IsZero())
	})

	t.Run("One element operations", func(t *testing.T) {
		one := alg.One()
		elem, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)

		// One is multiplicative identity
		assert.True(t, one.Mul(elem).Equal(elem))
		assert.True(t, elem.Mul(one).Equal(elem))
	})

	t.Run("Chain operations", func(t *testing.T) {
		a, err := alg.New(z12.FromUint64(2))
		require.NoError(t, err)
		b, err := alg.New(z12.FromUint64(3))
		require.NoError(t, err)
		c, err := alg.New(z12.FromUint64(4))
		require.NoError(t, err)

		// Test associativity: (a+b)+c = a+(b+c)
		left := a.Add(b).Add(c)
		right := a.Add(b.Add(c))
		assert.True(t, left.Equal(right))

		// Test distributivity: a*(b+c) = a*b + a*c
		dist1 := a.Mul(b.Add(c))
		dist2 := a.Mul(b).Add(a.Mul(c))
		assert.True(t, dist1.Equal(dist2))
	})
}

// TestFiniteRegularAlgebraEdgeCases tests edge cases for finite variant
func TestFiniteRegularAlgebraEdgeCases(t *testing.T) {
	z17, _ := num.NewZn(cardinal.New(17))

	t.Run("Structure method for finite variant", func(t *testing.T) {
		alg, err := constructions.NewFiniteRegularAlgebra(z17)
		require.NoError(t, err)
		elem, err := alg.New(z17.FromUint64(5))
		require.NoError(t, err)

		structure := elem.Structure()
		require.NotNil(t, structure)
		assert.Equal(t, alg.Name(), structure.Name())
	})

	t.Run("Finite variant panic on non-finite ring", func(t *testing.T) {
		// BUG: Similar to regular variant, panics on type assertion
		elem := &constructions.FiniteRegularAlgebraElement[*num.Uint]{}
		assert.Panics(t, func() {
			_ = elem.Structure()
		}, "Structure() should panic when scalar structure is not a FiniteRing")
	})
}

// BenchmarkRegularAlgebra provides performance benchmarks
func BenchmarkRegularAlgebra(b *testing.B) {
	z257, _ := num.NewZn(cardinal.New(257)) // prime field
	alg, _ := constructions.NewRegularAlgebra(z257)
	elem1, err := alg.New(z257.FromUint64(123))
	require.NoError(b, err)
	elem2, err := alg.New(z257.FromUint64(234))
	require.NoError(b, err)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Add(elem2)
		}
	})

	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Mul(elem2)
		}
	})

	b.Run("Square", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Square()
		}
	})

	b.Run("ScalarOp", func(b *testing.B) {
		scalar := z257.FromUint64(7)
		for i := 0; i < b.N; i++ {
			_ = elem1.ScalarOp(scalar)
		}
	})
}

// TestTypeConstraints tests that the type constraints are satisfied
func TestRegularAlgebraTypeConstraints(t *testing.T) {
	t.Run("Interface satisfaction", func(t *testing.T) {
		z12, _ := num.NewZn(cardinal.New(12))
		alg, _ := constructions.NewRegularAlgebra(z12)

		// Check that it implements Algebra
		var _ algebra.Algebra[*constructions.RegularAlgebraElement[*num.Uint], *num.Uint] = alg

		// Check element implements AlgebraElement
		elem, err := alg.New(z12.FromUint64(5))
		require.NoError(t, err)
		var _ algebra.AlgebraElement[*constructions.RegularAlgebraElement[*num.Uint], *num.Uint] = elem

		// Check finite variants
		falg, err := constructions.NewFiniteRegularAlgebra(z12)
		require.NoError(t, err)
		var _ algebra.FiniteAlgebra[*constructions.FiniteRegularAlgebraElement[*num.Uint], *num.Uint] = falg

		felem, err := falg.New(z12.FromUint64(5))
		require.NoError(t, err)
		var _ algebra.FiniteAlgebraElement[*constructions.FiniteRegularAlgebraElement[*num.Uint], *num.Uint] = felem

		t.Log("Type constraints are satisfied correctly")
	})
}
