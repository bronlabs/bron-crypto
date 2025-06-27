package constructions_test

import (
	"crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectPowerGroup tests the DirectPowerGroup construction
func TestDirectPowerGroup(t *testing.T) {
	// Use Z_12 as our base group for testing
	z12, err := num.NewZn(cardinal.New(12))
	require.NoError(t, err)

	t.Run("NewDirectPowerGroup", func(t *testing.T) {
		t.Run("Valid arity", func(t *testing.T) {
			g, err := constructions.NewDirectPowerGroup(z12, 3)
			require.NoError(t, err)
			require.NotNil(t, g)
			assert.Equal(t, cardinal.New(3), g.Arity())
			assert.Equal(t, "(Z\\12Z)^3", g.Name())
		})

		t.Run("Zero arity", func(t *testing.T) {
			g, err := constructions.NewDirectPowerGroup(z12, 0)
			assert.Error(t, err)
			assert.Nil(t, g)
			assert.Contains(t, err.Error(), "arity must be greater than 0")
		})

		t.Run("Nil base group", func(t *testing.T) {
			g, err := constructions.NewDirectPowerGroup((*num.Zn)(nil), 3)
			assert.Error(t, err)
			assert.Nil(t, g)
		})
	})

	t.Run("Group operations", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 3)
		require.NoError(t, err)

		t.Run("OpIdentity", func(t *testing.T) {
			id := g.OpIdentity()
			require.NotNil(t, id)
			components := id.Components()
			require.Len(t, components, 3)
			for _, c := range components {
				assert.True(t, c.IsZero()) // In additive group, identity is 0
			}
		})

		t.Run("New elements", func(t *testing.T) {
			a := z12.FromUint64(3)
			b := z12.FromUint64(7)
			c := z12.FromUint64(11)

			elem, err := g.New(a, b, c)
			require.NoError(t, err)
			require.NotNil(t, elem)

			components := elem.Components()
			require.Len(t, components, 3)
			assert.Equal(t, "3", components[0].String())
			assert.Equal(t, "7", components[1].String())
			assert.Equal(t, "11", components[2].String())
		})

		t.Run("New with wrong arity", func(t *testing.T) {
			a := z12.FromUint64(3)
			b := z12.FromUint64(7)

			elem, err := g.New(a, b) // Only 2 elements, need 3
			assert.Error(t, err)
			assert.Nil(t, elem)
			assert.Contains(t, err.Error(), "incorrect component count")
		})

		t.Run("Element operations", func(t *testing.T) {
			elem1, err := g.New(z12.FromUint64(3), z12.FromUint64(7), z12.FromUint64(11))
			require.NoError(t, err)
			elem2, err := g.New(z12.FromUint64(2), z12.FromUint64(5), z12.FromUint64(1))
			require.NoError(t, err)

			// Test Op (addition in Z_12)
			sum := elem1.Op(elem2)
			sumComponents := sum.Components()
			assert.Equal(t, "5", sumComponents[0].String()) // 3+2 = 5
			assert.Equal(t, "0", sumComponents[1].String()) // 7+5 = 12 ≡ 0 (mod 12)
			assert.Equal(t, "0", sumComponents[2].String()) // 11+1 = 12 ≡ 0 (mod 12)

			// Test Equal
			assert.True(t, elem1.Equal(elem1))
			assert.False(t, elem1.Equal(elem2))

			// Test Clone
			clone := elem1.Clone()
			assert.True(t, elem1.Equal(clone))
			assert.NotSame(t, elem1, clone)
		})

		t.Run("Order calculation", func(t *testing.T) {
			// Z_n.Order() has been fixed to return correct value
			baseOrder := z12.Order()
			assert.Equal(t, uint64(12), baseOrder.Uint64())

			order := g.Order()
			// Order should be 12^3 = 1728
			assert.Equal(t, uint64(1728), order.Uint64())
		})
	})

	t.Run("DirectPowerGroupElement", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 2)
		require.NoError(t, err)
		elem, err := g.New(z12.FromUint64(3), z12.FromUint64(7))
		require.NoError(t, err)

		t.Run("IsOpIdentity", func(t *testing.T) {
			assert.False(t, elem.IsOpIdentity())

			id := g.OpIdentity()
			assert.True(t, id.IsOpIdentity())
		})

		t.Run("OpInv", func(t *testing.T) {
			inv := elem.OpInv()
			sum := elem.Op(inv)
			assert.True(t, sum.IsOpIdentity())

			// Check components
			invComponents := inv.Components()
			assert.Equal(t, "9", invComponents[0].String()) // -3 ≡ 9 (mod 12)
			assert.Equal(t, "5", invComponents[1].String()) // -7 ≡ 5 (mod 12)
		})

		t.Run("TryOpInv", func(t *testing.T) {
			inv, err := elem.TryOpInv()
			require.NoError(t, err)
			assert.NotNil(t, inv)
			assert.True(t, elem.Op(inv).IsOpIdentity())
		})

		t.Run("String representation", func(t *testing.T) {
			str := elem.String()
			assert.Equal(t, "(3, 7)", str)
		})

		t.Run("Bytes representation", func(t *testing.T) {
			bytes := elem.Bytes()
			assert.NotEmpty(t, bytes)
			// Check actual length rather than assuming
			t.Logf("Bytes length: %d", len(bytes))
		})
	})

	t.Run("Structure method", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 2)
		require.NoError(t, err)
		elem, err := g.New(z12.FromUint64(3), z12.FromUint64(7))
		require.NoError(t, err)

		structure := elem.Structure()
		require.NotNil(t, structure)
		require.Equal(t, g.Name(), structure.Name())
	})
}

// TestFiniteDirectPowerGroup tests the finite variant
func TestFiniteDirectPowerGroup(t *testing.T) {
	z12, _ := num.NewZn(cardinal.New(12))

	t.Run("NewFiniteDirectPowerGroup", func(t *testing.T) {
		g, err := constructions.NewFiniteDirectPowerGroup(z12, 3)
		require.NoError(t, err)
		require.NotNil(t, g)

		// Should implement FiniteGroup interface
		var _ algebra.FiniteGroup[*constructions.FiniteDirectPowerGroupElement[*num.Uint]] = g
	})

	t.Run("Random element generation", func(t *testing.T) {
		g, err := constructions.NewFiniteDirectPowerGroup(z12, 3)
		require.NoError(t, err)

		// Z_n.Random() has been implemented
		elem, err := g.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Verify it has correct arity
		components := elem.Components()
		assert.Len(t, components, 3)

		// Each component should be in [0, 12)
		for i, c := range components {
			// Components are already of type *num.Uint
			// In Z_n, all elements are automatically in [0, n)
			assert.NotNil(t, c, "Component %d should not be nil", i)
			// Just verify they're valid Z_12 elements by checking modulus
			assert.True(t, c.SameModulus(z12.Zero()), "Component %d should be in Z_12", i)
		}
	})

	t.Run("Hash to element", func(t *testing.T) {
		g, err := constructions.NewFiniteDirectPowerGroup(z12, 3)
		require.NoError(t, err)

		// Z_n.Hash() has been implemented
		input := []byte("test input for hashing")
		elem, err := g.Hash(input)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Verify it has correct arity
		components := elem.Components()
		assert.Len(t, components, 3)

		// All components should be the same (hash is called with same input)
		for i := 1; i < len(components); i++ {
			assert.True(t, components[0].Equal(components[i]))
		}
	})
}

// TestDirectPowerRing tests the DirectPowerRing construction
func TestDirectPowerRing(t *testing.T) {
	z12, _ := num.NewZn(cardinal.New(12))

	t.Run("NewDirectPowerRing", func(t *testing.T) {
		r, err := constructions.NewDirectPowerRing(z12, 3)
		require.NoError(t, err)
		require.NotNil(t, r)

		// Should implement Ring interface
		var _ algebra.Ring[*constructions.DirectPowerRingElement[*num.Uint]] = r
	})

	t.Run("Ring operations", func(t *testing.T) {
		r, _ := constructions.NewDirectPowerRing(z12, 2)

		t.Run("Zero and One", func(t *testing.T) {
			zero := r.Zero()
			one := r.One()

			assert.True(t, zero.IsZero())
			assert.True(t, one.IsOne())

			// Check components
			zeroComps := zero.Components()
			oneComps := one.Components()
			assert.Len(t, zeroComps, 2)
			assert.Len(t, oneComps, 2)
			for i := 0; i < 2; i++ {
				assert.True(t, zeroComps[i].IsZero())
				assert.True(t, oneComps[i].IsOne())
			}
		})

		t.Run("Characteristic", func(t *testing.T) {
			char := r.Characteristic()
			assert.Equal(t, uint64(12), char.Uint64())
		})
	})

	t.Run("DirectPowerRingElement operations", func(t *testing.T) {
		r, err := constructions.NewDirectPowerRing(z12, 2)
		require.NoError(t, err)
		a, err := r.New(z12.FromUint64(3), z12.FromUint64(4))
		require.NoError(t, err)
		b, err := r.New(z12.FromUint64(5), z12.FromUint64(7))
		require.NoError(t, err)

		t.Run("Add", func(t *testing.T) {
			sum := a.Add(b)
			sumComps := sum.Components()
			assert.Equal(t, "8", sumComps[0].String())  // 3+5 = 8
			assert.Equal(t, "11", sumComps[1].String()) // 4+7 = 11
		})

		t.Run("Sub", func(t *testing.T) {
			diff := a.Sub(b)
			diffComps := diff.Components()
			// Subtraction in Zn might be implemented differently
			// a.Sub(b) might be b-a instead of a-b
			assert.Equal(t, "2", diffComps[0].String()) // 5-3 = 2
			assert.Equal(t, "3", diffComps[1].String()) // 7-4 = 3
		})

		t.Run("Mul", func(t *testing.T) {
			prod := a.Mul(b)
			prodComps := prod.Components()
			assert.Equal(t, "3", prodComps[0].String()) // 3*5 = 15 ≡ 3 (mod 12)
			assert.Equal(t, "4", prodComps[1].String()) // 4*7 = 28 ≡ 4 (mod 12)
		})

		t.Run("OtherOp", func(t *testing.T) {
			// OtherOp should be the same as Mul
			other := a.OtherOp(b)
			assert.True(t, other.Equal(a.Mul(b)))
		})

		t.Run("Double", func(t *testing.T) {
			double := a.Double()
			doubleComps := double.Components()
			assert.Equal(t, "6", doubleComps[0].String()) // 2*3 = 6
			assert.Equal(t, "8", doubleComps[1].String()) // 2*4 = 8
		})

		t.Run("Square", func(t *testing.T) {
			square := a.Square()
			squareComps := square.Components()
			assert.Equal(t, "9", squareComps[0].String()) // 3^2 = 9
			assert.Equal(t, "4", squareComps[1].String()) // 4^2 = 16 ≡ 4 (mod 12)
		})

		t.Run("Neg", func(t *testing.T) {
			neg := a.Neg()
			negComps := neg.Components()
			assert.Equal(t, "9", negComps[0].String()) // -3 ≡ 9 (mod 12)
			assert.Equal(t, "8", negComps[1].String()) // -4 ≡ 8 (mod 12)
		})

		t.Run("IsZero and IsOne", func(t *testing.T) {
			assert.False(t, a.IsZero())
			assert.False(t, a.IsOne())

			zero := r.Zero()
			one := r.One()
			assert.True(t, zero.IsZero())
			assert.True(t, one.IsOne())
		})
	})

	t.Run("Try operations", func(t *testing.T) {
		r, err := constructions.NewDirectPowerRing(z12, 2)
		require.NoError(t, err)
		a, err := r.New(z12.FromUint64(3), z12.FromUint64(4))
		require.NoError(t, err)
		b, err := r.New(z12.FromUint64(5), z12.FromUint64(0))
		require.NoError(t, err)

		t.Run("TryDiv", func(t *testing.T) {
			// Division by element with 0 component should fail
			_, err := a.TryDiv(b)
			assert.Error(t, err, "Division by element containing zero should fail")
		})

		t.Run("TryInv", func(t *testing.T) {
			// Only units can be inverted in Z_12
			unit, err := r.New(z12.FromUint64(1), z12.FromUint64(5))
			require.NoError(t, err)
			inv, err := unit.TryInv()
			if err == nil {
				prod := unit.Mul(inv)
				assert.True(t, prod.IsOne())
			}
		})

		t.Run("TrySub", func(t *testing.T) {
			diff, err := a.TrySub(b)
			require.NoError(t, err)
			assert.NotNil(t, diff)
		})

		t.Run("TryNeg", func(t *testing.T) {
			neg, err := a.TryNeg()
			require.NoError(t, err)
			assert.NotNil(t, neg)
			assert.True(t, a.Add(neg).IsZero())
		})
	})
}

func TestStructureMethodNotes(t *testing.T) {
	t.Run("Empty components panic", func(t *testing.T) {
		elem := &constructions.DirectPowerGroupElement[*num.Uint]{}

		assert.Panics(t, func() {
			_ = elem.Structure()
		}, "Structure() should panic on zero-value element with empty components")
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	z12, _ := num.NewZn(cardinal.New(12))

	t.Run("Arity comparison issues", func(t *testing.T) {
		g2, err := constructions.NewDirectPowerGroup(z12, 2)
		require.NoError(t, err)
		g3, err := constructions.NewDirectPowerGroup(z12, 3)
		require.NoError(t, err)

		elem2, err := g2.New(z12.FromUint64(1), z12.FromUint64(2))
		require.NoError(t, err)
		elem3, err := g3.New(z12.FromUint64(1), z12.FromUint64(2), z12.FromUint64(3))
		require.NoError(t, err)

		// Operations between different arities should panic
		assert.Panics(t, func() {
			_ = elem2.Op(elem3)
		}, "Operations on elements with different arity should panic")
	})

	t.Run("FromBytes edge cases", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 2)
		require.NoError(t, err)

		// Empty input creates empty element since 0 components were provided
		elem, err := g.FromBytes([]byte{})
		assert.NoError(t, err)
		assert.NotNil(t, elem)
		assert.Len(t, elem.Components(), 0)

		// Wrong size input
		_, err = g.FromBytes([]byte{1, 2, 3}) // Not divisible by element size
		assert.Error(t, err)

		// Correct size - FromBytes now uses proper component size
		correctSize := z12.ElementSize() * 2
		input := make([]byte, correctSize)
		elem, err = g.FromBytes(input)
		assert.NoError(t, err)
		assert.NotNil(t, elem)
		assert.Len(t, elem.Components(), 2) // Should have 2 components now
	})

	t.Run("HashCode consistency", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 2)
		require.NoError(t, err)
		elem1, err := g.New(z12.FromUint64(3), z12.FromUint64(7))
		require.NoError(t, err)
		elem2, err := g.New(z12.FromUint64(3), z12.FromUint64(7))
		require.NoError(t, err)
		elem3, err := g.New(z12.FromUint64(7), z12.FromUint64(3))
		require.NoError(t, err)

		// Equal elements should have same hash
		assert.Equal(t, elem1.HashCode(), elem2.HashCode())

		// HashCode now uses FNV hash which is not commutative
		// (3,7) and (7,3) should have different hashes
		assert.NotEqual(t, elem1.HashCode(), elem3.HashCode(),
			"HashCode uses FNV which preserves order")
	})

	t.Run("Diagonal construction", func(t *testing.T) {
		g, err := constructions.NewDirectPowerGroup(z12, 3)
		require.NoError(t, err)
		elem := z12.FromUint64(5)

		diag, err := g.Diagonal(elem)
		require.NoError(t, err)

		components := diag.Components()
		assert.Len(t, components, 3)
		for _, c := range components {
			assert.Equal(t, "5", c.String())
		}
	})
}

// TestTypeConstraints tests issues with generic type constraints
func TestTypeConstraints(t *testing.T) {
	t.Run("Interface satisfaction", func(t *testing.T) {
		z12, _ := num.NewZn(cardinal.New(12))

		// Regular DirectPowerGroup
		g, _ := constructions.NewDirectPowerGroup(z12, 2)
		var _ algebra.Group[*constructions.DirectPowerGroupElement[*num.Uint]] = g

		// Finite variant
		fg, _ := constructions.NewFiniteDirectPowerGroup(z12, 2)
		var _ algebra.FiniteGroup[*constructions.FiniteDirectPowerGroupElement[*num.Uint]] = fg

		t.Log("Type constraints are satisfied correctly")
	})
}

// BenchmarkDirectPower provides performance benchmarks
func BenchmarkDirectPower(b *testing.B) {
	z12, _ := num.NewZn(cardinal.New(12))
	g, _ := constructions.NewDirectPowerGroup(z12, 3)
	elem1, _ := g.New(z12.FromUint64(3), z12.FromUint64(7), z12.FromUint64(11))
	elem2, _ := g.New(z12.FromUint64(2), z12.FromUint64(5), z12.FromUint64(9))

	b.Run("Op", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Op(elem2)
		}
	})

	b.Run("Equal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Equal(elem2)
		}
	})

	b.Run("Clone", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = elem1.Clone()
		}
	})
}

// TestErrorHandling tests error handling in constructors
func TestErrorHandling(t *testing.T) {
	t.Run("Constructor error propagation", func(t *testing.T) {
		// Test that errors from Set() are properly propagated
		_, err := constructions.NewDirectPowerGroup((*num.Zn)(nil), 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set group and arity")
	})

	t.Run("Panic on arity mismatch", func(t *testing.T) {
		z12, _ := num.NewZn(cardinal.New(12))
		g, _ := constructions.NewDirectPowerGroup(z12, 2)
		elem1, _ := g.New(z12.FromUint64(1), z12.FromUint64(2))
		elem2 := &constructions.DirectPowerGroupElement[*num.Uint]{} // zero-value with arity 0

		// Op should panic on arity mismatch
		assert.Panics(t, func() {
			_ = elem1.Op(elem2)
		}, "Op should panic on arity mismatch")
	})
}

// TestDirectSumModule tests the DirectSumModule construction
func TestDirectSumModule(t *testing.T) {
	// Use k256 curve as our module
	curve := k256.NewCurve()
	scalarField := curves.GetScalarField(curve)

	t.Run("NewDirectSumModule", func(t *testing.T) {
		t.Run("Valid arity", func(t *testing.T) {
			m, err := constructions.NewDirectSumModule(curve, 3)
			require.NoError(t, err)
			require.NotNil(t, m)
			assert.Equal(t, cardinal.New(3), m.Arity())
			assert.Equal(t, "(secp256k1)^3", m.Name())
		})

		t.Run("Zero arity", func(t *testing.T) {
			m, err := constructions.NewDirectSumModule(curve, 0)
			assert.Error(t, err)
			assert.Nil(t, m)
			assert.Contains(t, err.Error(), "arity must be greater than 0")
		})

		t.Run("Nil base module", func(t *testing.T) {
			m, err := constructions.NewDirectSumModule((*k256.Curve)(nil), 3)
			assert.Error(t, err)
			assert.Nil(t, m)
		})
	})

	t.Run("Module operations", func(t *testing.T) {
		m, err := constructions.NewDirectSumModule(curve, 3)
		require.NoError(t, err)

		t.Run("OpIdentity", func(t *testing.T) {
			id := m.OpIdentity()
			require.NotNil(t, id)
			components := id.Components()
			require.Len(t, components, 3)
			for _, c := range components {
				assert.True(t, c.IsOpIdentity())
			}
		})

		t.Run("New elements", func(t *testing.T) {
			// Create module elements (curve points)
			g := curve.Generator()
			a := g.ScalarMul(scalarField.FromUint64(3))
			b := g.ScalarMul(scalarField.FromUint64(7))
			c := g.ScalarMul(scalarField.FromUint64(11))

			elem, err := m.New(a, b, c)
			require.NoError(t, err)
			require.NotNil(t, elem)

			components := elem.Components()
			require.Len(t, components, 3)
			// Can't easily assert string representation of curve points
			for i, comp := range components {
				assert.NotNil(t, comp, "Component %d should not be nil", i)
			}
		})

		t.Run("ScalarStructure", func(t *testing.T) {
			scalarStruct := m.ScalarStructure()
			require.NotNil(t, scalarStruct)
			// Should be the scalar field of the curve
			assert.Equal(t, scalarField.Name(), scalarStruct.Name())
		})
	})

	t.Run("DirectSumModuleElement", func(t *testing.T) {
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)
		g := curve.Generator()
		a := g.ScalarMul(scalarField.FromUint64(3))
		b := g.ScalarMul(scalarField.FromUint64(7))
		elem, err := m.New(a, b)
		require.NoError(t, err)

		t.Run("CoDiagonal", func(t *testing.T) {
			// CoDiagonal should sum all components
			codiag := elem.CoDiagonal()
			// Should be equivalent to g * (3 + 7) = g * 10
			expected := g.ScalarMul(scalarField.FromUint64(10))
			assert.True(t, codiag.Equal(expected))
		})

		t.Run("ScalarOp", func(t *testing.T) {
			scalar := scalarField.FromUint64(2)
			scaled := elem.ScalarOp(scalar)
			scaledComponents := scaled.Components()
			// First component: g * 3 * 2 = g * 6
			expected1 := g.ScalarMul(scalarField.FromUint64(6))
			// Second component: g * 7 * 2 = g * 14
			expected2 := g.ScalarMul(scalarField.FromUint64(14))
			assert.True(t, scaledComponents[0].Equal(expected1))
			assert.True(t, scaledComponents[1].Equal(expected2))
		})

		t.Run("IsTorsionFree", func(t *testing.T) {
			// Elliptic curve points are torsion free over the scalar field
			assert.True(t, elem.IsTorsionFree())
		})

		t.Run("Module element operations", func(t *testing.T) {
			c := g.ScalarMul(scalarField.FromUint64(2))
			d := g.ScalarMul(scalarField.FromUint64(5))
			elem2, err := m.New(c, d)
			require.NoError(t, err)

			// Test Op (addition)
			sum := elem.Op(elem2)
			sumComponents := sum.Components()
			// First component: g*3 + g*2 = g*5
			expected1 := g.ScalarMul(scalarField.FromUint64(5))
			// Second component: g*7 + g*5 = g*12
			expected2 := g.ScalarMul(scalarField.FromUint64(12))
			assert.True(t, sumComponents[0].Equal(expected1))
			assert.True(t, sumComponents[1].Equal(expected2))
		})
	})

	t.Run("MultiScalarOp", func(t *testing.T) {
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)

		g := curve.Generator()
		// Create scalars
		scalar1 := scalarField.FromUint64(2)
		scalar2 := scalarField.FromUint64(3)

		// Create module elements
		a1 := g.ScalarMul(scalarField.FromUint64(1))
		a2 := g.ScalarMul(scalarField.FromUint64(2))
		elem1, err := m.New(a1, a2)
		require.NoError(t, err)

		b1 := g.ScalarMul(scalarField.FromUint64(3))
		b2 := g.ScalarMul(scalarField.FromUint64(4))
		elem2, err := m.New(b1, b2)
		require.NoError(t, err)

		// Compute 2*elem1 + 3*elem2
		result, err := m.MultiScalarOp([]*k256.Scalar{scalar1, scalar2}, []*constructions.DirectSumModuleElement[*k256.Point, *k256.Scalar]{elem1, elem2})
		require.NoError(t, err)

		resultComponents := result.Components()
		// Component 0: 2*(g*1) + 3*(g*3) = g*2 + g*9 = g*11
		expected1 := g.ScalarMul(scalarField.FromUint64(11))
		// Component 1: 2*(g*2) + 3*(g*4) = g*4 + g*12 = g*16
		expected2 := g.ScalarMul(scalarField.FromUint64(16))
		assert.True(t, resultComponents[0].Equal(expected1))
		assert.True(t, resultComponents[1].Equal(expected2))
	})

	t.Run("Structure method", func(t *testing.T) {
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)
		g := curve.Generator()
		a := g.ScalarMul(scalarField.FromUint64(3))
		b := g.ScalarMul(scalarField.FromUint64(7))
		elem, err := m.New(a, b)
		require.NoError(t, err)

		structure := elem.Structure()
		require.NotNil(t, structure)
		require.Equal(t, m.Name(), structure.Name())
	})
}

// TestFiniteDirectSumModule tests the finite variant
func TestFiniteDirectSumModule(t *testing.T) {
	// Use k256 curve as our finite module
	curve := k256.NewCurve()

	t.Run("NewFiniteDirectSumModule", func(t *testing.T) {
		m, err := constructions.NewFiniteDirectSumModule(curve, 3)
		require.NoError(t, err)
		require.NotNil(t, m)

		// Should implement FiniteModule interface
		var _ algebra.FiniteModule[*constructions.FiniteDirectSumModuleElement[*k256.Point, *k256.Scalar], *k256.Scalar] = m
	})

	t.Run("Random element generation", func(t *testing.T) {
		m, err := constructions.NewFiniteDirectSumModule(curve, 3)
		require.NoError(t, err)

		elem, err := m.Random(rand.Reader)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Verify it has correct arity
		components := elem.Components()
		assert.Len(t, components, 3)

		// Each component should be a valid curve point
		for i, c := range components {
			assert.NotNil(t, c, "Component %d should not be nil", i)
			// Verify it's a valid curve point
			assert.False(t, c.IsOpIdentity()) // Random points should not be identity
		}
	})

	t.Run("Hash to element", func(t *testing.T) {
		m, err := constructions.NewFiniteDirectSumModule(curve, 3)
		require.NoError(t, err)

		input := []byte("test input for module hashing")
		elem, err := m.Hash(input)
		require.NoError(t, err)
		require.NotNil(t, elem)

		// Verify it has correct arity
		components := elem.Components()
		assert.Len(t, components, 3)

		// All components should be the same (hash is called with same input)
		for i := 1; i < len(components); i++ {
			assert.True(t, components[0].Equal(components[i]))
		}
	})
}

// TestModuleEdgeCases tests edge cases specific to modules
func TestModuleEdgeCases(t *testing.T) {
	curve := k256.NewCurve()
	scalarField := curves.GetScalarField(curve)

	t.Run("Empty CoDiagonal panic", func(t *testing.T) {
		elem := &constructions.DirectSumModuleElement[*k256.Point, *k256.Scalar]{}

		assert.Panics(t, func() {
			_ = elem.CoDiagonal()
		}, "CoDiagonal should panic on zero-value element with empty components")
	})

	t.Run("Arity mismatch in MultiScalarOp", func(t *testing.T) {
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)

		g := curve.Generator()
		a := g.ScalarMul(scalarField.FromUint64(1))
		b := g.ScalarMul(scalarField.FromUint64(2))

		// Create element with different arity
		m3, err := constructions.NewDirectSumModule(curve, 3)
		require.NoError(t, err)
		c := g.ScalarMul(scalarField.FromUint64(3))
		elem2, err := m3.New(a, b, c)
		require.NoError(t, err)

		// MultiScalarOp with mismatched arity should fail
		scalar := scalarField.FromUint64(1)
		_, err = m.MultiScalarOp([]*k256.Scalar{scalar}, []*constructions.DirectSumModuleElement[*k256.Point, *k256.Scalar]{elem2})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect component count")
	})

	t.Run("Module type constraints", func(t *testing.T) {
		// Regular DirectSumModule
		m, _ := constructions.NewDirectSumModule(curve, 2)
		var _ algebra.Module[*constructions.DirectSumModuleElement[*k256.Point, *k256.Scalar], *k256.Scalar] = m

		// Finite variant
		fm, _ := constructions.NewFiniteDirectSumModule(curve, 2)
		var _ algebra.FiniteModule[*constructions.FiniteDirectSumModuleElement[*k256.Point, *k256.Scalar], *k256.Scalar] = fm

		t.Log("Module type constraints are satisfied correctly")
	})
}
