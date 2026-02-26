package constructions_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/stretchr/testify/require"
)

// TestFieldUnitSubGroup tests the FieldUnitSubGroup construction
func TestFieldUnitSubGroup(t *testing.T) {
	// Use k256 scalar field as our base field for testing
	scalarField := k256.NewScalarField()

	t.Run("NewFieldUnitSubGroup", func(t *testing.T) {
		t.Parallel()
		t.Run("Valid field", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFieldUnitSubGroup(scalarField)
			require.NoError(t, err)
			require.NotNil(t, g)
			require.Equal(t, "U(secp256k1Fq)", g.Name())
		})

		t.Run("Nil field", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFieldUnitSubGroup((*k256.ScalarField)(nil))
			require.Error(t, err)
			require.Nil(t, g)
			require.Contains(t, err.Error(), "field is nil")
		})
	})

	t.Run("Group properties", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)

		t.Run("OpIdentity", func(t *testing.T) {
			t.Parallel()
			id := g.OpIdentity()
			require.NotNil(t, id)
			require.True(t, id.IsOpIdentity())
			require.True(t, id.IsOne())
			require.Equal(t, "U(1)", id.String())
		})

		t.Run("One", func(t *testing.T) {
			t.Parallel()
			one := g.One()
			require.NotNil(t, one)
			require.True(t, one.IsOne())
			require.True(t, one.IsOpIdentity())
		})

		t.Run("ElementSize", func(t *testing.T) {
			t.Parallel()
			// Should match the field's element size
			require.Equal(t, scalarField.ElementSize(), g.ElementSize())
		})

		t.Run("Order", func(t *testing.T) {
			t.Parallel()
			order := g.Order()
			// Field order - 1 (excluding zero)
			fieldOrder := scalarField.Order()
			fieldOrderKnown, ok := fieldOrder.(cardinal.Known)
			require.True(t, ok, "field order should be known")
			expectedOrder := fieldOrderKnown.Sub(cardinal.New(1))
			require.Equal(t, expectedOrder, order)
			require.True(t, order.IsFinite())
		})
	})

	t.Run("New elements", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)

		t.Run("Valid unit element", func(t *testing.T) {
			t.Parallel()
			elem, err := g.New(scalarField.FromUint64(5))
			require.NoError(t, err)
			require.NotNil(t, elem)
			require.Equal(t, "U(5)", elem.String())
		})

		t.Run("Zero element", func(t *testing.T) {
			t.Parallel()
			elem, err := g.New(scalarField.Zero())
			require.Error(t, err)
			require.Nil(t, elem)
			require.Contains(t, err.Error(), "argument is zero")
		})

		t.Run("FromBytes", func(t *testing.T) {
			t.Parallel()
			// Create a valid unit element
			original := scalarField.FromUint64(7)
			bytes := original.Bytes()

			elem, err := g.FromBytes(bytes)
			require.NoError(t, err)
			require.NotNil(t, elem)
			require.Equal(t, "U(7)", elem.String())
		})

		t.Run("FromBytes with zero", func(t *testing.T) {
			t.Parallel()
			// Zero bytes should fail
			bytes := scalarField.Zero().Bytes()
			elem, err := g.FromBytes(bytes)
			require.Error(t, err)
			require.Nil(t, elem)
			require.Contains(t, err.Error(), "argument is zero")
		})

		t.Run("FromBytes with invalid data", func(t *testing.T) {
			t.Parallel()
			// Invalid bytes should fail at field level
			elem, err := g.FromBytes([]byte{0xFF, 0xFF, 0xFF})
			require.Error(t, err)
			require.Nil(t, elem)
		})
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)

		elem1, err := g.New(scalarField.FromUint64(3))
		require.NoError(t, err)
		elem2, err := g.New(scalarField.FromUint64(4))
		require.NoError(t, err)

		t.Run("Op (multiplication)", func(t *testing.T) {
			t.Parallel()
			result := elem1.Op(elem2)
			// 3 * 4 = 12
			expected := scalarField.FromUint64(12)
			require.True(t, result.FieldElement().Equal(expected))
		})

		t.Run("Mul", func(t *testing.T) {
			t.Parallel()
			result := elem1.Mul(elem2)
			expected := scalarField.FromUint64(12)
			require.True(t, result.FieldElement().Equal(expected))
			// Op should be the same as Mul
			require.True(t, result.Equal(elem1.Op(elem2)))
		})

		t.Run("Square", func(t *testing.T) {
			t.Parallel()
			square := elem1.Square()
			// 3^2 = 9
			expected := scalarField.FromUint64(9)
			require.True(t, square.FieldElement().Equal(expected))
		})

		t.Run("Equal", func(t *testing.T) {
			t.Parallel()
			require.True(t, elem1.Equal(elem1))
			require.False(t, elem1.Equal(elem2))

			// Create another element with same value
			elem3, err := g.New(scalarField.FromUint64(3))
			require.NoError(t, err)
			require.True(t, elem1.Equal(elem3))
		})

		t.Run("Clone", func(t *testing.T) {
			t.Parallel()
			clone := elem1.Clone()
			require.True(t, elem1.Equal(clone))
			require.NotSame(t, elem1, clone)
		})

		t.Run("HashCode", func(t *testing.T) {
			t.Parallel()
			// Equal elements should have same hash
			elem3, err := g.New(scalarField.FromUint64(3))
			require.NoError(t, err)
			require.Equal(t, elem1.HashCode(), elem3.HashCode())

			// Different elements should (likely) have different hashes
			require.NotEqual(t, elem1.HashCode(), elem2.HashCode())
		})

		t.Run("Bytes", func(t *testing.T) {
			t.Parallel()
			bytes := elem1.Bytes()
			require.NotEmpty(t, bytes)
			// Should be same as field element bytes
			require.Equal(t, elem1.FieldElement().Bytes(), bytes)
		})

		t.Run("IsOpIdentity", func(t *testing.T) {
			t.Parallel()
			require.False(t, elem1.IsOpIdentity())
			one := g.One()
			require.True(t, one.IsOpIdentity())
		})

		t.Run("IsOne", func(t *testing.T) {
			t.Parallel()
			require.False(t, elem1.IsOne())
			one := g.One()
			require.True(t, one.IsOne())
		})

		t.Run("Order", func(t *testing.T) {
			t.Parallel()
			order := elem1.Order()
			// Element order should be same as group order for prime fields
			groupOrder := g.Order()
			require.Equal(t, groupOrder, order)
		})
	})

	t.Run("Inverse operations", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)

		elem, err := g.New(scalarField.FromUint64(5))
		require.NoError(t, err)
		one, err := g.New(scalarField.FromUint64(1))
		require.NoError(t, err)

		t.Run("OpInv", func(t *testing.T) {
			t.Parallel()
			inv := elem.OpInv()
			result := elem.Op(inv)
			require.True(t, result.IsOpIdentity())
		})

		t.Run("TryOpInv", func(t *testing.T) {
			t.Parallel()
			inv, err := elem.TryOpInv()
			require.NoError(t, err)
			require.NotNil(t, inv)
			require.True(t, elem.Op(inv).IsOpIdentity())
		})

		t.Run("Inv", func(t *testing.T) {
			t.Parallel()
			inv := elem.Inv()
			result := elem.Mul(inv)
			require.True(t, result.IsOne())
			require.True(t, one.Inv().IsOne())
		})

		t.Run("TryInv", func(t *testing.T) {
			t.Parallel()
			inv, err := elem.TryInv()
			require.NoError(t, err)
			require.NotNil(t, inv)
			require.True(t, elem.Mul(inv).IsOne())
		})
	})

	t.Run("Division operations", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)

		elem1, err := g.New(scalarField.FromUint64(6))
		require.NoError(t, err)
		elem2, err := g.New(scalarField.FromUint64(2))
		require.NoError(t, err)

		t.Run("Div", func(t *testing.T) {
			t.Parallel()
			result := elem1.Div(elem2)
			// 6 / 2 = 3
			expected := scalarField.FromUint64(3)
			require.True(t, result.FieldElement().Equal(expected))
			// Verify: result * elem2 = elem1
			require.True(t, result.Mul(elem2).Equal(elem1))
		})

		t.Run("TryDiv", func(t *testing.T) {
			t.Parallel()
			result, err := elem1.TryDiv(elem2)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.True(t, result.Mul(elem2).Equal(elem1))
		})
	})

	t.Run("Structure method", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)
		elem, err := g.New(scalarField.FromUint64(5))
		require.NoError(t, err)

		structure := elem.Structure()
		require.NotNil(t, structure)
		require.Equal(t, g.Name(), structure.Name())
	})

	t.Run("FieldElement access", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)
		fe := scalarField.FromUint64(7)
		elem, err := g.New(fe)
		require.NoError(t, err)

		require.True(t, elem.FieldElement().Equal(fe))
	})
}

// TestFieldUnitSubGroupWithDifferentFields tests with various field implementations
func TestFieldUnitSubGroupWithDifferentFields(t *testing.T) {
	t.Parallel()
	t.Run("K256 scalar field", func(t *testing.T) {
		t.Parallel()
		scalarField := k256.NewScalarField()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)
		require.Equal(t, "U(secp256k1Fq)", g.Name())

		// Test basic operations
		elem1, _ := g.New(scalarField.FromUint64(12345))
		elem2, _ := g.New(scalarField.FromUint64(67890))
		result := elem1.Mul(elem2)
		require.NotNil(t, result)
	})

	t.Run("P256 scalar field", func(t *testing.T) {
		t.Parallel()
		scalarField := p256.NewScalarField()
		g, err := constructions.NewFieldUnitSubGroup(scalarField)
		require.NoError(t, err)
		require.Equal(t, "U(P256Fq)", g.Name())

		// Test basic operations
		elem, _ := g.New(scalarField.FromUint64(999))
		inv := elem.Inv()
		require.True(t, elem.Mul(inv).IsOne())
	})

	t.Run("Edwards25519 base field", func(t *testing.T) {
		t.Parallel()
		baseField := edwards25519.NewBaseField()
		g, err := constructions.NewFieldUnitSubGroup(baseField)
		require.NoError(t, err)
		require.Equal(t, "U(curve25519Fp)", g.Name())

		// Test squaring
		elem, _ := g.New(baseField.FromUint64(2))
		square := elem.Square()
		expected := baseField.FromUint64(4)
		require.True(t, square.FieldElement().Equal(expected))
	})
}

// TestFieldUnitSubGroupEdgeCases tests edge cases
func TestFieldUnitSubGroupEdgeCases(t *testing.T) {
	t.Parallel()
	scalarField := edwards25519.NewScalarField()
	g, _ := constructions.NewFieldUnitSubGroup(scalarField)

	t.Run("Identity self-operations", func(t *testing.T) {
		t.Parallel()
		one := g.One()

		// Identity operations
		require.True(t, one.Mul(one).IsOne())
		require.True(t, one.Square().IsOne())
		require.True(t, one.Inv().IsOne())
		require.True(t, one.OpInv().IsOne())
	})

	t.Run("Large values", func(t *testing.T) {
		t.Parallel()
		// Test with large values close to field modulus
		largeVal := scalarField.FromUint64(0xFFFFFFFFFFFFFFF)
		elem, err := g.New(largeVal)
		require.NoError(t, err)

		// Verify operations work correctly
		inv := elem.Inv()
		require.True(t, elem.Mul(inv).IsOne())
	})

	t.Run("Chain operations", func(t *testing.T) {
		t.Parallel()
		elem, _ := g.New(scalarField.FromUint64(7))

		// Chain multiple operations
		result := elem.Square().Mul(elem).Inv().Mul(elem).Mul(elem)
		// (7^2 * 7)^(-1) * 7 * 7 = 7^3^(-1) * 7^2 = 7^(-1)
		expected := elem.Inv()
		require.True(t, result.Equal(expected))
	})
}
