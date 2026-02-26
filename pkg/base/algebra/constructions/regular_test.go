package constructions_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// =========== RegularAlgebra ===========

func TestRegularAlgebra(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("NewRegularAlgebra", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			a, err := constructions.NewRegularAlgebra(field)
			require.NoError(t, err)
			require.NotNil(t, a)
		})

		t.Run("Nil ring", func(t *testing.T) {
			t.Parallel()
			a, err := constructions.NewRegularAlgebra((*k256.ScalarField)(nil))
			require.Error(t, err)
			require.Nil(t, a)
			require.Contains(t, err.Error(), "ring is nil")
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)
		require.Equal(t, "RegularAlgebra[secp256k1Fq]", a.Name())
	})

	t.Run("Algebra properties", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		t.Run("Zero", func(t *testing.T) {
			t.Parallel()
			z := a.Zero()
			require.NotNil(t, z)
			require.True(t, z.IsZero())
			require.True(t, z.IsOpIdentity())
		})

		t.Run("One", func(t *testing.T) {
			t.Parallel()
			one := a.One()
			require.NotNil(t, one)
			require.True(t, one.IsOne())
		})

		t.Run("OpIdentity is Zero", func(t *testing.T) {
			t.Parallel()
			id := a.OpIdentity()
			require.True(t, id.IsZero())
		})

		t.Run("IsDomain", func(t *testing.T) {
			t.Parallel()
			// k256 scalar field is a field, so it's a domain
			require.True(t, a.IsDomain())
		})

		t.Run("Characteristic", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, field.Characteristic(), a.Characteristic())
		})

		t.Run("Order", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, field.Order(), a.Order())
		})

		t.Run("ScalarStructure", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, field.Name(), a.ScalarStructure().Name())
		})
	})

	t.Run("Element creation", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		t.Run("New", func(t *testing.T) {
			t.Parallel()
			elem, err := a.New(field.FromUint64(7))
			require.NoError(t, err)
			require.NotNil(t, elem)
			require.True(t, elem.Value().Equal(field.FromUint64(7)))
		})

		t.Run("FromBytes", func(t *testing.T) {
			t.Parallel()
			original := field.FromUint64(42)
			bytes := original.Bytes()

			elem, err := a.FromBytes(bytes)
			require.NoError(t, err)
			require.True(t, elem.Value().Equal(original))
		})
	})

	t.Run("Additive operations", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		e1, _ := a.New(field.FromUint64(5))
		e2, _ := a.New(field.FromUint64(3))

		t.Run("Add", func(t *testing.T) {
			t.Parallel()
			result := e1.Add(e2)
			require.True(t, result.Value().Equal(field.FromUint64(8)))
		})

		t.Run("Sub", func(t *testing.T) {
			t.Parallel()
			result := e1.Sub(e2)
			require.True(t, result.Value().Equal(field.FromUint64(2)))
		})

		t.Run("Neg", func(t *testing.T) {
			t.Parallel()
			neg := e1.Neg()
			result := e1.Add(neg)
			require.True(t, result.IsZero())
		})

		t.Run("Double", func(t *testing.T) {
			t.Parallel()
			dbl := e1.Double()
			require.True(t, dbl.Value().Equal(field.FromUint64(10)))
		})

		t.Run("Op is Add", func(t *testing.T) {
			t.Parallel()
			require.True(t, e1.Op(e2).Equal(e1.Add(e2)))
		})

		t.Run("OpInv is Neg", func(t *testing.T) {
			t.Parallel()
			result := e1.Op(e1.OpInv())
			require.True(t, result.IsOpIdentity())
		})
	})

	t.Run("Multiplicative operations", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		e1, _ := a.New(field.FromUint64(6))
		e2, _ := a.New(field.FromUint64(7))

		t.Run("Mul", func(t *testing.T) {
			t.Parallel()
			result := e1.Mul(e2)
			require.True(t, result.Value().Equal(field.FromUint64(42)))
		})

		t.Run("Square", func(t *testing.T) {
			t.Parallel()
			sq := e1.Square()
			require.True(t, sq.Value().Equal(field.FromUint64(36)))
		})

		t.Run("TryInv", func(t *testing.T) {
			t.Parallel()
			inv, err := e1.TryInv()
			require.NoError(t, err)
			require.True(t, e1.Mul(inv).IsOne())
		})

		t.Run("TryDiv", func(t *testing.T) {
			t.Parallel()
			quotient, err := e1.TryDiv(e2)
			require.NoError(t, err)
			require.True(t, quotient.Mul(e2).Equal(e1))
		})

		t.Run("Mul by One", func(t *testing.T) {
			t.Parallel()
			one, _ := a.New(field.One())
			require.True(t, e1.Mul(one).Equal(e1))
		})
	})

	t.Run("ScalarMul", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		elem, _ := a.New(field.FromUint64(5))
		scalar := field.FromUint64(3)

		// ScalarMul in a regular algebra is just ring multiplication
		result := elem.ScalarMul(scalar)
		require.True(t, result.Value().Equal(field.FromUint64(15)))
	})

	t.Run("IsTorsionFree", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		elem, _ := a.New(field.FromUint64(5))
		// A field is a domain, so regular algebra elements are torsion-free
		require.True(t, elem.IsTorsionFree())
	})

	t.Run("Element universal methods", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		e1, _ := a.New(field.FromUint64(5))
		e2, _ := a.New(field.FromUint64(7))

		t.Run("Equal", func(t *testing.T) {
			t.Parallel()
			same, _ := a.New(field.FromUint64(5))
			require.True(t, e1.Equal(same))
			require.False(t, e1.Equal(e2))
		})

		t.Run("Clone", func(t *testing.T) {
			t.Parallel()
			clone := e1.Clone()
			require.True(t, e1.Equal(clone))
			require.NotSame(t, e1, clone)
		})

		t.Run("HashCode", func(t *testing.T) {
			t.Parallel()
			same, _ := a.New(field.FromUint64(5))
			require.Equal(t, e1.HashCode(), same.HashCode())
			require.NotEqual(t, e1.HashCode(), e2.HashCode())
		})

		t.Run("Bytes round-trip", func(t *testing.T) {
			t.Parallel()
			bytes := e1.Bytes()
			restored, err := a.FromBytes(bytes)
			require.NoError(t, err)
			require.True(t, e1.Equal(restored))
		})

		t.Run("String", func(t *testing.T) {
			t.Parallel()
			s := e1.String()
			require.NotEmpty(t, s)
		})
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewRegularAlgebra(field)
		require.NoError(t, err)

		elem, _ := a.New(field.FromUint64(5))
		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, a.Name(), s.Name())
	})
}

// =========== FiniteRegularAlgebra ===========

func TestFiniteRegularAlgebra(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("NewFiniteRegularAlgebra", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			a, err := constructions.NewFiniteRegularAlgebra(field)
			require.NoError(t, err)
			require.NotNil(t, a)
		})

		t.Run("Nil ring", func(t *testing.T) {
			t.Parallel()
			a, err := constructions.NewFiniteRegularAlgebra((*k256.ScalarField)(nil))
			require.Error(t, err)
			require.Nil(t, a)
			require.Contains(t, err.Error(), "ring is nil")
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewFiniteRegularAlgebra(field)
		require.NoError(t, err)
		require.Equal(t, "RegularAlgebra[secp256k1Fq]", a.Name())
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewFiniteRegularAlgebra(field)
		require.NoError(t, err)

		prng := pcg.NewRandomised()
		elem1, err := a.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem1)

		elem2, err := a.Random(prng)
		require.NoError(t, err)
		require.False(t, elem1.Equal(elem2))
	})

	t.Run("Finite algebra operations", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewFiniteRegularAlgebra(field)
		require.NoError(t, err)

		prng := pcg.NewRandomised()
		e1, err := a.Random(prng)
		require.NoError(t, err)
		e2, err := a.Random(prng)
		require.NoError(t, err)

		t.Run("Additive inverse", func(t *testing.T) {
			t.Parallel()
			require.True(t, e1.Add(e1.Neg()).IsZero())
		})

		t.Run("Multiplicative inverse", func(t *testing.T) {
			t.Parallel()
			if !e1.IsZero() {
				inv, err := e1.TryInv()
				require.NoError(t, err)
				require.True(t, e1.Mul(inv).IsOne())
			}
		})

		t.Run("Distributive law", func(t *testing.T) {
			t.Parallel()
			e3, err := a.Random(prng)
			require.NoError(t, err)
			// a * (b + c) = a*b + a*c
			lhs := e1.Mul(e2.Add(e3))
			rhs := e1.Mul(e2).Add(e1.Mul(e3))
			require.True(t, lhs.Equal(rhs))
		})

		t.Run("ScalarMul consistency", func(t *testing.T) {
			t.Parallel()
			// ScalarMul(s) should equal Mul(wrap(s))
			scalar := field.FromUint64(7)
			viaScalar := e1.ScalarMul(scalar)
			wrapped, _ := a.New(scalar)
			viaMul := e1.Mul(wrapped)
			require.True(t, viaScalar.Equal(viaMul))
		})
	})

	t.Run("IsTorsionFree", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewFiniteRegularAlgebra(field)
		require.NoError(t, err)

		elem, _ := a.New(field.FromUint64(5))
		require.True(t, elem.IsTorsionFree())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		a, err := constructions.NewFiniteRegularAlgebra(field)
		require.NoError(t, err)

		elem, _ := a.New(field.FromUint64(5))
		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, a.Name(), s.Name())
	})
}
