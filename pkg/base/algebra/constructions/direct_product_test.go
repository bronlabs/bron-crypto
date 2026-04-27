package constructions_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// =========== DirectProductGroup ===========

func TestDirectProductGroup(t *testing.T) {
	t.Parallel()
	curve1 := k256.NewCurve()
	curve2 := p256.NewCurve()

	t.Run("NewDirectProductGroup", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectProductGroup(curve1, curve2)
			require.NoError(t, err)
			require.NotNil(t, g)
		})

		t.Run("Nil first group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectProductGroup((*k256.Curve)(nil), curve2)
			require.Error(t, err)
			require.Nil(t, g)
		})

		t.Run("Nil second group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectProductGroup(curve1, (*p256.Curve)(nil))
			require.Error(t, err)
			require.Nil(t, g)
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)
		require.Equal(t, "(secp256k1 x P256)", g.Name())
	})

	t.Run("Arity", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)
		require.Equal(t, cardinal.New(2), g.Arity())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		id := g.OpIdentity()
		require.NotNil(t, id)
		require.True(t, id.IsOpIdentity())
		c1, c2 := id.Components()
		require.True(t, c1.IsOpIdentity())
		require.True(t, c2.IsOpIdentity())
	})

	t.Run("New", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		t.Run("Valid components", func(t *testing.T) {
			t.Parallel()
			elem, err := g.New(curve1.Generator(), curve2.OpIdentity())
			require.NoError(t, err)
			require.NotNil(t, elem)
			require.Equal(t, cardinal.New(2), elem.Arity())
			c1, c2 := elem.Components()
			require.True(t, c1.Equal(curve1.Generator()))
			require.True(t, c2.IsOpIdentity())
		})

		t.Run("Nil first component", func(t *testing.T) {
			t.Parallel()
			_, err := g.New(nil, curve2.Generator())
			require.Error(t, err)
		})

		t.Run("Nil second component", func(t *testing.T) {
			t.Parallel()
			_, err := g.New(curve1.Generator(), nil)
			require.Error(t, err)
		})
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)
		g1 := curve1.Generator()
		g1Double := g1.Op(g1)
		g2 := curve2.Generator()
		g2Double := g2.Op(g2)

		elem1, err := g.New(g1, g2Double)
		require.NoError(t, err)
		elem2, err := g.New(g1Double, g2)
		require.NoError(t, err)

		t.Run("Op is component-wise", func(t *testing.T) {
			t.Parallel()
			result := elem1.Op(elem2)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(g1.Op(g1Double)))
			require.True(t, c2.Equal(g2Double.Op(g2)))
		})

		t.Run("OpInv", func(t *testing.T) {
			t.Parallel()
			inv := elem1.OpInv()
			result := elem1.Op(inv)
			require.True(t, result.IsOpIdentity())
		})

		t.Run("Op with identity", func(t *testing.T) {
			t.Parallel()
			id := g.OpIdentity()
			result := elem1.Op(id)
			require.True(t, result.Equal(elem1))
		})

		t.Run("Equal", func(t *testing.T) {
			t.Parallel()
			same, err := g.New(g1, g2Double)
			require.NoError(t, err)
			require.True(t, elem1.Equal(same))
			require.False(t, elem1.Equal(elem2))
		})

		t.Run("Clone", func(t *testing.T) {
			t.Parallel()
			clone := elem1.Clone()
			require.True(t, elem1.Equal(clone))
			require.NotSame(t, elem1, clone)
		})

		t.Run("HashCode", func(t *testing.T) {
			t.Parallel()
			same, err := g.New(g1, g2Double)
			require.NoError(t, err)
			require.Equal(t, elem1.HashCode(), same.HashCode())
			require.NotEqual(t, elem1.HashCode(), elem2.HashCode())
		})

		t.Run("String", func(t *testing.T) {
			t.Parallel()
			s := elem1.String()
			require.NotEmpty(t, s)
		})
	})

	t.Run("Bytes round-trip", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		elem, err := g.New(curve1.Generator(), curve2.Generator().Op(curve2.Generator()))
		require.NoError(t, err)

		bytes := elem.Bytes()
		require.Len(t, bytes, curve1.ElementSize()+curve2.ElementSize())

		restored, err := g.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, elem.Equal(restored))
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		elem, err := g.New(curve1.Generator(), curve2.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, g.Name(), s.Name())
	})
}

// =========== FiniteDirectProductGroup ===========

func TestFiniteDirectProductGroup(t *testing.T) {
	t.Parallel()
	curve1 := k256.NewCurve()
	curve2 := p256.NewCurve()

	t.Run("NewFiniteDirectProductGroup", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectProductGroup(curve1, curve2)
			require.NoError(t, err)
			require.NotNil(t, g)
		})

		t.Run("Nil first group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectProductGroup((*k256.Curve)(nil), curve2)
			require.Error(t, err)
			require.Nil(t, g)
		})

		t.Run("Nil second group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectProductGroup(curve1, (*p256.Curve)(nil))
			require.Error(t, err)
			require.Nil(t, g)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		order := g.Order()
		require.True(t, order.IsFinite())
		expected := curve1.Order().Mul(curve2.Order())
		require.True(t, expected.Equal(order))
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		prng := pcg.NewRandomised()
		elem1, err := g.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem1)
		require.False(t, elem1.IsOpIdentity())

		elem2, err := g.Random(prng)
		require.NoError(t, err)
		require.False(t, elem1.Equal(elem2))
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectProductGroup(curve1, curve2)
		require.NoError(t, err)
		require.Equal(t, curve1.ElementSize()+curve2.ElementSize(), g.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectProductGroup(curve1, curve2)
		require.NoError(t, err)

		elem, err := g.New(curve1.Generator(), curve2.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, g.Name(), s.Name())
	})
}

// =========== DirectProductRing ===========

func TestDirectProductRing(t *testing.T) {
	t.Parallel()
	field1 := k256.NewScalarField()
	field2 := p256.NewScalarField()

	t.Run("NewDirectProductRing", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectProductRing(field1, field2)
			require.NoError(t, err)
			require.NotNil(t, r)
		})

		t.Run("Nil first ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectProductRing((*k256.ScalarField)(nil), field2)
			require.Error(t, err)
			require.Nil(t, r)
		})

		t.Run("Nil second ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectProductRing(field1, (*p256.ScalarField)(nil))
			require.Error(t, err)
			require.Nil(t, r)
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectProductRing(field1, field2)
		require.NoError(t, err)
		require.Equal(t, "(secp256k1Fq x P256Fq)", r.Name())
	})

	t.Run("Ring properties", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectProductRing(field1, field2)
		require.NoError(t, err)

		t.Run("Zero", func(t *testing.T) {
			t.Parallel()
			z := r.Zero()
			require.NotNil(t, z)
			require.True(t, z.IsZero())
			c1, c2 := z.Components()
			require.True(t, c1.IsZero())
			require.True(t, c2.IsZero())
		})

		t.Run("One", func(t *testing.T) {
			t.Parallel()
			one := r.One()
			require.NotNil(t, one)
			require.True(t, one.IsOne())
			c1, c2 := one.Components()
			require.True(t, c1.IsOne())
			require.True(t, c2.IsOne())
		})

		t.Run("IsDomain", func(t *testing.T) {
			t.Parallel()
			require.False(t, r.IsDomain())
		})

		t.Run("Characteristic is lcm of coprime primes", func(t *testing.T) {
			t.Parallel()
			// The two curves' scalar fields have distinct prime orders, so
			// lcm(p1, p2) = p1 * p2.
			expected := field1.Characteristic().Mul(field2.Characteristic())
			require.True(t, expected.Equal(r.Characteristic()))
		})

		t.Run("OpIdentity is Zero", func(t *testing.T) {
			t.Parallel()
			id := r.OpIdentity()
			require.True(t, id.IsZero())
		})
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectProductRing(field1, field2)
		require.NoError(t, err)

		a1 := field1.FromUint64(3)
		b1 := field2.FromUint64(5)
		a2 := field1.FromUint64(7)
		b2 := field2.FromUint64(11)

		elem1, err := r.New(a1, b1)
		require.NoError(t, err)
		elem2, err := r.New(a2, b2)
		require.NoError(t, err)

		t.Run("Add", func(t *testing.T) {
			t.Parallel()
			result := elem1.Add(elem2)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(field1.FromUint64(10)))
			require.True(t, c2.Equal(field2.FromUint64(16)))
		})

		t.Run("Sub", func(t *testing.T) {
			t.Parallel()
			result := elem2.Sub(elem1)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(field1.FromUint64(4)))
			require.True(t, c2.Equal(field2.FromUint64(6)))
		})

		t.Run("Mul", func(t *testing.T) {
			t.Parallel()
			result := elem1.Mul(elem2)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(field1.FromUint64(21)))
			require.True(t, c2.Equal(field2.FromUint64(55)))
		})

		t.Run("Neg", func(t *testing.T) {
			t.Parallel()
			neg := elem1.Neg()
			result := elem1.Add(neg)
			require.True(t, result.IsZero())
		})

		t.Run("Double", func(t *testing.T) {
			t.Parallel()
			dbl := elem1.Double()
			c1, c2 := dbl.Components()
			require.True(t, c1.Equal(field1.FromUint64(6)))
			require.True(t, c2.Equal(field2.FromUint64(10)))
		})

		t.Run("Square", func(t *testing.T) {
			t.Parallel()
			sq := elem1.Square()
			c1, c2 := sq.Components()
			require.True(t, c1.Equal(field1.FromUint64(9)))
			require.True(t, c2.Equal(field2.FromUint64(25)))
		})

		t.Run("TryInv", func(t *testing.T) {
			t.Parallel()
			inv, err := elem1.TryInv()
			require.NoError(t, err)
			result := elem1.Mul(inv)
			require.True(t, result.IsOne())
		})

		t.Run("TryDiv", func(t *testing.T) {
			t.Parallel()
			quotient, err := elem1.TryDiv(elem2)
			require.NoError(t, err)
			require.True(t, quotient.Mul(elem2).Equal(elem1))
		})

		t.Run("Op is Add", func(t *testing.T) {
			t.Parallel()
			require.True(t, elem1.Op(elem2).Equal(elem1.Add(elem2)))
		})

		t.Run("OpInv is Neg", func(t *testing.T) {
			t.Parallel()
			result := elem1.Op(elem1.OpInv())
			require.True(t, result.IsOpIdentity())
		})

		t.Run("Equal and Clone", func(t *testing.T) {
			t.Parallel()
			clone := elem1.Clone()
			require.True(t, elem1.Equal(clone))
			require.NotSame(t, elem1, clone)
			require.False(t, elem1.Equal(elem2))
		})

		t.Run("HashCode", func(t *testing.T) {
			t.Parallel()
			same, _ := r.New(a1, b1)
			require.Equal(t, elem1.HashCode(), same.HashCode())
			require.NotEqual(t, elem1.HashCode(), elem2.HashCode())
		})
	})

	t.Run("Bytes round-trip", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectProductRing(field1, field2)
		require.NoError(t, err)

		elem, err := r.New(field1.FromUint64(42), field2.FromUint64(99))
		require.NoError(t, err)

		bytes := elem.Bytes()
		require.Len(t, bytes, field1.ElementSize()+field2.ElementSize())

		restored, err := r.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, elem.Equal(restored))
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectProductRing(field1, field2)
		require.NoError(t, err)

		elem, err := r.New(field1.FromUint64(1), field2.FromUint64(2))
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, r.Name(), s.Name())
	})
}

// =========== FiniteDirectProductRing ===========

func TestFiniteDirectProductRing(t *testing.T) {
	t.Parallel()
	field1 := k256.NewScalarField()
	field2 := p256.NewScalarField()

	t.Run("NewFiniteDirectProductRing", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectProductRing(field1, field2)
			require.NoError(t, err)
			require.NotNil(t, r)
		})

		t.Run("Nil first ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectProductRing((*k256.ScalarField)(nil), field2)
			require.Error(t, err)
			require.Nil(t, r)
		})

		t.Run("Nil second ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectProductRing(field1, (*p256.ScalarField)(nil))
			require.Error(t, err)
			require.Nil(t, r)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectProductRing(field1, field2)
		require.NoError(t, err)

		order := r.Order()
		require.True(t, order.IsFinite())
		expected := field1.Order().Mul(field2.Order())
		require.True(t, expected.Equal(order))
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectProductRing(field1, field2)
		require.NoError(t, err)

		prng := pcg.NewRandomised()
		elem1, err := r.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem1)

		elem2, err := r.Random(prng)
		require.NoError(t, err)
		require.False(t, elem1.Equal(elem2))
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectProductRing(field1, field2)
		require.NoError(t, err)
		require.Equal(t, field1.ElementSize()+field2.ElementSize(), r.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectProductRing(field1, field2)
		require.NoError(t, err)

		elem, err := r.New(field1.FromUint64(1), field2.FromUint64(2))
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, r.Name(), s.Name())
	})
}

// =========== DirectProductModule ===========

// Modules in a direct product must share a scalar ring, so the tests here use
// two copies of the same curve (homogeneous E1 = E2) — the trait still treats
// them as an ordered pair with independent components.

func TestDirectProductModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()

	t.Run("NewDirectProductModule", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectProductModule(curve, curve)
			require.NoError(t, err)
			require.NotNil(t, m)
		})

		t.Run("Nil first module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectProductModule((*k256.Curve)(nil), curve)
			require.Error(t, err)
			require.Nil(t, m)
		})

		t.Run("Nil second module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectProductModule(curve, (*k256.Curve)(nil))
			require.Error(t, err)
			require.Nil(t, m)
		})
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewDirectProductModule(curve, curve)
		require.NoError(t, err)
		require.Equal(t, field.Name(), m.ScalarStructure().Name())
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewDirectProductModule(curve, curve)
		require.NoError(t, err)

		gen := curve.Generator()
		gen2 := gen.Op(gen)

		elem, err := m.New(gen, gen2)
		require.NoError(t, err)

		t.Run("ScalarOp", func(t *testing.T) {
			t.Parallel()
			scalar := field.FromUint64(3)
			result := elem.ScalarOp(scalar)
			expected1 := gen.ScalarOp(scalar)
			expected2 := gen2.ScalarOp(scalar)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(expected1))
			require.True(t, c2.Equal(expected2))
		})

		t.Run("ScalarOp by zero", func(t *testing.T) {
			t.Parallel()
			zero := field.Zero()
			result := elem.ScalarOp(zero)
			require.True(t, result.IsOpIdentity())
		})

		t.Run("ScalarOp by one", func(t *testing.T) {
			t.Parallel()
			one := field.One()
			result := elem.ScalarOp(one)
			require.True(t, result.Equal(elem))
		})

		t.Run("Op is component-wise addition", func(t *testing.T) {
			t.Parallel()
			elem2, err := m.New(gen2, gen)
			require.NoError(t, err)
			result := elem.Op(elem2)
			gen3 := gen2.Op(gen)
			c1, c2 := result.Components()
			require.True(t, c1.Equal(gen3))
			require.True(t, c2.Equal(gen3))
		})

		t.Run("OpInv", func(t *testing.T) {
			t.Parallel()
			inv := elem.OpInv()
			result := elem.Op(inv)
			require.True(t, result.IsOpIdentity())
		})
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewDirectProductModule(curve, curve)
		require.NoError(t, err)

		elem, err := m.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, m.Name(), s.Name())
	})
}

// =========== FiniteDirectProductModule ===========

func TestFiniteDirectProductModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("NewFiniteDirectProductModule", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectProductModule(curve, curve)
			require.NoError(t, err)
			require.NotNil(t, m)
		})

		t.Run("Nil first module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectProductModule((*k256.Curve)(nil), curve)
			require.Error(t, err)
			require.Nil(t, m)
		})

		t.Run("Nil second module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectProductModule(curve, (*k256.Curve)(nil))
			require.Error(t, err)
			require.Nil(t, m)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectProductModule(curve, curve)
		require.NoError(t, err)

		order := m.Order()
		require.True(t, order.IsFinite())
		curveOrder, ok := curve.Order().(cardinal.Known)
		require.True(t, ok)
		expected := curveOrder.Mul(curveOrder)
		require.True(t, expected.Equal(order))
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectProductModule(curve, curve)
		require.NoError(t, err)

		prng := pcg.NewRandomised()
		elem1, err := m.Random(prng)
		require.NoError(t, err)
		require.NotNil(t, elem1)

		elem2, err := m.Random(prng)
		require.NoError(t, err)
		require.False(t, elem1.Equal(elem2))
	})

	t.Run("ElementSize", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectProductModule(curve, curve)
		require.NoError(t, err)
		require.Equal(t, 2*curve.ElementSize(), m.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectProductModule(curve, curve)
		require.NoError(t, err)

		elem, err := m.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, m.Name(), s.Name())
	})
}
