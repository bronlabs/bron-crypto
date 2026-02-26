package constructions_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// =========== DirectPowerGroup ===========

func TestDirectPowerGroup(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("NewDirectPowerGroup", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectPowerGroup(curve, 3)
			require.NoError(t, err)
			require.NotNil(t, g)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectPowerGroup(curve, 0)
			require.Error(t, err)
			require.Nil(t, g)
		})

		t.Run("Nil group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewDirectPowerGroup((*k256.Curve)(nil), 3)
			require.Error(t, err)
			require.Nil(t, g)
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 3)
		require.NoError(t, err)
		require.Equal(t, "(secp256k1)^3", g.Name())
	})

	t.Run("OpIdentity", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 2)
		require.NoError(t, err)

		id := g.OpIdentity()
		require.NotNil(t, id)
		require.True(t, id.IsOpIdentity())
		// Each component should be the curve identity (point at infinity)
		for _, c := range id.Components() {
			require.True(t, c.IsOpIdentity())
		}
	})

	t.Run("New", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 2)
		require.NoError(t, err)
		gen := curve.Generator()

		t.Run("Valid components", func(t *testing.T) {
			t.Parallel()
			elem, err := g.New(gen, curve.OpIdentity())
			require.NoError(t, err)
			require.NotNil(t, elem)
			require.Equal(t, cardinal.New(2), elem.Arity())
			require.True(t, elem.Components()[0].Equal(gen))
			require.True(t, elem.Components()[1].IsOpIdentity())
		})

		t.Run("Wrong arity", func(t *testing.T) {
			t.Parallel()
			_, err := g.New(gen)
			require.Error(t, err)
		})
	})

	t.Run("Diagonal", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 3)
		require.NoError(t, err)
		gen := curve.Generator()

		diag, err := g.Diagonal(gen)
		require.NoError(t, err)
		for _, c := range diag.Components() {
			require.True(t, c.Equal(gen))
		}
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 2)
		require.NoError(t, err)
		gen := curve.Generator()
		gen2 := gen.Op(gen) // 2G

		elem1, err := g.New(gen, gen2)
		require.NoError(t, err)
		elem2, err := g.New(gen2, gen)
		require.NoError(t, err)

		t.Run("Op is component-wise", func(t *testing.T) {
			t.Parallel()
			result := elem1.Op(elem2)
			// (G + 2G, 2G + G) = (3G, 3G)
			gen3 := gen2.Op(gen)
			require.True(t, result.Components()[0].Equal(gen3))
			require.True(t, result.Components()[1].Equal(gen3))
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
			same, err := g.New(gen, gen2)
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
			same, err := g.New(gen, gen2)
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
		g, err := constructions.NewDirectPowerGroup(curve, 2)
		require.NoError(t, err)
		gen := curve.Generator()

		elem, err := g.New(gen, gen.Op(gen))
		require.NoError(t, err)

		bytes := elem.Bytes()
		require.Len(t, bytes, 2*curve.ElementSize())

		restored, err := g.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, elem.Equal(restored))
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewDirectPowerGroup(curve, 2)
		require.NoError(t, err)

		elem, err := g.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, g.Name(), s.Name())
	})
}

// =========== FiniteDirectPowerGroup ===========

func TestFiniteDirectPowerGroup(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("NewFiniteDirectPowerGroup", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectPowerGroup(curve, 2)
			require.NoError(t, err)
			require.NotNil(t, g)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectPowerGroup(curve, 0)
			require.Error(t, err)
			require.Nil(t, g)
		})

		t.Run("Nil group", func(t *testing.T) {
			t.Parallel()
			g, err := constructions.NewFiniteDirectPowerGroup((*k256.Curve)(nil), 2)
			require.Error(t, err)
			require.Nil(t, g)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectPowerGroup(curve, 2)
		require.NoError(t, err)

		order := g.Order()
		require.True(t, order.IsFinite())
		// Should be curveOrder^2
		curveOrder, ok := curve.Order().(cardinal.Known)
		require.True(t, ok)
		expected := curveOrder.Mul(curveOrder)
		require.True(t, expected.Equal(order))
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectPowerGroup(curve, 2)
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
		g, err := constructions.NewFiniteDirectPowerGroup(curve, 3)
		require.NoError(t, err)
		require.Equal(t, 3*curve.ElementSize(), g.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		g, err := constructions.NewFiniteDirectPowerGroup(curve, 2)
		require.NoError(t, err)

		elem, err := g.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, g.Name(), s.Name())
	})
}

// =========== DirectPowerRing ===========

func TestDirectPowerRing(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("NewDirectPowerRing", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectPowerRing(field, 3)
			require.NoError(t, err)
			require.NotNil(t, r)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectPowerRing(field, 0)
			require.Error(t, err)
			require.Nil(t, r)
		})

		t.Run("Nil ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewDirectPowerRing((*k256.ScalarField)(nil), 3)
			require.Error(t, err)
			require.Nil(t, r)
		})
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectPowerRing(field, 2)
		require.NoError(t, err)
		require.Equal(t, "(secp256k1Fq)^2", r.Name())
	})

	t.Run("Ring properties", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectPowerRing(field, 2)
		require.NoError(t, err)

		t.Run("Zero", func(t *testing.T) {
			t.Parallel()
			z := r.Zero()
			require.NotNil(t, z)
			require.True(t, z.IsZero())
			for _, c := range z.Components() {
				require.True(t, c.IsZero())
			}
		})

		t.Run("One", func(t *testing.T) {
			t.Parallel()
			one := r.One()
			require.NotNil(t, one)
			require.True(t, one.IsOne())
			for _, c := range one.Components() {
				require.True(t, c.IsOne())
			}
		})

		t.Run("IsDomain", func(t *testing.T) {
			t.Parallel()
			// A direct product of rings is never a domain
			require.False(t, r.IsDomain())
		})

		t.Run("Characteristic", func(t *testing.T) {
			t.Parallel()
			require.Equal(t, field.Characteristic(), r.Characteristic())
		})

		t.Run("OpIdentity is Zero", func(t *testing.T) {
			t.Parallel()
			id := r.OpIdentity()
			require.True(t, id.IsZero())
		})
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectPowerRing(field, 2)
		require.NoError(t, err)

		a := field.FromUint64(3)
		b := field.FromUint64(5)
		c := field.FromUint64(7)
		d := field.FromUint64(11)

		elem1, err := r.New(a, b)
		require.NoError(t, err)
		elem2, err := r.New(c, d)
		require.NoError(t, err)

		t.Run("Add", func(t *testing.T) {
			t.Parallel()
			result := elem1.Add(elem2)
			// (3+7, 5+11) = (10, 16)
			require.True(t, result.Components()[0].Equal(field.FromUint64(10)))
			require.True(t, result.Components()[1].Equal(field.FromUint64(16)))
		})

		t.Run("Sub", func(t *testing.T) {
			t.Parallel()
			result := elem2.Sub(elem1)
			// (7-3, 11-5) = (4, 6)
			require.True(t, result.Components()[0].Equal(field.FromUint64(4)))
			require.True(t, result.Components()[1].Equal(field.FromUint64(6)))
		})

		t.Run("Mul", func(t *testing.T) {
			t.Parallel()
			result := elem1.Mul(elem2)
			// (3*7, 5*11) = (21, 55)
			require.True(t, result.Components()[0].Equal(field.FromUint64(21)))
			require.True(t, result.Components()[1].Equal(field.FromUint64(55)))
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
			// (6, 10)
			require.True(t, dbl.Components()[0].Equal(field.FromUint64(6)))
			require.True(t, dbl.Components()[1].Equal(field.FromUint64(10)))
		})

		t.Run("Square", func(t *testing.T) {
			t.Parallel()
			sq := elem1.Square()
			// (9, 25)
			require.True(t, sq.Components()[0].Equal(field.FromUint64(9)))
			require.True(t, sq.Components()[1].Equal(field.FromUint64(25)))
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
			// quotient * elem2 should give elem1
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
			same, _ := r.New(a, b)
			require.Equal(t, elem1.HashCode(), same.HashCode())
			require.NotEqual(t, elem1.HashCode(), elem2.HashCode())
		})
	})

	t.Run("Bytes round-trip", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectPowerRing(field, 2)
		require.NoError(t, err)

		elem, err := r.New(field.FromUint64(42), field.FromUint64(99))
		require.NoError(t, err)

		bytes := elem.Bytes()
		require.Len(t, bytes, 2*field.ElementSize())

		restored, err := r.FromBytes(bytes)
		require.NoError(t, err)
		require.True(t, elem.Equal(restored))
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewDirectPowerRing(field, 2)
		require.NoError(t, err)

		elem, err := r.New(field.FromUint64(1), field.FromUint64(2))
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, r.Name(), s.Name())
	})
}

// =========== FiniteDirectPowerRing ===========

func TestFiniteDirectPowerRing(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("NewFiniteDirectPowerRing", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectPowerRing(field, 2)
			require.NoError(t, err)
			require.NotNil(t, r)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectPowerRing(field, 0)
			require.Error(t, err)
			require.Nil(t, r)
		})

		t.Run("Nil ring", func(t *testing.T) {
			t.Parallel()
			r, err := constructions.NewFiniteDirectPowerRing((*k256.ScalarField)(nil), 2)
			require.Error(t, err)
			require.Nil(t, r)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectPowerRing(field, 2)
		require.NoError(t, err)

		order := r.Order()
		require.True(t, order.IsFinite())
		fieldOrder, ok := field.Order().(cardinal.Known)
		require.True(t, ok)
		expected := fieldOrder.Mul(fieldOrder)
		require.True(t, expected.Equal(order))
	})

	t.Run("Random", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectPowerRing(field, 2)
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
		r, err := constructions.NewFiniteDirectPowerRing(field, 3)
		require.NoError(t, err)
		require.Equal(t, 3*field.ElementSize(), r.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		r, err := constructions.NewFiniteDirectPowerRing(field, 2)
		require.NoError(t, err)

		elem, err := r.New(field.FromUint64(1), field.FromUint64(2))
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, r.Name(), s.Name())
	})
}

// =========== DirectSumModule ===========

func TestDirectSumModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()

	t.Run("NewDirectSumModule", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectSumModule(curve, 3)
			require.NoError(t, err)
			require.NotNil(t, m)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectSumModule(curve, 0)
			require.Error(t, err)
			require.Nil(t, m)
		})

		t.Run("Nil module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewDirectSumModule((*k256.Curve)(nil), 3)
			require.Error(t, err)
			require.Nil(t, m)
		})
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)
		require.Equal(t, field.Name(), m.ScalarStructure().Name())
	})

	t.Run("Element operations", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)

		gen := curve.Generator()
		gen2 := gen.Op(gen)

		elem, err := m.New(gen, gen2)
		require.NoError(t, err)

		t.Run("ScalarOp", func(t *testing.T) {
			t.Parallel()
			scalar := field.FromUint64(3)
			result := elem.ScalarOp(scalar)
			// (3*G, 3*2G) = (3G, 6G)
			expected0 := gen.ScalarOp(scalar)
			expected1 := gen2.ScalarOp(scalar)
			require.True(t, result.Components()[0].Equal(expected0))
			require.True(t, result.Components()[1].Equal(expected1))
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
			// (G + 2G, 2G + G) = (3G, 3G)
			gen3 := gen2.Op(gen)
			require.True(t, result.Components()[0].Equal(gen3))
			require.True(t, result.Components()[1].Equal(gen3))
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
		m, err := constructions.NewDirectSumModule(curve, 2)
		require.NoError(t, err)

		elem, err := m.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, m.Name(), s.Name())
	})
}

// =========== FiniteDirectSumModule ===========

func TestFiniteDirectSumModule(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("NewFiniteDirectSumModule", func(t *testing.T) {
		t.Parallel()

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectSumModule(curve, 2)
			require.NoError(t, err)
			require.NotNil(t, m)
		})

		t.Run("Arity zero", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectSumModule(curve, 0)
			require.Error(t, err)
			require.Nil(t, m)
		})

		t.Run("Nil module", func(t *testing.T) {
			t.Parallel()
			m, err := constructions.NewFiniteDirectSumModule((*k256.Curve)(nil), 2)
			require.Error(t, err)
			require.Nil(t, m)
		})
	})

	t.Run("Order", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectSumModule(curve, 2)
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
		m, err := constructions.NewFiniteDirectSumModule(curve, 2)
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
		m, err := constructions.NewFiniteDirectSumModule(curve, 3)
		require.NoError(t, err)
		require.Equal(t, 3*curve.ElementSize(), m.ElementSize())
	})

	t.Run("Structure", func(t *testing.T) {
		t.Parallel()
		m, err := constructions.NewFiniteDirectSumModule(curve, 2)
		require.NoError(t, err)

		elem, err := m.New(curve.Generator(), curve.Generator())
		require.NoError(t, err)

		s := elem.Structure()
		require.NotNil(t, s)
		require.Equal(t, m.Name(), s.Name())
	})
}
