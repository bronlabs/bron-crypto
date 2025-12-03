package properties

import (
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ******************** Magma.

func NewMagmaticPropertySuite[S algebra.Magma[E], E algebra.MagmaElement[E]](
	t *testing.T, s S, g *rapid.Generator[E],
	op func(a, b E) E, isAssociative, isCommutative bool,
) *Magmatic[S, E] {
	t.Helper()
	return &Magmatic[S, E]{
		Structural:    *NewStructuralPropertySuite(t, s, g),
		op:            op,
		isCommutative: isCommutative,
		isAssociative: isAssociative,
	}
}

type Magmatic[M algebra.Magma[E], E algebra.MagmaElement[E]] struct {
	Structural[M, E]
	op            func(a, b E) E
	isCommutative bool
	isAssociative bool
}

func (m *Magmatic[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.Structural.CheckAll(t)
	t.Run("OpIsClosed", m.OpIsClosed)
	t.Run("TargetOpIsCorrect", m.TargetOpIsCorrect)
	if m.isAssociative {
		t.Run("OpIsAssociative", m.OpIsAssociative)
	}
	if m.isCommutative {
		t.Run("OpIsCommutative", m.OpIsCommutative)
	}
}

func (m *Magmatic[S, E]) OpIsClosed(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		c := m.op(a, b)
		require.NotNil(t, c)
	})
}

func (m *Magmatic[S, E]) OpIsAssociative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		c := m.g.Draw(t, "c")

		ab := m.op(a, b)
		abc1 := m.op(ab, c)

		bc := m.op(b, c)
		abc2 := m.op(a, bc)

		require.True(t, abc1.Equal(abc2))
	})
}

func (m *Magmatic[S, E]) OpIsCommutative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")

		ab := m.op(a, b)
		ba := m.op(b, a)

		require.True(t, ab.Equal(ba))
	})
}

func (m *Magmatic[S, E]) TargetOpIsCorrect(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")

		actual := m.op(a, b)
		expected := a.Op(b)

		aUint64 := any(a).(interface {
			Uint64() uint64
		}).Uint64()
		bUint64 := any(b).(interface {
			Uint64() uint64
		}).Uint64()
		actualUint64 := any(actual).(interface {
			Uint64() uint64
		}).Uint64()
		expectedUint64 := any(expected).(interface {
			Uint64() uint64
		}).Uint64()
		require.True(t, actual.Equal(expected), fmt.Sprintf("a: %d, b: %d, actual: %d, expected: %d", aUint64, bUint64, actualUint64, expectedUint64))
	})
}

// ******************** SemiGroup.

func NewSemiGroupalPropertySuite[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]](
	t *testing.T, s S, g *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
) *SemiGroupal[S, E] {
	t.Helper()
	return &SemiGroupal[S, E]{
		Magmatic: *NewMagmaticPropertySuite(t, s, g, op, true, isCommutative),
	}
}

func NewAdditiveSemiGroupalPropertySuite[S algebra.AdditiveSemiGroup[E], E algebra.AdditiveSemiGroupElement[E]](
	t *testing.T, s S, g *rapid.Generator[E],
	isCommutative bool,
) *AdditiveSemiGroupal[S, E] {
	t.Helper()
	return &AdditiveSemiGroupal[S, E]{
		SemiGroupal: *NewSemiGroupalPropertySuite(t, s, g, algebra.Addition[E], isCommutative),
	}
}

func NewMultiplicativeSemiGroupalPropertySuite[S algebra.MultiplicativeSemiGroup[E], E algebra.MultiplicativeSemiGroupElement[E]](
	t *testing.T, s S, g *rapid.Generator[E],
	isCommutative bool,
) *MultiplicativeSemiGroupal[S, E] {
	t.Helper()
	return &MultiplicativeSemiGroupal[S, E]{
		SemiGroupal: *NewSemiGroupalPropertySuite(t, s, g, algebra.Multiplication[E], isCommutative),
	}
}

func NewCyclicSemiGroupalPropertySuite[S algebra.CyclicSemiGroup[E], E algebra.CyclicSemiGroupElement[E]](
	t *testing.T, s S, g *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
) *CyclicSemiGroupal[S, E] {
	t.Helper()
	return &CyclicSemiGroupal[S, E]{
		SemiGroupal: *NewSemiGroupalPropertySuite(t, s, g, op, isCommutative),
	}
}

type SemiGroupal[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]] struct {
	Magmatic[S, E]
}

type AdditiveSemiGroupal[S algebra.AdditiveSemiGroup[E], E algebra.AdditiveSemiGroupElement[E]] struct {
	SemiGroupal[S, E]
}

func (m *AdditiveSemiGroupal[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.SemiGroupal.CheckAll(t)
	t.Run("CanDouble", m.CanDouble)
}

func (m *AdditiveSemiGroupal[S, E]) CanDouble(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		doubleA := a.Add(a)
		expectedDouble := a.Double()
		require.True(t, doubleA.Equal(expectedDouble))
	})
}

type MultiplicativeSemiGroupal[S algebra.MultiplicativeSemiGroup[E], E algebra.MultiplicativeSemiGroupElement[E]] struct {
	SemiGroupal[S, E]
}

func (m *MultiplicativeSemiGroupal[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.SemiGroupal.CheckAll(t)
	t.Run("CanSquare", m.CanSquare)
}

func (m *MultiplicativeSemiGroupal[S, E]) CanSquare(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		squareA := a.Mul(a)
		expectedSquare := a.Square()
		require.True(t, squareA.Equal(expectedSquare))
	})
}

type CyclicSemiGroupal[S algebra.CyclicSemiGroup[E], E algebra.CyclicSemiGroupElement[E]] struct {
	SemiGroupal[S, E]
}

func (c *CyclicSemiGroupal[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	c.SemiGroupal.CheckAll(t)
	t.Run("HasDesignatedGenerator", c.HasDesignatedGenerator)
}

func (c *CyclicSemiGroupal[S, E]) HasDesignatedGenerator(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		generator := c.st.Generator()
		require.True(t, generator.IsDesignatedGenerator())
	})
}

// ******************** Monoid.

func NewMonoidalPropertySuite[M algebra.Monoid[E], E algebra.MonoidElement[E]](
	t *testing.T, m M, g *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
	identity E, isIdentity func(E) bool,
) *Monoidal[M, E] {
	t.Helper()
	return &Monoidal[M, E]{
		SemiGroupal: *NewSemiGroupalPropertySuite(t, m, g, op, isCommutative),
		identity:    identity,
		isIdentity:  isIdentity,
	}
}

func NewAdditiveMonoidalPropertySuite[M algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	t *testing.T, m M, g *rapid.Generator[E], isCommutative bool,
) *AdditiveMonoidal[M, E] {
	t.Helper()
	return &AdditiveMonoidal[M, E]{
		Monoidal: *NewMonoidalPropertySuite(t, m, g, algebra.Addition[E], isCommutative, m.Zero(), func(e E) bool {
			return e.IsZero()
		}),
	}
}

func NewMultiplicativeMonoidalPropertySuite[M algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	t *testing.T, m M, g *rapid.Generator[E], isCommutative bool,
) *MultiplicativeMonoidal[M, E] {
	t.Helper()
	return &MultiplicativeMonoidal[M, E]{
		Monoidal: *NewMonoidalPropertySuite(t, m, g, algebra.Multiplication[E], isCommutative, m.One(), func(e E) bool {
			return e.IsOne()
		}),
	}
}

func NewCyclicMonoidalPropertySuite[M algebra.CyclicMonoid[E], E algebra.CyclicMonoidElement[E]](
	t *testing.T, m M, g *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
	identity E, isIdentity func(E) bool,
) *CyclicMonoidal[M, E] {
	t.Helper()
	return &CyclicMonoidal[M, E]{
		Monoidal:          *NewMonoidalPropertySuite(t, m, g, op, isCommutative, identity, isIdentity),
		CyclicSemiGroupal: *NewCyclicSemiGroupalPropertySuite(t, m, g, op, isCommutative),
	}
}

type Monoidal[M algebra.Monoid[E], E algebra.MonoidElement[E]] struct {
	SemiGroupal[M, E]
	identity   E
	isIdentity func(E) bool
}

func (m *Monoidal[M, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.SemiGroupal.CheckAll(t)
	t.Run("HasOpIdentity", m.HasOpIdentity)
}

func (m *Monoidal[M, E]) HasOpIdentity(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")

		require.True(t, m.isIdentity(m.identity))

		left := m.op(m.identity, a)
		require.True(t, left.Equal(a))

		right := m.op(a, m.identity)
		require.True(t, right.Equal(a))
	})
}

type AdditiveMonoidal[M algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]] struct {
	Monoidal[M, E]
}

func (m *AdditiveMonoidal[M, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.Monoidal.CheckAll(t)
	t.Run("CanTryNeg", m.CanTryNeg)
	t.Run("CanTrySub", m.CanTrySub)
}

func (m *AdditiveMonoidal[M, E]) CanTryNeg(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		negA, err := a.TryNeg()
		if err != nil {
			require.NotNil(t, negA)

			left := m.op(negA, a)
			require.True(t, left.Equal(m.identity))

			right := m.op(a, negA)
			require.True(t, right.Equal(m.identity))
		} else {
			require.Nil(t, negA)
		}
	})
}

func (m *AdditiveMonoidal[M, E]) CanTrySub(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		diff, err := a.TrySub(b)
		if err != nil {
			require.NotNil(t, diff)

			sum := m.op(diff, b)
			require.True(t, sum.Equal(a))
		} else {
			require.Nil(t, diff)
		}
	})
}

type MultiplicativeMonoidal[M algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]] struct {
	Monoidal[M, E]
}

func (m *MultiplicativeMonoidal[M, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.Monoidal.CheckAll(t)
	t.Run("CanTryInv", m.CanTryInv)
	t.Run("CanTryDiv", m.CanTryDiv)
}

func (m *MultiplicativeMonoidal[M, E]) CanTryInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		invA, err := a.TryInv()
		if err == nil {
			require.NotNil(t, invA)

			left := m.op(invA, a)
			require.True(t, left.Equal(m.identity))

			right := m.op(a, invA)
			require.True(t, right.Equal(m.identity))
		} else {
			require.Nil(t, invA)
		}
	})
}

func (m *MultiplicativeMonoidal[M, E]) CanTryDiv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		quotient, err := a.TryDiv(b)
		if err == nil {
			require.NotNil(t, quotient)

			product := m.op(quotient, b)
			require.True(t, product.Equal(a))
		} else {
			require.Nil(t, quotient)
		}
	})
}

type CyclicMonoidal[M algebra.CyclicMonoid[E], E algebra.CyclicMonoidElement[E]] struct {
	Monoidal[M, E]
	CyclicSemiGroupal[M, E]
}

func (m *CyclicMonoidal[M, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.Monoidal.CheckAll(t)
	m.CyclicSemiGroupal.CheckAll(t)
}

// ******************** Group.

func NewGroupalPropertySuite[G algebra.Group[E], E algebra.GroupElement[E]](
	t *testing.T, g G, gen *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
	identity E, isIdentity func(E) bool,
	opInv func(a E) E,
) *Groupal[G, E] {
	t.Helper()
	return &Groupal[G, E]{
		Monoidal: *NewMonoidalPropertySuite(t, g, gen, op, isCommutative, identity, isIdentity),
		opInv:    opInv,
	}
}

type Groupal[G algebra.Group[E], E algebra.GroupElement[E]] struct {
	Monoidal[G, E]
	opInv func(a E) E
}

func (g *Groupal[G, E]) CheckAll(t *testing.T) {
	t.Helper()
	g.Monoidal.CheckAll(t)
	t.Run("EveryElementHasInverse", g.EveryElementHasInverse)
}

func (g *Groupal[G, E]) EveryElementHasInverse(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := g.g.Draw(t, "a")

		inv := g.opInv(a)
		require.NotNil(t, inv)

		// a * a^(-1) = identity
		left := g.op(a, inv)
		require.True(t, left.Equal(g.identity), "a * inv(a) should equal identity")

		// a^(-1) * a = identity
		right := g.op(inv, a)
		require.True(t, right.Equal(g.identity), "inv(a) * a should equal identity")
	})
}

func NewAdditiveGroupalPropertySuite[G algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	t *testing.T, g G, gen *rapid.Generator[E], isCommutative bool,
) *AdditiveGroupal[G, E] {
	t.Helper()
	return &AdditiveGroupal[G, E]{
		Groupal:          *NewGroupalPropertySuite(t, g, gen, algebra.Addition[E], isCommutative, g.Zero(), func(e E) bool { return e.IsZero() }, algebra.Negate[E]),
		AdditiveMonoidal: *NewAdditiveMonoidalPropertySuite(t, g, gen, isCommutative),
	}
}

type AdditiveGroupal[G algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]] struct {
	Groupal[G, E]
	AdditiveMonoidal[G, E]
}

func (g *AdditiveGroupal[G, E]) CheckAll(t *testing.T) {
	t.Helper()
	g.Groupal.CheckAll(t)
	g.AdditiveMonoidal.CheckAll(t)
	t.Run("SubIsAddNeg", g.SubIsAddNeg)
}

func (g *AdditiveGroupal[G, E]) SubIsAddNeg(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := g.Groupal.g.Draw(t, "a")
		b := g.Groupal.g.Draw(t, "b")

		// a - b should equal a + (-b)
		diff := a.Sub(b)
		negB := b.Neg()
		expected := a.Add(negB)
		require.True(t, diff.Equal(expected), "a - b should equal a + neg(b)")
	})
}

func NewMultiplicativeGroupalPropertySuite[G algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]](
	t *testing.T, g G, gen *rapid.Generator[E], isCommutative bool,
) *MultiplicativeGroupal[G, E] {
	t.Helper()
	return &MultiplicativeGroupal[G, E]{
		Groupal:                *NewGroupalPropertySuite(t, g, gen, algebra.Multiplication[E], isCommutative, g.One(), func(e E) bool { return e.IsOne() }, algebra.Invert[E]),
		MultiplicativeMonoidal: *NewMultiplicativeMonoidalPropertySuite(t, g, gen, isCommutative),
	}
}

type MultiplicativeGroupal[G algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]] struct {
	Groupal[G, E]
	MultiplicativeMonoidal[G, E]
}

func (g *MultiplicativeGroupal[G, E]) CheckAll(t *testing.T) {
	t.Helper()
	g.Groupal.CheckAll(t)
	g.MultiplicativeMonoidal.CheckAll(t)
	t.Run("DivIsMulInv", g.DivIsMulInv)
}

func (g *MultiplicativeGroupal[G, E]) DivIsMulInv(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := g.Groupal.g.Draw(t, "a")
		b := g.Groupal.g.Draw(t, "b")

		// a / b should equal a * b^(-1)
		quot := a.Div(b)
		invB := b.Inv()
		expected := a.Mul(invB)
		require.True(t, quot.Equal(expected), "a / b should equal a * inv(b)")
	})
}

func NewCyclicGroupalPropertySuite[G algebra.CyclicGroup[E], E algebra.CyclicGroupElement[E]](
	t *testing.T, g G, gen *rapid.Generator[E],
	op func(a, b E) E, isCommutative bool,
	identity E, isIdentity func(E) bool,
	opInv func(a E) E,
) *CyclicGroupal[G, E] {
	t.Helper()
	return &CyclicGroupal[G, E]{
		Groupal:        *NewGroupalPropertySuite(t, g, gen, op, isCommutative, identity, isIdentity, opInv),
		CyclicMonoidal: *NewCyclicMonoidalPropertySuite(t, g, gen, op, isCommutative, identity, isIdentity),
	}
}

type CyclicGroupal[G algebra.CyclicGroup[E], E algebra.CyclicGroupElement[E]] struct {
	Groupal[G, E]
	CyclicMonoidal[G, E]
}

func (g *CyclicGroupal[G, E]) CheckAll(t *testing.T) {
	t.Helper()
	g.Groupal.CheckAll(t)
	g.CyclicMonoidal.CheckAll(t)
}

// ******************** Extra Groups.

func NewAbelianGroupalPropertySuite[G algebra.AbelianGroup[E, S], N interface {
	algebra.NumericStructure[S]
	algebra.Ring[S]
}, E algebra.AbelianGroupElement[E, S], S interface {
	algebra.Numeric[S]
	algebra.RingElement[S]
}](
	t *testing.T, module G, ring N,
	gM *rapid.Generator[E], gR *rapid.Generator[S],
	op func(a, b E) E,
	identity E, isIdentity func(e E) bool,
	opInv func(a E) E,
	scMul func(s S, m E) E,
) *AbelianGroupal[G, N, E, S] {
	t.Helper()
	return &AbelianGroupal[G, N, E, S]{
		Modular:   *NewModularPropertySuite(t, module, ring, gM, gR, op, identity, isIdentity, opInv, scMul),
		Numerical: *NewNumericalPropertySuite(t, ring, gR),
	}
}

func NewPrimeGroupalPropertySuite[
	G algebra.PrimeGroup[E, S], F algebra.PrimeField[S],
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](
	t *testing.T, group G, field F,
	gG *rapid.Generator[E], gF *rapid.Generator[S],
	op func(a, b E) E,
	identity E, isIdentity func(e E) bool,
	opInv func(a E) E,
	scMul func(s S, m E) E,
	scBaseMul func(s S) E,
) *PrimeGroupal[G, F, E, S] {
	t.Helper()
	return &PrimeGroupal[G, F, E, S]{
		Groupal:           *NewGroupalPropertySuite(t, group, gG, op, true, identity, isIdentity, opInv),
		AbelianGroupal:    *NewAbelianGroupalPropertySuite(t, group, field, gG, gF, op, identity, isIdentity, opInv, scMul),
		VectorSpatial:     *NewVectorSpatialPropertySuite(t, group, field, gG, gF, op, identity, isIdentity, opInv, scMul),
		CyclicSemiGroupal: *NewCyclicSemiGroupalPropertySuite(t, group, gG, op, true),
		scBaseMul:         scBaseMul,
	}
}

func NewAdditivePrimeGroupalPropertySuite[
	G algebra.AdditivePrimeGroup[E, S], F algebra.PrimeField[S],
	E algebra.AdditivePrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
](
	t *testing.T, group G, field F,
	gG *rapid.Generator[E], gF *rapid.Generator[S],
) *AdditivePrimeGroupal[G, F, E, S] {
	t.Helper()
	return &AdditivePrimeGroupal[G, F, E, S]{
		PrimeGroupal: *NewPrimeGroupalPropertySuite(
			t, group, field,
			gG, gF, algebra.Addition[E],
			group.Zero(), func(e E) bool { return e.IsZero() },
			algebra.Negate[E], algebra.ScalarMultiply[E, S], func(s S) E { return group.ScalarBaseMul(s) },
		),
	}
}

type AbelianGroupal[G algebra.AbelianGroup[E, S], N interface {
	algebra.NumericStructure[S]
	algebra.Ring[S]
}, E algebra.AbelianGroupElement[E, S], S interface {
	algebra.Numeric[S]
	algebra.RingElement[S]
}] struct {
	Modular[G, N, E, S]
	Numerical[N, S]
}

func (a *AbelianGroupal[G, N, E, S]) CheckAll(t *testing.T) {
	t.Helper()
	a.Modular.CheckAll(t)
	a.Numerical.CheckAll(t)
}

type PrimeGroupal[
	G algebra.PrimeGroup[E, S], F algebra.PrimeField[S],
	E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
] struct {
	Groupal[G, E]
	AbelianGroupal[G, F, E, S]
	VectorSpatial[G, F, E, S]
	CyclicSemiGroupal[G, E]
	scBaseMul func(S) E
}

func (p *PrimeGroupal[G, F, E, S]) CheckAll(t *testing.T) {
	t.Helper()
	p.Groupal.CheckAll(t)
	p.AbelianGroupal.CheckAll(t)
	p.VectorSpatial.CheckAll(t)
	p.CyclicSemiGroupal.CheckAll(t)
	t.Run("HasScalarBaseOp", p.HasScalarBaseOp)
}

func (p *PrimeGroupal[G, F, E, S]) HasScalarBaseOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		group := p.AbelianGroupal.Modular.Groupal.st
		s := p.AbelianGroupal.Numerical.g.Draw(t, "s")
		g := group.Generator()

		actual := p.AbelianGroupal.scMul(s, g)
		expected := p.scBaseMul(s)

		require.True(t, actual.Equal(expected))
	})
}

type AdditivePrimeGroupal[
	G algebra.AdditivePrimeGroup[E, S], F algebra.PrimeField[S],
	E algebra.AdditivePrimeGroupElement[E, S], S algebra.PrimeFieldElement[S],
] struct {
	PrimeGroupal[G, F, E, S]
}

func (a *AdditivePrimeGroupal[G, F, E, S]) CheckAll(t *testing.T) {
	t.Helper()
	a.PrimeGroupal.CheckAll(t)
}
