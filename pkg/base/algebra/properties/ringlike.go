package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ******************** Double Magma.

func NewDoubleMagmaticPropertySuite[M algebra.DoubleMagma[E], E algebra.DoubleMagmaElement[E]](
	t *testing.T, m M, g *rapid.Generator[E],
	op func(a, b E) E, opIsAssociative, opIsCommutative bool,
	otherOp func(a, b E) E, otherOpIsAssociative, otherOpIsCommutative bool,
) *DoubleMagmatic[M, E] {
	t.Helper()
	return &DoubleMagmatic[M, E]{
		Magmatic:             *NewMagmaticPropertySuite(t, m, g, op, opIsAssociative, opIsCommutative),
		otherOp:              otherOp,
		otherOpIsAssociative: otherOpIsAssociative,
		otherOpIsCommutative: otherOpIsCommutative,
	}
}

type DoubleMagmatic[M algebra.DoubleMagma[E], E algebra.DoubleMagmaElement[E]] struct {
	Magmatic[M, E]
	otherOp              func(a, b E) E
	otherOpIsCommutative bool
	otherOpIsAssociative bool
}

func (m *DoubleMagmatic[M, E]) CheckAll(t *testing.T) {
	t.Helper()
	m.Magmatic.CheckAll(t)
	t.Run("OtherOpIsClosed", m.OtherOpIsClosed)
	if m.otherOpIsAssociative {
		t.Run("OtherOpIsAssociative", m.OtherOpIsAssociative)
	}
	if m.otherOpIsCommutative {
		t.Run("OtherOpIsCommutative", m.OtherOpIsCommutative)
	}
}

func (m *DoubleMagmatic[M, E]) OtherOpIsClosed(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		c := m.otherOp(a, b)
		require.NotNil(t, c)
	})
}

func (m *DoubleMagmatic[M, E]) OtherOpIsAssociative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")
		c := m.g.Draw(t, "c")

		ab := m.otherOp(a, b)
		abc1 := m.otherOp(ab, c)

		bc := m.otherOp(b, c)
		abc2 := m.otherOp(a, bc)

		require.True(t, abc1.Equal(abc2))
	})
}

func (m *DoubleMagmatic[M, E]) OtherOpIsCommutative(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := m.g.Draw(t, "a")
		b := m.g.Draw(t, "b")

		ab := m.otherOp(a, b)
		ba := m.otherOp(b, a)

		require.True(t, ab.Equal(ba))
	})
}

// ******************** HemiRing.

func NewHemiRingalPropertySuite[R algebra.HemiRing[E], E algebra.HemiRingElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
	additionIsPrimaryOperator bool,
) *HemiRingal[R, E] {
	t.Helper()
	var primary, secondary func(a, b E) E
	if additionIsPrimaryOperator {
		primary = algebra.Addition[E]
		secondary = algebra.Multiplication[E]
	} else {
		primary = algebra.Multiplication[E]
		secondary = algebra.Addition[E]
	}
	return &HemiRingal[R, E]{
		DoubleMagmatic:            *NewDoubleMagmaticPropertySuite(t, r, g, primary, true, isAdditionCommutative, secondary, true, isMultiplicationCommutative),
		AdditiveSemiGroupal:       *NewAdditiveSemiGroupalPropertySuite(t, r, g, isAdditionCommutative),
		MultiplicativeSemiGroupal: *NewMultiplicativeSemiGroupalPropertySuite(t, r, g, isMultiplicationCommutative),
	}
}

type HemiRingal[R algebra.HemiRing[E], E algebra.HemiRingElement[E]] struct {
	DoubleMagmatic[R, E]
	AdditiveSemiGroupal[R, E]
	MultiplicativeSemiGroupal[R, E]
}

func (r *HemiRingal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.DoubleMagmatic.CheckAll(t)
	r.AdditiveSemiGroupal.CheckAll(t)
	r.MultiplicativeSemiGroupal.CheckAll(t)
	t.Run("MulDistributesOverAdd", r.MulDistributesOverAdd)
}

func (r *HemiRingal[R, E]) MulDistributesOverAdd(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := r.AdditiveSemiGroupal.g.Draw(t, "a")
		b := r.AdditiveSemiGroupal.g.Draw(t, "b")
		c := r.AdditiveSemiGroupal.g.Draw(t, "c")

		// Left distributivity: a * (b + c) = (a * b) + (a * c)
		bc := r.op(b, c)
		left1 := r.otherOp(a, bc)
		ab := r.otherOp(a, b)
		ac := r.otherOp(a, c)
		right1 := r.op(ab, ac)
		require.True(t, left1.Equal(right1), "left distributivity failed")

		// Right distributivity: (a + b) * c = (a * c) + (b * c)
		ab2 := r.op(a, b)
		left2 := r.otherOp(ab2, c)
		ac2 := r.otherOp(a, c)
		bc2 := r.otherOp(b, c)
		right2 := r.op(ac2, bc2)
		require.True(t, left2.Equal(right2), "right distributivity failed")
	})
}

// ******************** SemiRing.

func NewSemiRingalPropertySuite[R algebra.SemiRing[E], E algebra.SemiRingElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
	additionIsPrimaryOperator bool,
) *SemiRingal[R, E] {
	t.Helper()
	return &SemiRingal[R, E]{
		HemiRingal:             *NewHemiRingalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative, additionIsPrimaryOperator),
		MultiplicativeMonoidal: *NewMultiplicativeMonoidalPropertySuite(t, r, g, isMultiplicationCommutative),
	}
}

type SemiRingal[R algebra.SemiRing[E], E algebra.SemiRingElement[E]] struct {
	HemiRingal[R, E]
	MultiplicativeMonoidal[R, E]
}

func (r *SemiRingal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.HemiRingal.CheckAll(t)
	r.MultiplicativeMonoidal.CheckAll(t)
}

// ******************** Rng.

func NewRngalPropertySuite[R algebra.Rng[E], E algebra.RngElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *Rngal[R, E] {
	t.Helper()
	return &Rngal[R, E]{
		HemiRingal:       *NewHemiRingalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative, true),
		AdditiveMonoidal: *NewAdditiveMonoidalPropertySuite(t, r, g, isAdditionCommutative),
	}
}

type Rngal[R algebra.Rng[E], E algebra.RngElement[E]] struct {
	HemiRingal[R, E]
	AdditiveMonoidal[R, E]
}

func (r *Rngal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.HemiRingal.CheckAll(t)
	r.AdditiveMonoidal.CheckAll(t)
	t.Run("Zero Annihilates", r.ZeroAnnihilates)
}

func (r *Rngal[R, E]) ZeroAnnihilates(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := r.AdditiveMonoidal.g.Draw(t, "a")
		zero := r.AdditiveMonoidal.identity

		// 0 * a = 0
		left := r.otherOp(zero, a)
		require.True(t, left.Equal(zero), "left zero annihilation failed: 0*a != 0")

		// a * 0 = 0
		right := r.otherOp(a, zero)
		require.True(t, right.Equal(zero), "right zero annihilation failed: a*0 != 0")
	})
}

// ******************** Rig.

func NewRigalPropertySuite[R algebra.Rig[E], E algebra.RigElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *Rigal[R, E] {
	t.Helper()
	return &Rigal[R, E]{
		SemiRingal:       *NewSemiRingalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative, true),
		AdditiveMonoidal: *NewAdditiveMonoidalPropertySuite(t, r, g, isAdditionCommutative),
	}
}

type Rigal[R algebra.Rig[E], E algebra.RigElement[E]] struct {
	SemiRingal[R, E]
	AdditiveMonoidal[R, E]
}

func (r *Rigal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.SemiRingal.CheckAll(t)
	r.AdditiveMonoidal.CheckAll(t)
	t.Run("Zero Annihilates", r.ZeroAnnihilates)
}

func (r *Rigal[R, E]) ZeroAnnihilates(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := r.AdditiveMonoidal.g.Draw(t, "a")
		zero := r.AdditiveMonoidal.identity

		// 0 * a = 0
		left := r.otherOp(zero, a)
		require.True(t, left.Equal(zero), "left zero annihilation failed: 0*a != 0")

		// a * 0 = 0
		right := r.otherOp(a, zero)
		require.True(t, right.Equal(zero), "right zero annihilation failed: a*0 != 0")
	})
}

// ******************** EuclideanSemiDomain.

func NewEuclideanSemiDomainalPropertySuite[R algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *EuclideanSemiDomainal[R, E] {
	t.Helper()
	return &EuclideanSemiDomainal[R, E]{
		Rigal: *NewRigalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative),
	}
}

type EuclideanSemiDomainal[R algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]] struct {
	Rigal[R, E]
}

func (r *EuclideanSemiDomainal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.Rigal.CheckAll(t)
	t.Run("EuclideanDivision", r.EuclideanDivision)
}

func (r *EuclideanSemiDomainal[R, E]) EuclideanDivision(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := r.Rigal.AdditiveMonoidal.g.Draw(t, "a")
		b := r.Rigal.AdditiveMonoidal.g.Filter(func(x E) bool { return !x.IsZero() }).Draw(t, "b")

		quot, rem, err := a.EuclideanDiv(b)
		if err != nil {
			return
		}

		// a = quot * b + rem
		quotTimesB := r.Rigal.SemiRingal.otherOp(quot, b)
		result := r.Rigal.SemiRingal.op(quotTimesB, rem)
		require.True(t, result.Equal(a), "euclidean division property failed: a != quot*b + rem")

		// rem should have smaller valuation than b (or be zero)
		if !rem.IsZero() {
			remVal := rem.EuclideanValuation()
			bVal := b.EuclideanValuation()
			require.True(t, remVal.IsLessThanOrEqual(bVal) && !remVal.Equal(bVal),
				"remainder valuation should be less than divisor valuation")
		}
	})
}

// ******************** Ring.

func NewRingalPropertySuite[R algebra.Ring[E], E algebra.RingElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *Ringal[R, E] {
	t.Helper()
	return &Ringal[R, E]{
		Rigal: *NewRigalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative),
		Rngal: *NewRngalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative),
	}
}

type Ringal[R algebra.Ring[E], E algebra.RingElement[E]] struct {
	Rigal[R, E]
	Rngal[R, E]
}

func (r *Ringal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.Rigal.CheckAll(t)
	r.Rngal.CheckAll(t)
}

// ******************** Euclidean Domain.

func NewEuclideanDomainalPropertySuite[R algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]](
	t *testing.T, r R, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *EuclideanDomainal[R, E] {
	t.Helper()
	require.True(t, r.IsSemiDomain())
	return &EuclideanDomainal[R, E]{
		EuclideanSemiDomainal: *NewEuclideanSemiDomainalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative),
		Ringal:                *NewRingalPropertySuite(t, r, g, isAdditionCommutative, isMultiplicationCommutative),
	}
}

type EuclideanDomainal[R algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]] struct {
	EuclideanSemiDomainal[R, E]
	Ringal[R, E]
}

func (r *EuclideanDomainal[R, E]) CheckAll(t *testing.T) {
	t.Helper()
	r.EuclideanSemiDomainal.CheckAll(t)
	r.Ringal.CheckAll(t)
}

// ******************** Field.

func NewFieldalPropertySuite[F algebra.Field[E], E algebra.FieldElement[E]](
	t *testing.T, f F, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *Fieldal[F, E] {
	t.Helper()
	require.Greater(t, f.ExtensionDegree(), 0)
	return &Fieldal[F, E]{
		EuclideanDomainal:      *NewEuclideanDomainalPropertySuite(t, f, g, isAdditionCommutative, isMultiplicationCommutative),
		MultiplicativeMonoidal: *NewMultiplicativeMonoidalPropertySuite(t, f, g, isMultiplicationCommutative),
	}
}

type Fieldal[F algebra.Field[E], E algebra.FieldElement[E]] struct {
	EuclideanDomainal[F, E]
	MultiplicativeMonoidal[F, E]
}

func (f *Fieldal[F, E]) CheckAll(t *testing.T) {
	t.Helper()
	f.EuclideanDomainal.CheckAll(t)
	f.MultiplicativeMonoidal.CheckAll(t)
	t.Run("NonZeroElementsHaveInverse", f.NonZeroElementsHaveInverse)
}

func (f *Fieldal[F, E]) NonZeroElementsHaveInverse(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := f.MultiplicativeMonoidal.g.Filter(func(x E) bool { return !x.IsZero() }).Draw(t, "a")

		inv, err := a.TryInv()
		require.NoError(t, err, "non-zero element should have multiplicative inverse")
		require.NotNil(t, inv)

		// a * a^(-1) = 1
		product := f.otherOp(a, inv)
		require.True(t, product.Equal(f.MultiplicativeMonoidal.identity), "a * inv(a) should equal 1")

		// a^(-1) * a = 1
		product2 := f.otherOp(inv, a)
		require.True(t, product2.Equal(f.MultiplicativeMonoidal.identity), "inv(a) * a should equal 1")
	})
}

// ******************** FieldExtension.

func NewFieldExtensionalPropertySuite[F algebra.FieldExtension[E], E algebra.FieldExtensionElement[E]](
	t *testing.T, f F, g *rapid.Generator[E],
	isAdditionCommutative, isMultiplicationCommutative bool,
) *FieldExtensional[F, E] {
	t.Helper()
	return &FieldExtensional[F, E]{
		Fieldal: *NewFieldalPropertySuite(t, f, g, isAdditionCommutative, isMultiplicationCommutative),
	}
}

type FieldExtensional[F algebra.FieldExtension[E], E algebra.FieldExtensionElement[E]] struct {
	Fieldal[F, E]
}

func (f *FieldExtensional[F, E]) CheckAll(t *testing.T) {
	t.Helper()
	f.Fieldal.CheckAll(t)
	t.Run("ComponentsBytesRoundTrip", f.ComponentsBytesRoundTrip)
}

func (f *FieldExtensional[F, E]) ComponentsBytesRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := f.Fieldal.MultiplicativeMonoidal.g.Draw(t, "a")

		components := a.ComponentsBytes()
		require.NotNil(t, components)

		recovered, err := f.st.FromComponentsBytes(components)
		require.NoError(t, err, "FromComponentsBytes should succeed for valid components")

		require.True(t, recovered.Equal(a), "round-trip through ComponentsBytes should preserve value")
	})
}
