package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// ******************** Semi Module.

func NewSemiModularPropertySuite[
	SM algebra.SemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.SemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
](
	t *testing.T, semiModule SM, semiRing SR,
	gM *rapid.Generator[SME], gR *rapid.Generator[S],
	op func(a, b SME) SME,
	identity SME, isIdentity func(e SME) bool,
	scMul func(s S, m SME) SME,
) *SemiModular[SM, SR, SME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &SemiModular[SM, SR, SME, S]{
		Monoidal:   *NewMonoidalPropertySuite(t, semiModule, gM, op, true, identity, isIdentity),
		SemiRingal: *NewSemiRingalPropertySuite(t, semiRing, gR, true, true, true),
		scMul:      scMul,
	}
}

func NewAdditiveSemiModularPropertySuite[
	SM algebra.AdditiveSemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.AdditiveSemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
](
	t *testing.T, semiModule SM, semiRing SR,
	gM *rapid.Generator[SME], gR *rapid.Generator[S],
) *AdditiveSemiModular[SM, SR, SME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &AdditiveSemiModular[SM, SR, SME, S]{
		SemiModular: *NewSemiModularPropertySuite(t, semiModule, semiRing, gM, gR, algebra.Addition[SME], semiModule.Zero(), func(x SME) bool {
			return x.IsZero()
		}, algebra.ScalarMultiply[SME, S]),
	}
}

func NewMultiplicativeSemiModularPropertySuite[
	SM algebra.MultiplicativeSemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.MultiplicativeSemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
](
	t *testing.T, semiModule SM, semiRing SR,
	gM *rapid.Generator[SME], gR *rapid.Generator[S],
) *MultiplicativeSemiModular[SM, SR, SME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &MultiplicativeSemiModular[SM, SR, SME, S]{
		SemiModular: *NewSemiModularPropertySuite(t, semiModule, semiRing, gM, gR, algebra.Multiplication[SME], semiModule.One(), func(x SME) bool {
			return x.IsOne()
		}, algebra.ScalarExponentiate[SME, S]),
	}
}

type SemiModular[
	SM algebra.SemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.SemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
] struct {
	Monoidal[SM, SME]
	SemiRingal[SR, S]
	scMul func(s S, m SME) SME
}

func (r *SemiModular[SM, SR, SME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.Monoidal.CheckAll(t)
	r.SemiRingal.CheckAll(t)
	t.Run("ScalarMulLeftDistributesOverGroupOp", r.ScalarMulLeftDistributesOverGroupOp)
}

func (r *SemiModular[SM, SR, SME, S]) ScalarMulLeftDistributesOverGroupOp(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := r.SemiRingal.g.Draw(t, "s")
		a := r.Monoidal.g.Draw(t, "a")
		b := r.Monoidal.g.Draw(t, "b")

		// Left distributivity: a * (b + c) = (a * b) + (a * c)
		bc := r.op(a, b)
		left1 := r.scMul(s, bc)
		ab := r.scMul(s, a)
		ac := r.scMul(s, b)
		right1 := r.op(ab, ac)
		require.True(t, left1.Equal(right1), "left distributivity failed")
	})
}

type AdditiveSemiModular[
	SM algebra.AdditiveSemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.AdditiveSemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
] struct {
	SemiModular[SM, SR, SME, S]
}

func (r *AdditiveSemiModular[SM, SR, SME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.SemiModular.CheckAll(t)
}

type MultiplicativeSemiModular[
	SM algebra.MultiplicativeSemiModule[SME, S],
	SR algebra.SemiRing[S],
	SME algebra.MultiplicativeSemiModuleElement[SME, S],
	S algebra.SemiRingElement[S],
] struct {
	SemiModular[SM, SR, SME, S]
}

func (r *MultiplicativeSemiModular[SM, SR, SME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.SemiModular.CheckAll(t)
}

// ******************** Module.

func NewModularPropertySuite[
	M algebra.Module[ME, S],
	R algebra.Ring[S],
	ME algebra.ModuleElement[ME, S],
	S algebra.RingElement[S],
](
	t *testing.T, module M, ring R,
	gM *rapid.Generator[ME], gR *rapid.Generator[S],
	op func(a, b ME) ME,
	identity ME, isIdentity func(e ME) bool,
	opInv func(a ME) ME,
	scMul func(s S, m ME) ME,
) *Modular[M, R, ME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &Modular[M, R, ME, S]{
		SemiModular: *NewSemiModularPropertySuite(t, module, ring, gM, gR, op, identity, isIdentity, scMul),
		Groupal:     *NewGroupalPropertySuite(t, module, gM, op, true, identity, isIdentity, opInv),
		Ringal:      *NewRingalPropertySuite(t, ring, gR, true, true),
	}
}

func NewAdditiveModularPropertySuite[
	M algebra.AdditiveModule[ME, S],
	R algebra.Ring[S],
	ME algebra.AdditiveModuleElement[ME, S],
	S algebra.RingElement[S],
](
	t *testing.T, module M, ring R,
	gM *rapid.Generator[ME], gR *rapid.Generator[S],
) *AdditiveModular[M, R, ME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &AdditiveModular[M, R, ME, S]{
		Modular: *NewModularPropertySuite(t, module, ring, gM, gR, algebra.Addition[ME], module.Zero(), func(x ME) bool {
			return x.IsZero()
		}, algebra.Negate[ME], algebra.ScalarMultiply[ME, S]),
		AdditiveSemiModular: *NewAdditiveSemiModularPropertySuite(t, module, ring, gM, gR),
		AdditiveGroupal:     *NewAdditiveGroupalPropertySuite(t, module, gM, true),
	}
}

func NewMultiplicativeModularPropertySuite[
	M algebra.MultiplicativeModule[ME, S],
	R algebra.Ring[S],
	ME algebra.MultiplicativeModuleElement[ME, S],
	S algebra.RingElement[S],
](
	t *testing.T, module M, ring R,
	gM *rapid.Generator[ME], gR *rapid.Generator[S],
) *MultiplicativeModular[M, R, ME, S] {
	t.Helper()
	require.NotNil(t, gM, "module element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &MultiplicativeModular[M, R, ME, S]{
		Modular: *NewModularPropertySuite(t, module, ring, gM, gR, algebra.Multiplication[ME], module.One(), func(x ME) bool {
			return x.IsOne()
		}, algebra.Invert[ME], algebra.ScalarExponentiate[ME, S]),
		MultiplicativeSemiModular: *NewMultiplicativeSemiModularPropertySuite(t, module, ring, gM, gR),
		MultiplicativeGroupal:     *NewMultiplicativeGroupalPropertySuite(t, module, gM, true),
	}
}

type Modular[
	M algebra.Module[ME, S],
	R algebra.Ring[S],
	ME algebra.ModuleElement[ME, S],
	S algebra.RingElement[S],
] struct {
	SemiModular[M, R, ME, S]
	Groupal[M, ME]
	Ringal[R, S]
}

func (r *Modular[M, R, ME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.SemiModular.CheckAll(t)
	r.Groupal.CheckAll(t)
	r.Ringal.CheckAll(t)
}

type AdditiveModular[
	M algebra.AdditiveModule[ME, S],
	R algebra.Ring[S],
	ME algebra.AdditiveModuleElement[ME, S],
	S algebra.RingElement[S],
] struct {
	Modular[M, R, ME, S]
	AdditiveSemiModular[M, R, ME, S]
	AdditiveGroupal[M, ME]
}

func (r *AdditiveModular[M, R, ME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.Modular.CheckAll(t)
	r.AdditiveSemiModular.CheckAll(t)
	r.AdditiveGroupal.CheckAll(t)
}

type MultiplicativeModular[
	M algebra.MultiplicativeModule[ME, S],
	R algebra.Ring[S],
	ME algebra.MultiplicativeModuleElement[ME, S],
	S algebra.RingElement[S],
] struct {
	Modular[M, R, ME, S]
	MultiplicativeSemiModular[M, R, ME, S]
	MultiplicativeGroupal[M, ME]
}

func (r *MultiplicativeModular[M, R, ME, S]) CheckAll(t *testing.T) {
	t.Helper()
	r.Modular.CheckAll(t)
	r.MultiplicativeSemiModular.CheckAll(t)
	r.MultiplicativeGroupal.CheckAll(t)
}

// ******************** Vector Space.

func NewVectorSpatialPropertySuite[
	VS algebra.VectorSpace[V, FE],
	F algebra.Field[FE],
	V algebra.Vector[V, FE],
	FE algebra.FieldElement[FE],
](
	t *testing.T, vectorSpace VS, field F,
	gVS *rapid.Generator[V], gF *rapid.Generator[FE],
	op func(a, b V) V,
	identity V, isIdentity func(e V) bool,
	opInv func(a V) V,
	scMul func(s FE, m V) V,
) *VectorSpatial[VS, F, V, FE] {
	t.Helper()
	require.NotNil(t, gVS, "vector element generator must not be nil")
	require.NotNil(t, gF, "field element generator must not be nil")
	return &VectorSpatial[VS, F, V, FE]{
		Modular: *NewModularPropertySuite(t, vectorSpace, field, gVS, gF, op, identity, isIdentity, opInv, scMul),
	}
}

func NewAdditiveVectorSpatialPropertySuite[
	VS algebra.VectorSpace[V, FE],
	F algebra.Field[FE],
	V algebra.Vector[V, FE],
	FE algebra.FieldElement[FE],
](
	t *testing.T, vectorSpace VS, field F,
	gVS *rapid.Generator[V], gF *rapid.Generator[FE],
) *AdditiveVectorSpatial[VS, F, V, FE] {
	t.Helper()
	require.NotNil(t, gVS, "vector element generator must not be nil")
	require.NotNil(t, gF, "field element generator must not be nil")
	return &AdditiveVectorSpatial[VS, F, V, FE]{
		AdditiveModular: *NewAdditiveModularPropertySuite(t, vectorSpace, field, gVS, gF),
	}
}

type VectorSpatial[
	VS algebra.VectorSpace[V, FE],
	F algebra.Field[FE],
	V algebra.Vector[V, FE],
	FE algebra.FieldElement[FE],
] struct {
	Modular[VS, F, V, FE]
}

func (r *VectorSpatial[VS, F, V, FE]) CheckAll(t *testing.T) {
	t.Helper()
	r.Modular.CheckAll(t)
}

type AdditiveVectorSpatial[
	VS algebra.VectorSpace[V, FE],
	F algebra.Field[FE],
	V algebra.Vector[V, FE],
	FE algebra.FieldElement[FE],
] struct {
	AdditiveModular[VS, F, V, FE]
}

func (r *AdditiveVectorSpatial[VS, F, V, FE]) CheckAll(t *testing.T) {
	t.Helper()
	r.AdditiveModular.CheckAll(t)
}

// ******************** Algebra.

func NewAlgebraicPropertySuite[
	A algebra.Algebra[AE, RE],
	R algebra.Ring[RE],
	AE algebra.AlgebraElement[AE, RE],
	RE algebra.RingElement[RE],
](
	t *testing.T, ralgebra A, baseRing R,
	gA *rapid.Generator[AE], gR *rapid.Generator[RE],
) *Algebraic[A, R, AE, RE] {
	t.Helper()
	require.NotNil(t, gA, "algebra element generator must not be nil")
	require.NotNil(t, gR, "ring element generator must not be nil")
	return &Algebraic[A, R, AE, RE]{
		AdditiveModular: *NewAdditiveModularPropertySuite(t, ralgebra, baseRing, gA, gR),
		Ringal:          *NewRingalPropertySuite(t, ralgebra, gA, true, true),
	}
}

type Algebraic[
	A algebra.Algebra[AE, RE],
	R algebra.Ring[RE],
	AE algebra.AlgebraElement[AE, RE],
	RE algebra.RingElement[RE],
] struct {
	AdditiveModular[A, R, AE, RE]
	Ringal[A, AE]
}

func (r *Algebraic[A, R, AE, RE]) CheckAll(t *testing.T) {
	t.Helper()
	r.AdditiveModular.CheckAll(t)
	r.Ringal.CheckAll(t)
}
