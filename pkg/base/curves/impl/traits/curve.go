package traits

import (
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type PointWrapper[FP fields.FiniteFieldElement[FP], P points.Point[FP, P]] interface {
	P() P
}

type PointWrapperPtrConstraint[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], WT any] interface {
	*WT
	PointWrapper[FP, P]
}

type CurveTrait[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
}

func (c *CurveTrait[FP, P, W, WT]) Zero() W {
	var zero WT
	W(&zero).P().SetZero()
	return &zero
}

func (c *CurveTrait[FP, P, W, WT]) Random(prng io.Reader) (W, error) {
	var p WT
	if ok := W(&p).P().SetRandom(prng); ok == 0 {
		return nil, errs.NewRandomSample("cannot sample point")
	}
	return &p, nil
}

func (c *CurveTrait[FP, P, W, WT]) Iter() iter.Seq[W] {
	return func(yield func(W) bool) {
		generator := c.PrimeSubGroupGenerator()

		var current WT
		W(&current).P().Set(generator.P())

		for W(&current).P().IsZero() != 1 {
			if !yield(W(&current)) {
				break
			}
			W(&current).P().Add(W(&current).P(), generator.P())
		}
	}
}

func (c *CurveTrait[FP, P, W, WT]) OpIdentity() W {
	return c.Zero()
}

func (c *CurveTrait[FP, P, W, WT]) PrimeSubGroupGenerator() W {
	var gen WT
	W(&gen).P().SetGenerator()
	return &gen
}

type PrimeCurveTrait[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	CurveTrait[FP, P, W, WT]
}

func (c *PrimeCurveTrait[FP, P, W, WT]) Generator() W {
	var gen WT
	W(&gen).P().SetGenerator()
	return &gen
}

type MSMTrait[FE algebra.FieldElement[FE], P algebra.AdditiveModuleElement[P, FE]] struct {
}

func (t *MSMTrait[FE, P]) MultiScalarOp(scs []FE, ps []P) (P, error) {
	return t.MultiScalarMul(scs, ps)
}

func (*MSMTrait[FE, P]) MultiScalarMul(scs []FE, ps []P) (P, error) {
	if len(scs) != len(ps) {
		return *new(P), errs.NewLength("length of scalars and points must match")
	}
	if len(scs) == 0 {
		return *new(P), errs.NewValue("cannot perform multi-scalar operation on empty slices")
	}
	M, ok := ps[0].Structure().(algebra.AdditiveModule[P, FE])
	if !ok {
		return *new(P), errs.NewType("points do not have a module structure")
	}

	result := M.Zero()
	for i, p := range ps {
		result = result.Op(p.ScalarMul(scs[i]))
	}
	return result, nil
}

type PointTrait[FP fields.FiniteFieldElement[FP], P points.PointPtr[FP, P, T], T any, W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	V T
}

func (p *PointTrait[FP, P, T, W, WT]) P() P {
	return &p.V
}

func (p *PointTrait[FP, P, T, W, WT]) Clone() W {
	var clone WT
	W(&clone).P().Set(&p.V)
	return &clone
}

func (p *PointTrait[FP, P, T, W, WT]) Add(e W) W {
	var sum WT
	W(&sum).P().Add(&p.V, e.P())
	return &sum
}

func (p *PointTrait[FP, P, T, W, WT]) Double() W {
	var doubled WT
	W(&doubled).P().Add(&p.V, &p.V)
	return &doubled
}

func (p *PointTrait[FP, P, T, W, WT]) TrySub(e W) (W, error) {
	return p.Sub(e), nil
}

func (p *PointTrait[FP, P, T, W, WT]) Sub(e W) W {
	var diff WT
	W(&diff).P().Sub(&p.V, e.P())
	return &diff
}

func (p *PointTrait[FP, P, T, W, WT]) TryNeg() (W, error) {
	return p.Neg(), nil
}

func (p *PointTrait[FP, P, T, W, WT]) Neg() W {
	var neg WT
	W(&neg).P().Neg(&p.V)
	return &neg
}

func (p *PointTrait[FP, P, T, W, WT]) ClearCofactor() W {
	var torsionFree WT
	W(&torsionFree).P().ClearCofactor(&p.V)
	return &torsionFree
}

func (p *PointTrait[FP, P, T, W, WT]) IsZero() bool {
	return P(&p.V).IsZero() == 1
}

func (p *PointTrait[FP, P, T, W, WT]) IsPrimeSubGroupDesignatedGenerator() bool {
	var generator WT
	W(&generator).P().SetGenerator()
	return p.Equal(&generator)
}

func (p *PointTrait[FP, P, T, W, WT]) Equal(rhs W) bool {
	return P(&p.V).Equal(rhs.P()) == 1
}

func (p *PointTrait[FP, P, T, W, WT]) Op(e W) W {
	return p.Add(e)
}

func (p *PointTrait[FP, P, T, W, WT]) IsOpIdentity() bool {
	return p.IsZero()
}

func (p *PointTrait[FP, P, T, W, WT]) OpInv() W {
	return p.Neg()
}

func (p *PointTrait[FP, P, T, W, WT]) TryOpInv() (W, error) {
	return p.Neg(), nil
}

//func StringifyPoint[P algebra.AffinePoint[P, C], C algebra.RingElement[C]](obj P) string {
//	return fmt.Sprintf("(%s, %s)", obj.AffineX().String(), obj.AffineY().String())
//}.

type PrimePointTrait[FP fields.FiniteFieldElement[FP], P points.PointPtr[FP, P, T], T any, W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	PointTrait[FP, P, T, W, WT]
}

func (p *PrimePointTrait[FP, P, T, W, WT]) IsDesignatedGenerator() bool {
	var generator WT
	W(&generator).P().SetGenerator()
	return p.Equal(&generator)
}
