package traits

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"
)

type CurveTraitInheriter[FP fields.FiniteFieldElement[FP], P points.Point[FP, P]] interface {
	P() P
}

type CurveTraitInheriterPtrConstraint[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], WT any] interface {
	*WT
	CurveTraitInheriter[FP, P]
}

type Curve[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], W CurveTraitInheriterPtrConstraint[FP, P, WT], WT any] struct {
}

func (c *Curve[FP, P, W, WT]) Zero() W {
	var zero WT
	W(&zero).P().SetIdentity()
	return &zero
}

func (c *Curve[FP, P, W, WT]) Random(prng io.Reader) (W, error) {
	var p WT
	if ok := W(&p).P().SetRandom(prng); ok == 0 {
		return nil, errs.NewRandomSample("cannot sample point")
	}
	return &p, nil
}

func (c *Curve[FP, P, W, WT]) Generator() W {
	var gen WT
	W(&gen).P().SetGenerator()
	return &gen
}

func (c *Curve[FP, P, W, WT]) OpIdentity() W {
	return c.Zero()
}

func (c *Curve[FP, P, W, WT]) TorsionFreeSubGroupGenerator() W {
	return c.Generator()
}

type Point[FP fields.FiniteFieldElement[FP], P points.PointPtrConstraint[FP, P, T], T any, W CurveTraitInheriterPtrConstraint[FP, P, WT], WT any] struct {
	V T
}

func (p *Point[FP, P, T, W, WT]) Clone() W {
	var clone WT
	W(&clone).P().Set(&p.V)
	return &clone
}

func (p *Point[FP, P, T, W, WT]) Equal(rhs W) bool {
	return P(&p.V).Equals(rhs.P()) == 1
}

func (p *Point[FP, P, T, W, WT]) Add(e W) W {
	var sum WT
	W(&sum).P().Add(&p.V, e.P())
	return &sum
}

func (p *Point[FP, P, T, W, WT]) Sub(e W) W {
	var diff WT
	W(&diff).P().Sub(&p.V, e.P())
	return &diff
}

func (p *Point[FP, P, T, W, WT]) Neg() W {
	var neg WT
	W(&neg).P().Neg(&p.V)
	return &neg
}

func (p *Point[FP, P, T, W, WT]) IsZero() bool {
	return P(&p.V).IsIdentity() == 1
}

func (p *Point[FP, P, T, W, WT]) Op(e W) W {
	return p.Add(e)
}

func (p *Point[FP, P, T, W, WT]) ClearCofactor() W {
	var torsionFree WT
	W(&torsionFree).P().ClearCofactor(&p.V)
	return &torsionFree
}

func (p *Point[FP, P, T, W, WT]) IsDesignatedGenerator() bool {
	var generator WT
	W(&generator).P().SetGenerator()
	return p.Equal(&generator)
}

func (p *Point[FP, P, T, W, WT]) IsOpIdentity() bool {
	return p.IsZero()
}

func (p *Point[FP, P, T, W, WT]) OpInv() W {
	return p.Neg()
}

func (p *Point[FP, P, T, W, WT]) TryOpInv() (W, error) {
	return p.Neg(), nil
}
