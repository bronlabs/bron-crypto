package traits

import (
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

// PointWrapper exposes the underlying curve point.
type PointWrapper[FP fields.FiniteFieldElement[FP], P points.Point[FP, P]] interface {
	// P defines the P operation.
	P() P
}

// PointWrapperPtrConstraint restricts wrappers to pointer receivers.
type PointWrapperPtrConstraint[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], WT any] interface {
	*WT
	PointWrapper[FP, P]
}

// CurveTrait provides constructors and iterator helpers for curve points.
type CurveTrait[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
}

// Zero returns the curve's point at infinity.
func (c *CurveTrait[FP, P, W, WT]) Zero() W {
	var zero WT
	W(&zero).P().SetZero()
	return &zero
}

// Random samples a curve point using the provided PRNG.
func (c *CurveTrait[FP, P, W, WT]) Random(prng io.Reader) (W, error) {
	var p WT
	if ok := W(&p).P().SetRandom(prng); ok == 0 {
		return nil, curves.ErrRandomSample.WithMessage("cannot sample point")
	}
	return &p, nil
}

// Iter returns an iterator over points in the prime subgroup.
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

// OpIdentity returns the group operation identity.
func (c *CurveTrait[FP, P, W, WT]) OpIdentity() W {
	return c.Zero()
}

// PrimeSubGroupGenerator returns the designated prime subgroup generator.
func (c *CurveTrait[FP, P, W, WT]) PrimeSubGroupGenerator() W {
	var gen WT
	W(&gen).P().SetGenerator()
	return &gen
}

// PrimeCurveTrait provides helpers for prime-order curves.
type PrimeCurveTrait[FP fields.FiniteFieldElement[FP], P points.Point[FP, P], W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	CurveTrait[FP, P, W, WT]
}

// Generator returns the designated generator for the curve.
func (c *PrimeCurveTrait[FP, P, W, WT]) Generator() W {
	var gen WT
	W(&gen).P().SetGenerator()
	return &gen
}

// PointTrait implements common group operations for points.
type PointTrait[FP fields.FiniteFieldElement[FP], P points.PointPtr[FP, P, T], T any, W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	V T
}

// P returns the underlying point pointer.
func (p *PointTrait[FP, P, T, W, WT]) P() P {
	return &p.V
}

// Clone returns a new point with the same value.
func (p *PointTrait[FP, P, T, W, WT]) Clone() W {
	var clone WT
	W(&clone).P().Set(&p.V)
	return &clone
}

// Add returns the sum of this point and e.
func (p *PointTrait[FP, P, T, W, WT]) Add(e W) W {
	var sum WT
	W(&sum).P().Add(&p.V, e.P())
	return &sum
}

// Double returns the point doubled.
func (p *PointTrait[FP, P, T, W, WT]) Double() W {
	var doubled WT
	W(&doubled).P().Add(&p.V, &p.V)
	return &doubled
}

// TrySub returns the difference between this point and e.
func (p *PointTrait[FP, P, T, W, WT]) TrySub(e W) (W, error) {
	return p.Sub(e), nil
}

// Sub returns the difference between this point and e.
func (p *PointTrait[FP, P, T, W, WT]) Sub(e W) W {
	var diff WT
	W(&diff).P().Sub(&p.V, e.P())
	return &diff
}

// TryNeg returns the negation of this point.
func (p *PointTrait[FP, P, T, W, WT]) TryNeg() (W, error) {
	return p.Neg(), nil
}

// Neg returns the negation of this point.
func (p *PointTrait[FP, P, T, W, WT]) Neg() W {
	var neg WT
	W(&neg).P().Neg(&p.V)
	return &neg
}

// ClearCofactor clears the curve cofactor on this point.
func (p *PointTrait[FP, P, T, W, WT]) ClearCofactor() W {
	var torsionFree WT
	W(&torsionFree).P().ClearCofactor(&p.V)
	return &torsionFree
}

// IsZero reports whether this point is the identity.
func (p *PointTrait[FP, P, T, W, WT]) IsZero() bool {
	return P(&p.V).IsZero() == 1
}

// IsPrimeSubGroupDesignatedGenerator reports whether this point is the prime subgroup generator.
func (p *PointTrait[FP, P, T, W, WT]) IsPrimeSubGroupDesignatedGenerator() bool {
	var generator WT
	W(&generator).P().SetGenerator()
	return p.Equal(&generator)
}

// Equal reports whether this point equals rhs.
func (p *PointTrait[FP, P, T, W, WT]) Equal(rhs W) bool {
	return P(&p.V).Equal(rhs.P()) == 1
}

// Op returns the group operation result (addition).
func (p *PointTrait[FP, P, T, W, WT]) Op(e W) W {
	return p.Add(e)
}

// IsOpIdentity reports whether this point is the group identity.
func (p *PointTrait[FP, P, T, W, WT]) IsOpIdentity() bool {
	return p.IsZero()
}

// OpInv returns the group inverse of this point.
func (p *PointTrait[FP, P, T, W, WT]) OpInv() W {
	return p.Neg()
}

// TryOpInv returns the group inverse of this point.
func (p *PointTrait[FP, P, T, W, WT]) TryOpInv() (W, error) {
	return p.Neg(), nil
}

// PrimePointTrait provides helpers for prime-order points.
type PrimePointTrait[FP fields.FiniteFieldElement[FP], P points.PointPtr[FP, P, T], T any, W PointWrapperPtrConstraint[FP, P, WT], WT any] struct {
	PointTrait[FP, P, T, W, WT]
}

// IsDesignatedGenerator reports whether this point is the curve generator.
func (p *PrimePointTrait[FP, P, T, W, WT]) IsDesignatedGenerator() bool {
	var generator WT
	W(&generator).P().SetGenerator()
	return p.Equal(&generator)
}
