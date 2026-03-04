package testutils

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

// LiftedPoly wraps a module-valued polynomial (the lifted dealer function)
// and provides the ShareOf/Accepts/Op/Repr interface required by meta Feldman
// and meta Pedersen schemes.
type LiftedPoly[
	E algebra.ModuleElement[E, FE],
	FE algebra.PrimeFieldElement[FE],
	AC accessstructures.Monotone,
] struct {
	poly  *polynomials.ModuleValuedPolynomial[E, FE]
	field algebra.PrimeField[FE]
}

// ShareOf evaluates the lifted polynomial at the field element corresponding
// to the given shareholder ID, returning a LiftedEval.
func (lp *LiftedPoly[E, FE, AC]) ShareOf(id sharing.ID) *LiftedEval[E] {
	point := lp.field.FromUint64(uint64(id))
	value := lp.poly.Eval(point)
	return &LiftedEval[E]{id: id, value: value}
}

// Accepts returns true if the lifted polynomial is non-nil (valid).
func (lp *LiftedPoly[E, FE, AC]) Accepts(_ AC) bool {
	return lp.poly != nil
}

// Op returns a new LiftedPoly that is the coefficient-wise sum of two
// lifted polynomials.
func (lp *LiftedPoly[E, FE, AC]) Op(other *LiftedPoly[E, FE, AC]) *LiftedPoly[E, FE, AC] {
	return &LiftedPoly[E, FE, AC]{
		poly:  lp.poly.Op(other.poly),
		field: lp.field,
	}
}

// Repr yields the coefficients of the lifted polynomial.
func (lp *LiftedPoly[E, FE, AC]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, c := range lp.poly.Coefficients() {
			if !yield(c) {
				return
			}
		}
	}
}

// LiftedEval wraps an evaluated group element for a specific shareholder.
type LiftedEval[E base.Equatable[E]] struct {
	id    sharing.ID
	value E
}

// ID returns the shareholder identifier.
func (le *LiftedEval[E]) ID() sharing.ID {
	return le.id
}

// Repr yields the single evaluated value.
func (le *LiftedEval[E]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		yield(le.value)
	}
}

// Equal returns true if two LiftedEvals have the same ID and value.
func (le *LiftedEval[E]) Equal(other *LiftedEval[E]) bool {
	if le == nil || other == nil {
		return le == other
	}
	return le.id == other.id && le.value.Equal(other.value)
}

// HashCode returns a hash code for this lifted evaluation.
func (le *LiftedEval[E]) HashCode() base.HashCode {
	return base.HashCode(le.id)
}

// LiftPolynomialDealerFunc lifts a scalar polynomial into a module-valued
// polynomial by multiplying each coefficient by the base point.
func LiftPolynomialDealerFunc[
	E algebra.ModuleElement[E, FE],
	FE algebra.PrimeFieldElement[FE],
	AC accessstructures.Monotone,
](poly *polynomials.Polynomial[FE], basePoint E) (*LiftedPoly[E, FE, AC], error) {
	lifted, err := polynomials.LiftPolynomial(poly, basePoint)
	if err != nil {
		return nil, err
	}
	field := algebra.StructureMustBeAs[algebra.PrimeField[FE]](poly.ScalarStructure())
	return &LiftedPoly[E, FE, AC]{
		poly:  lifted,
		field: field,
	}, nil
}

// LiftShareValue lifts a scalar share value into the group by computing
// basePoint * value (scalar multiplication).
func LiftShareValue[
	E algebra.ModuleElement[E, FE],
	FE algebra.PrimeFieldElement[FE],
](value FE, basePoint E) (E, error) {
	return basePoint.ScalarOp(value), nil
}
