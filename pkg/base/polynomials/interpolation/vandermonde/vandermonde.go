package vandermonde

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

// Interpolate computes the unique polynomial of degree < len(nodes) that evaluates to values[i] at nodes[i] for each i.
func Interpolate[FE algebra.FiniteFieldElement[FE]](nodes, values []FE, at FE) (*polynomials.Polynomial[FE], error) {
	if len(nodes) != len(values) {
		return nil, polynomials.ErrLengthMismatch.WithMessage("nodes and values")
	}
	field := algebra.StructureMustBeAs[algebra.FiniteField[FE]](at.Structure())

	columnFactory, err := mat.NewMatrixModule(uint(len(nodes)), 1, field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create column factory")
	}
	valuesVector, err := columnFactory.NewRowMajor(values...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create values vector")
	}

	vandermondeMatrix, err := BuildVandermondeMatrix(nodes, uint(len(nodes)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create vandermonde matrix")
	}

	coeffsRow, err := mat.SolveRight(vandermondeMatrix, valuesVector)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not solve linear system")
	}

	polyRing, err := polynomials.NewPolynomialRing(field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	poly, err := polyRing.New(slices.Collect(coeffsRow.Iter())...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial")
	}
	return poly, nil
}

// BuildVandermondeMatrix constructs an n × cols Vandermonde matrix where n = len(nodes).
// Entry (r, c) = nodes[r]^c.
func BuildVandermondeMatrix[E algebra.RingElement[E]](nodes []E, cols uint) (*mat.Matrix[E], error) {
	if len(nodes) == 0 {
		return nil, polynomials.ErrValidation.WithMessage("nodes must be non-empty")
	}
	if cols == 0 {
		return nil, polynomials.ErrValidation.WithMessage("cols must be positive")
	}
	ring := algebra.StructureMustBeAs[algebra.FiniteRing[E]](nodes[0].Structure())
	n := len(nodes)
	c := int(cols)
	input := make([]E, n*c)
	for r, node := range nodes {
		input[r*c] = ring.One()
		for j := 1; j < c; j++ {
			input[r*c+j] = input[r*c+j-1].Mul(node)
		}
	}
	mod, err := mat.NewMatrixModule(uint(n), cols, ring)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create matrix module for vandermonde matrix")
	}
	out, err := mod.NewRowMajor(input...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create vandermonde matrix")
	}
	return out, nil
}
