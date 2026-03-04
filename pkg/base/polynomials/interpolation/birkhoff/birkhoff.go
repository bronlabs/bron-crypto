package birkhoff

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/birkhoff/internal"
	"github.com/bronlabs/errs-go/errs"
)

// Interpolate reconstructs a polynomial from Birkhoff interpolation nodes.
// Each triple (xs[i], js[i], ys[i]) represents the js[i]-th derivative value
// of the polynomial evaluated at xs[i].
func Interpolate[F algebra.PrimeFieldElement[F]](xs []F, js []uint64, ys []F) (*polynomials.Polynomial[F], error) {
	if len(xs) != len(js) || len(xs) != len(ys) {
		return nil, errs.New("validation failed").WithMessage("x, j, and y must have the same length")
	}
	if len(xs) == 0 {
		return nil, polynomials.ErrValidation.WithMessage("no nodes")
	}

	xs, js, ys = internal.SortNodes(xs, js, ys)
	field := algebra.StructureMustBeAs[algebra.PrimeField[F]](xs[0].Structure())
	denMatrix, err := BuildVandermondeMatrix(xs, js)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not build vandermonde matrix")
	}
	den := denMatrix.Determinant()
	if den.IsZero() {
		return nil, polynomials.ErrFailed.WithMessage("determinant is zero")
	}

	var coeffs []F
	for c := range xs {
		numMatrix, err := denMatrix.SetColumn(c, ys)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not set column")
		}
		num := numMatrix.Determinant()
		coeff, err := num.TryDiv(den)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cdivision by zero")
		}
		coeffs = append(coeffs, coeff)
	}
	polyRing, err := polynomials.NewPolynomialRing(field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	poly, err := polyRing.New(coeffs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create polynomial")
	}

	return poly, nil
}

// BuildVandermondeMatrix constructs the generalized Vandermonde matrix used by
// Birkhoff interpolation for nodes (xs[i], js[i]).
func BuildVandermondeMatrix[F algebra.PrimeFieldElement[F]](xs []F, js []uint64) (*mat.SquareMatrix[F], error) {
	if len(xs) != len(js) {
		return nil, errs.New("validation failed").WithMessage("x and j must have the same length")
	}

	var coeffs []F
	for r := range xs {
		for c := range xs {
			coeff, err := internal.Phi(c, xs[r], js[r])
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not compute phi")
			}
			coeffs = append(coeffs, coeff)
		}
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[F]](xs[0].Structure())
	matrices, err := mat.NewMatrixAlgebra(uint(len(xs)), field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create matrix algebra")
	}
	matrix, err := matrices.NewRowMajor(coeffs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create matrix")
	}
	return matrix, nil
}
