package lagrange

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// L_i returns the i'th basis polynomial.
func L_i[S fields.PrimeFieldElement[S]](i int, xs []S, x S) (S, error) {
	var nilS S

	if i < 0 || i >= len(xs) {
		return nilS, errs.NewArgument("i is out of range")
	}
	field, err := fields.GetPrimeField(x)
	if err != nil {
		return nilS, errs.NewFailed("cannot get field")
	}

	numerator := field.One()
	denominator := field.One()
	for j, xj := range xs {
		if j == i {
			continue
		}
		numerator = numerator.Mul(xj.Sub(x))
		denominator = denominator.Mul(xj.Sub(xs[i]))
		if denominator.IsZero() {
			return nilS, errs.NewValue("division by zero")
		}
	}
	nOverD, err := numerator.TryDiv(denominator)
	if err != nil {
		return nilS, errs.WrapFailed(err, "division by zero")
	}
	return nOverD, nil
}

// Basis computes the set of basis polynomials, and returns a map from i to L_i.
func Basis[S fields.PrimeFieldElement[S]](xs []S, x S) (map[int]S, error) {
	result := make(map[int]S, len(xs))
	for i := range xs {
		li, err := L_i[S](i, xs, x)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not evaluate lagrange basis polynomial")
		}
		result[i] = li
	}
	return result, nil
}

func Interpolate[S fields.PrimeFieldElement[S]](xs, ys []S, evaluateAt S) (S, error) {
	var nilS S

	field, err := fields.GetPrimeField(evaluateAt)
	if err != nil {
		return nilS, errs.NewFailed("cannot get field")
	}
	result := field.Zero()
	ls, err := Basis[S](xs, evaluateAt)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not derive all basis polynomials")
	}
	for j, yj := range ys {
		lj := ls[j]
		result = result.Add(yj.Mul(lj))
	}
	return result, nil
}

//func InterpolateInTheExponent[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](xs []S, bigYs []P, evaluateAt S) (P, error) {
//	var nilP P
//
//	coefficients := make([]S, len(xs))
//	ls, err := Basis[S](xs, evaluateAt)
//	if err != nil {
//		return nilP, errs.WrapFailed(err, "could not compute all basis polynomials")
//	}
//	for i := 0; i < len(xs); i++ {
//		coefficients[i] = ls[i]
//	}
//	result, err := curve.MultiScalarMult(coefficients, bigYs)
//	if err != nil {
//		return nil, errs.WrapFailed(err, "MSM failed")
//	}
//	return result, nil
//}
