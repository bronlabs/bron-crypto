package polynomialsUtils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
)

// Li returns the i'th basis polynomial.
func Li[Field algebra.AbstractFiniteField[Field, FieldElement], FieldElement algebra.AbstractFiniteFieldElement[Field, FieldElement]](polynomialsSet *polynomials.UnivariatePolynomialsSet[Field, FieldElement], i int, xs []FieldElement) (*polynomials.UnivariatePolynomial[Field, FieldElement], error) {
	if i < 0 || i > len(xs) {
		return nil, errs.NewInvalidArgument("i is out of range")
	}
	numerator := polynomialsSet.MultiplicativeIdentity()
	denominator := polynomialsSet.InnerField().MultiplicativeIdentity()
	for j, xj := range xs {
		if j == i {
			continue
		}
		numeratorCoefficients := []FieldElement{xj.Neg(), polynomialsSet.InnerField().MultiplicativeIdentity()}
		numerator = numerator.Prod(polynomialsSet.NewUnivariatePolynomial(numeratorCoefficients))
		denominator = denominator.Mul(xs[i].Sub(xj))
		if denominator.IsAdditiveIdentity() {
			return nil, errs.NewDivisionByZero("denominator became zero")
		}
	}

	denominatorInv := denominator.MultiplicativeInverse()
	return numerator.ScalarMul(denominatorInv), nil
}

// LagrangeBasis computes the set of basis polynomials, and returns a map from i to L_i.
func LagrangeBasis[Field algebra.AbstractFiniteField[Field, FieldElement], FieldElement algebra.AbstractFiniteFieldElement[Field, FieldElement]](polynomialsSet *polynomials.UnivariatePolynomialsSet[Field, FieldElement], xs []FieldElement) (map[int]*polynomials.UnivariatePolynomial[Field, FieldElement], error) {
	result := make(map[int]*polynomials.UnivariatePolynomial[Field, FieldElement], len(xs))
	for i := range xs {
		li, err := Li(polynomialsSet, i, xs)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not evaluate lagrange basis polynomial i=%d", i)
		}
		result[i] = li
	}

	return result, nil
}

func Interpolate[Field algebra.AbstractFiniteField[Field, FieldElement], FieldElement algebra.AbstractFiniteFieldElement[Field, FieldElement]](polynomialsSet *polynomials.UnivariatePolynomialsSet[Field, FieldElement], xs, ys []FieldElement) (*polynomials.UnivariatePolynomial[Field, FieldElement], error) {
	result := polynomialsSet.AdditiveIdentity()
	ls, err := LagrangeBasis(polynomialsSet, xs)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive all basis polynomials")
	}
	for j, yj := range ys {
		lj := ls[j]
		result = result.Add(lj.ScalarMul(yj))
	}

	return result, nil
}

func InterpolateInTheExponent(curve curves.Curve, xs []curves.Scalar, ys []curves.Point, evaluateAt curves.Scalar) (curves.Point, error) {
	polynomialsSet := polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarField())
	ls, err := LagrangeBasis(polynomialsSet, xs)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials")
	}

	coefficients := make([]curves.Scalar, len(xs))
	for i := 0; i < len(xs); i++ {
		coefficients[i] = ls[i].Eval(evaluateAt)
	}
	result, err := curve.MultiScalarMult(coefficients, ys)
	if err != nil {
		return nil, errs.WrapFailed(err, "MSM failed")
	}
	return result, nil
}
