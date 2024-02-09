package polynomials

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type UnivariatePolynomialsSetTrait[InnerField algebra.AbstractFiniteField[InnerField, InnerFieldElement], InnerFieldElement algebra.AbstractFiniteFieldElement[InnerField, InnerFieldElement]] interface {
	NewUnivariatePolynomial(coefficients []InnerFieldElement) *UnivariatePolynomial[InnerField, InnerFieldElement]
	NewUnivariatePolynomialRandom(degree int, prng io.Reader) (*UnivariatePolynomial[InnerField, InnerFieldElement], error)
	NewUnivariatePolynomialRandomWithIntercept(degree int, intercept InnerFieldElement, prng io.Reader) (*UnivariatePolynomial[InnerField, InnerFieldElement], error)
	InnerField() InnerField
}

type UnivariatePolynomialTrait[InnerField algebra.AbstractFiniteField[InnerField, InnerFieldElement], InnerFieldElement algebra.AbstractFiniteFieldElement[InnerField, InnerFieldElement]] interface {
	Eval(at InnerFieldElement) InnerFieldElement
	Coefficients() []InnerFieldElement
	Derivative() *UnivariatePolynomial[InnerField, InnerFieldElement]

	Degree() int
	EuclideanDiv(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) (quo, rem *UnivariatePolynomial[InnerField, InnerFieldElement])
	EuclideanGcd(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement]
	EuclideanLcm(rhs *UnivariatePolynomial[InnerField, InnerFieldElement]) *UnivariatePolynomial[InnerField, InnerFieldElement]
}
