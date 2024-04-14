package algebra

import "io"

type GenericPolynomial[PolynomialRingType, CoefficientRingType Structure, PolynomialType, CoefficientType Element] interface {
	UnitalAlgebraElement[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
	EuclideanDomainElement[PolynomialRingType, PolynomialType]
	Degree() int
	Dimension() uint
	Derivative() Polynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
}

type PolynomialRing[PolynomialRingType, CoefficientRingType Structure, PolynomialType, CoefficientType Element] interface {
	UnitalAlgebra[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
	EuclideanDomain[PolynomialRingType, PolynomialType]

	NewPolynomial(coefficients []CoefficientType) Polynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
	RandomPolynomial(degree int, prng io.Reader) (Polynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType], error)
	RandomPolynomialWithIntercept(degree int, intercept CoefficientType, prng io.Reader) (Polynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType], error)
}

type Polynomial[PolynomialRingType, CoefficientRingType Structure, PolynomialType, CoefficientType Element] interface {
	GenericPolynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
	Coefficients() []CoefficientType
	Eval(at CoefficientType) CoefficientType
}

type MultivariatePolynomialRing[MultivariatePolynomialRingType, CoefficientRingType Structure, MultivariatePolynomialType, CoefficientType Element] interface {
	UnitalAlgebra[MultivariatePolynomialRingType, CoefficientRingType, MultivariatePolynomialType, CoefficientType]
	EuclideanDomain[MultivariatePolynomialRingType, MultivariatePolynomialType]

	NewPolynomial(coefficients [][]CoefficientType) MultiVariatePolynomial[MultivariatePolynomialRingType, CoefficientRingType, MultivariatePolynomialType, CoefficientType]
	RandomPolynomial(degree int, dimension uint, prng io.Reader) (MultiVariatePolynomial[MultivariatePolynomialRingType, CoefficientRingType, MultivariatePolynomialType, CoefficientType], error)
	RandomPolynomialWithIntercepts(degree int, intercepts []CoefficientType, prng io.Reader) (MultiVariatePolynomial[MultivariatePolynomialRingType, CoefficientRingType, MultivariatePolynomialType, CoefficientType], error)
}

type MultiVariatePolynomial[PolynomialRingType, CoefficientRingType Structure, PolynomialType, CoefficientType Element] interface {
	GenericPolynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
	Coefficients() [][]CoefficientType
	Eval(at []CoefficientType) (CoefficientType, error)
	PartialDerivative(indeterminateIndices ...uint) MultiVariatePolynomial[PolynomialRingType, CoefficientRingType, PolynomialType, CoefficientType]
}
