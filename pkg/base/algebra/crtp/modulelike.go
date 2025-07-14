package crtp

import (
	"io"
)

type Actable[E, S any] interface {
	ScalarOp(actor S) E
}

type AdditivelyActable[E, S any] interface {
	Actable[E, S]
	ScalarMul(actor S) E
}

type MultiplicativelyActable[E, S any] interface {
	Actable[E, S]
	ScalarExp(actor S) E
}

// ****************** SemiModule

type SemiModule[SME, S any] interface {
	Monoid[SME]
	ScalarStructure() Structure[S]
	MultiScalarOp(scalars []S, elements []SME) (SME, error)
}

type SemiModuleElement[SME, S any] interface {
	MonoidElement[SME]
	Actable[SME, S]
	IsTorsionFree() bool
}

type AdditiveSemiModule[SME, S any] interface {
	SemiModule[SME, S]
	AdditiveMonoid[SME]
	MultiScalarMul(scalars []S, elements []SME) (SME, error)
}

type AdditiveSemiModuleElement[SME, S any] interface {
	SemiModuleElement[SME, S]
	AdditiveMonoidElement[SME]
	AdditivelyActable[SME, S]
}

type MultiplicativeSemiModule[SME, S any] interface {
	SemiModule[SME, S]
	MultiplicativeMonoid[SME]
	MultiScalarExp(scalars []S, elements []SME) (SME, error)
}
type MultiplicativeSemiModuleElement[SME, S any] interface {
	SemiModuleElement[SME, S]
	MultiplicativeMonoidElement[SME]
	MultiplicativelyActable[SME, S]
}

// ****************** Module

type Module[ME, S any] interface {
	Group[ME]
	SemiModule[ME, S]
}

type ModuleElement[ME, S any] interface {
	GroupElement[ME]
	SemiModuleElement[ME, S]
}

type AdditiveModule[ME, S any] interface {
	Module[ME, S]
	AdditiveSemiModule[ME, S]
	AdditiveGroup[ME]
}

type AdditiveModuleElement[ME, S any] interface {
	ModuleElement[ME, S]
	AdditiveGroupElement[ME]
	AdditiveSemiModuleElement[ME, S]
}

type MultiplicativeModule[ME, S any] interface {
	Module[ME, S]
	MultiplicativeGroup[ME]
	MultiplicativeSemiModule[ME, S]
}

type MultiplicativeModuleElement[ME, S any] interface {
	ModuleElement[ME, S]
	MultiplicativeGroupElement[ME]
	MultiplicativeSemiModuleElement[ME, S]
}

type ZLikeModule[E, R any] Module[E, R]
type ZLikeModuleElement[E, R any] ModuleElement[E, R]

// ****************** Vector Space

type VectorSpace[V, S any] Module[V, S]

type Vector[V, S any] ModuleElement[V, S]

// ****************** Algebra

type Algebra[AE, S any] interface {
	AdditiveModule[AE, S]
	Ring[AE]
}

type AlgebraElement[AE, S any] interface {
	AdditiveModuleElement[AE, S]
	RingElement[AE]
}

// ******************* Polynomials

type PolynomialLikeStructure[P, S, C any] interface {
	Module[P, S]
	CoefficientStructure() Structure[C]
}

type PolynomialLike[P, S, C any] interface {
	ModuleElement[P, S]
	ConstantTerm() C
	IsHomogeneous() bool
	IsConstant() bool
	IsMonic() bool
	Derivative() P
	Degree() int
	ScalarStructure() Structure[S]
	CoefficientStructure() Structure[C]
}

type UnivariatePolynomialLikeStructure[P, S, C any] interface {
	PolynomialLikeStructure[P, S, C]
	New(...C) (P, error)
}

type UnivariatePolynomialLike[P, S, C any] interface {
	PolynomialLike[P, S, C]
	Coefficients() []C
	LeadingCoefficient() C
	Eval(S) C
}

type PolynomialModule[MP, P, C, S any] interface {
	UnivariatePolynomialLikeStructure[MP, S, C]
	MultiPolynomialOp([]P, []MP) (MP, error)
}

type ModuleValuedPolynomial[MP, P, C, S any] interface {
	UnivariatePolynomialLike[MP, S, C]
	PolynomialOp(P) MP
}

type PolynomialRing[P, S any] interface {
	UnivariatePolynomialLikeStructure[P, S, S]
	Algebra[P, S]
	AdditiveModule[P, S]
	EuclideanDomain[P]
	RandomPolynomial(degree int, prng io.Reader) (P, error)
	RandomPolynomialWithConstantTerm(degree int, constantTerm S, prng io.Reader) (P, error)
}

type Polynomial[P, S any] interface {
	UnivariatePolynomialLike[P, S, S]
	AlgebraElement[P, S]
	AdditiveModuleElement[P, S]
	EuclideanDomainElement[P]
}

type MultivariatePolynomialRing[PP, P, S any] interface {
	PolynomialLikeStructure[PP, S, S]
	TensorProduct[PP, P, S]
}

type MultivariatePolynomial[PP, P, S any] interface {
	PolynomialLike[PP, S, S]
	Algebra[PP, S]
	AdditiveModule[PP, S]
	Tensor[PP, S]
	PolynomialOp(arity uint, polynomial P) PP
	Eval(...[]S) (S, error)
	PartialEval(arity uint, value S) (PP, error)
	PartialDerivative(arity uint) (PP, error)
	PartialDegree(arity uint) (int, error)
}
