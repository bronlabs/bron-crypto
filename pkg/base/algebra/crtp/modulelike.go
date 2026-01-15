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

// ****************** SemiModule.

type SemiModule[SME, S any] interface {
	Monoid[SME]
	ScalarStructure() Structure[S]
}

type SemiModuleElement[SME, S any] interface {
	MonoidElement[SME]
	Actable[SME, S]
	IsTorsionFree() bool
}

type AdditiveSemiModule[SME, S any] interface {
	SemiModule[SME, S]
	AdditiveMonoid[SME]
}

type AdditiveSemiModuleElement[SME, S any] interface {
	SemiModuleElement[SME, S]
	AdditiveMonoidElement[SME]
	AdditivelyActable[SME, S]
}

type MultiplicativeSemiModule[SME, S any] interface {
	SemiModule[SME, S]
	MultiplicativeMonoid[SME]
}
type MultiplicativeSemiModuleElement[SME, S any] interface {
	SemiModuleElement[SME, S]
	MultiplicativeMonoidElement[SME]
	MultiplicativelyActable[SME, S]
}

// ****************** Module.

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

type FiniteModule[ME, S any] interface {
	Module[ME, S]
	FiniteStructure[ME]
}

// ****************** Vector Space.

type VectorSpace[V, S any] Module[V, S]

type Vector[V, S any] ModuleElement[V, S]

// ****************** Algebra.

type Algebra[AE, S any] interface {
	AdditiveModule[AE, S]
	Ring[AE]
}

type AlgebraElement[AE, S any] interface {
	AdditiveModuleElement[AE, S]
	RingElement[AE]
}

// ******************* Polynomials.

type PolynomialLikeStructure[P, S, C any] Module[P, S]

type PolynomialLike[P, S, C any] interface {
	ModuleElement[P, S]
	ConstantTerm() C
	IsConstant() bool
	Derivative() P
	Degree() int
}

type UnivariatePolynomialLikeStructure[P, S, C any] interface {
	PolynomialLikeStructure[P, S, C]
	New(...C) (P, error)
}

type UnivariatePolynomialLike[P, S, C, SS, CS any] interface {
	PolynomialLike[P, S, C]
	Coefficients() []C
	LeadingCoefficient() C
	Eval(S) C

	ScalarStructure() SS
	CoefficientStructure() CS
}

type PolynomialModule[MP, P, C, S any] interface {
	UnivariatePolynomialLikeStructure[MP, S, C]
	RandomModuleValuedPolynomial(degree int, prng io.Reader) (MP, error)
	RandomModuleValuedPolynomialWithConstantTerm(degree int, constantTerm C, prng io.Reader) (MP, error)
}

type ModuleValuedPolynomial[MP, P, C, S any] interface {
	UnivariatePolynomialLike[MP, S, C, Ring[S], FiniteModule[C, S]]
	PolynomialOp(P) MP
}

type PolynomialRing[P, S any] interface {
	UnivariatePolynomialLikeStructure[P, S, S]
	Algebra[P, S]
	EuclideanDomain[P]
	RandomPolynomial(degree int, prng io.Reader) (P, error)
	RandomPolynomialWithConstantTerm(degree int, constantTerm S, prng io.Reader) (P, error)
}

type Polynomial[P, S any] interface {
	UnivariatePolynomialLike[P, S, S, Ring[S], Ring[S]]
	AlgebraElement[P, S]
	EuclideanDomainElement[P]
	IsMonic() bool
}

type MultivariatePolynomialRing[PP, P, S any] interface {
	PolynomialLikeStructure[PP, S, S]
	TensorProduct[PP, P, S]
	CoefficientStructure() Structure[S]
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
