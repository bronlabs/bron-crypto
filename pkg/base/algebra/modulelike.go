package algebra

import (
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type (
	Actable[E, S any]                 aimpl.Actable[E, S]
	AdditivelyActable[E, S any]       aimpl.AdditivelyActable[E, S]
	MultiplicativelyActable[E, S any] aimpl.MultiplicativelyActable[E, S]

	Action[S SemiGroupElement[S], E Element[E]] func(actor S, element E) E
)

type (
	SemiModule[ME aimpl.SemiModuleElement[ME, S], S aimpl.SemiRingElement[S]]        = aimpl.SemiModule[ME, S]
	SemiModuleElement[ME aimpl.SemiModuleElement[ME, S], S aimpl.SemiRingElement[S]] = aimpl.SemiModuleElement[ME, S]

	ZLikeSemiModule[E aimpl.SemiModuleElement[E, S], S aimpl.IntLike[S]]        = aimpl.ZLikeSemiModule[E, S]
	ZLikeSemiModuleElement[E aimpl.SemiModuleElement[E, S], S aimpl.IntLike[S]] = aimpl.ZLikeSemiModuleElement[E, S]
)

type (
	Module[ME aimpl.ModuleElement[ME, S], S aimpl.RingElement[S]]        = aimpl.Module[ME, S]
	ModuleElement[ME aimpl.ModuleElement[ME, S], S aimpl.RingElement[S]] = aimpl.ModuleElement[ME, S]

	AdditiveModule[ME aimpl.AdditiveModuleElement[ME, S], S aimpl.RingElement[S]]        aimpl.AdditiveModule[ME, S]
	AdditiveModuleElement[ME aimpl.AdditiveModuleElement[ME, S], S aimpl.RingElement[S]] aimpl.AdditiveModuleElement[ME, S]

	MultiplicativeModule[ME aimpl.MultiplicativeModuleElement[ME, S], S aimpl.RingElement[S]]        aimpl.MultiplicativeModule[ME, S]
	MultiplicativeModuleElement[ME aimpl.MultiplicativeModuleElement[ME, S], S aimpl.RingElement[S]] aimpl.MultiplicativeModuleElement[ME, S]

	FiniteModule[ME aimpl.FiniteModuleElement[ME, S], S aimpl.FiniteRingElement[S]]        aimpl.FiniteModule[ME, S]
	FiniteModuleElement[ME aimpl.FiniteModuleElement[ME, S], S aimpl.FiniteRingElement[S]] aimpl.FiniteModuleElement[ME, S]

	ZLikeModule[E aimpl.ModuleElement[E, S], S aimpl.IntLike[S]]        = aimpl.ZLikeModule[E, S]
	ZLikeModuleElement[E aimpl.ModuleElement[E, S], S aimpl.IntLike[S]] = aimpl.ZLikeModuleElement[E, S]
)

type (
	VectorSpace[V aimpl.Vector[V, S], S aimpl.FieldElement[S]] aimpl.VectorSpace[V, S]
	Vector[V aimpl.Vector[V, S], S aimpl.FieldElement[S]]      aimpl.Vector[V, S]
)

type (
	Algebra[AE aimpl.AlgebraElement[AE, S], S aimpl.RingElement[S]]        aimpl.Algebra[AE, S]
	AlgebraElement[AE aimpl.AlgebraElement[AE, S], S aimpl.RingElement[S]] aimpl.AlgebraElement[AE, S]

	FiniteAlgebra[AE aimpl.FiniteAlgebraElement[AE, S], S aimpl.FiniteRingElement[S]]        aimpl.FiniteAlgebra[AE, S]
	FiniteAlgebraElement[AE aimpl.FiniteAlgebraElement[AE, S], S aimpl.FiniteRingElement[S]] aimpl.FiniteAlgebraElement[AE, S]
)

type (
	PolynomialLikeStructure[
		P aimpl.PolynomialLike[P, S, C],
		S aimpl.RingElement[S],
		C aimpl.GroupElement[C],
	] = aimpl.PolynomialLike[P, S, C]

	PolynomialLike[
		P aimpl.PolynomialLike[P, S, C],
		S aimpl.RingElement[S],
		C aimpl.GroupElement[C],
	] = aimpl.PolynomialLike[P, S, C]

	UnivariatePolynomialLikeStructure[
		P aimpl.UnivariatePolynomialLike[P, S, C],
		S aimpl.RingElement[S],
		C aimpl.GroupElement[C],
	] = aimpl.UnivariatePolynomialLikeStructure[P, S, C]

	UnivariatePolynomialLike[
		P aimpl.UnivariatePolynomialLike[P, S, C],
		S aimpl.RingElement[S],
		C aimpl.GroupElement[C],
	] = aimpl.UnivariatePolynomialLike[P, S, C]

	PolynomialModule[
		MP aimpl.ModuleValuedPolynomial[MP, P, C, S],
		P aimpl.Polynomial[P, S],
		C aimpl.ModuleElement[C, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.PolynomialModule[MP, P, C, S]
	ModuleValuedPolynomial[
		MP aimpl.ModuleValuedPolynomial[MP, P, C, S],
		P aimpl.Polynomial[P, S],
		C aimpl.ModuleElement[C, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.ModuleValuedPolynomial[MP, P, C, S]

	PolynomialRing[
		P aimpl.Polynomial[P, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.PolynomialRing[P, S]
	Polynomial[
		P aimpl.Polynomial[P, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.Polynomial[P, S]

	MultiVariatePolynomialRing[
		PP aimpl.MultivariatePolynomial[PP, P, S],
		P aimpl.Polynomial[P, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.MultivariatePolynomialRing[PP, P, S]
	MultivariatePolynomial[
		MP aimpl.MultivariatePolynomial[MP, P, S],
		P aimpl.Polynomial[P, S],
		S aimpl.FiniteRingElement[S],
	] = aimpl.MultivariatePolynomial[MP, P, S]
)
