package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	Actable[E, S any]                 crtp.Actable[E, S]
	AdditivelyActable[E, S any]       crtp.AdditivelyActable[E, S]
	MultiplicativelyActable[E, S any] crtp.MultiplicativelyActable[E, S]

	Action[S, E any] func(actor S, element E) E
)

type (
	SemiModule[ME crtp.SemiModuleElement[ME, S], S crtp.SemiRingElement[S]]        = crtp.SemiModule[ME, S]
	SemiModuleElement[ME crtp.SemiModuleElement[ME, S], S crtp.SemiRingElement[S]] = crtp.SemiModuleElement[ME, S]

	AdditiveSemiModule[ME crtp.AdditiveSemiModuleElement[ME, S], S crtp.SemiRingElement[S]]        crtp.AdditiveSemiModule[ME, S]
	AdditiveSemiModuleElement[ME crtp.AdditiveSemiModuleElement[ME, S], S crtp.SemiRingElement[S]] crtp.AdditiveSemiModuleElement[ME, S]

	MultiplicativeSemiModule[ME crtp.MultiplicativeSemiModuleElement[ME, S], S crtp.SemiRingElement[S]]        crtp.MultiplicativeSemiModule[ME, S]
	MultiplicativeSemiModuleElement[ME crtp.MultiplicativeSemiModuleElement[ME, S], S crtp.SemiRingElement[S]] crtp.MultiplicativeSemiModuleElement[ME, S]
)

type (
	Module[ME crtp.ModuleElement[ME, S], S crtp.RingElement[S]]        = crtp.Module[ME, S]
	ModuleElement[ME crtp.ModuleElement[ME, S], S crtp.RingElement[S]] = crtp.ModuleElement[ME, S]

	AdditiveModule[ME crtp.AdditiveModuleElement[ME, S], S crtp.RingElement[S]]        crtp.AdditiveModule[ME, S]
	AdditiveModuleElement[ME crtp.AdditiveModuleElement[ME, S], S crtp.RingElement[S]] crtp.AdditiveModuleElement[ME, S]

	MultiplicativeModule[ME crtp.MultiplicativeModuleElement[ME, S], S crtp.RingElement[S]]        crtp.MultiplicativeModule[ME, S]
	MultiplicativeModuleElement[ME crtp.MultiplicativeModuleElement[ME, S], S crtp.RingElement[S]] crtp.MultiplicativeModuleElement[ME, S]

	ZLikeModule[E crtp.ModuleElement[E, S], S crtp.IntLike[S]]        = crtp.ZLikeModule[E, S]
	ZLikeModuleElement[E crtp.ModuleElement[E, S], S crtp.IntLike[S]] = crtp.ZLikeModuleElement[E, S]
)

type (
	VectorSpace[V crtp.Vector[V, S], S crtp.FieldElement[S]] crtp.VectorSpace[V, S]
	Vector[V crtp.Vector[V, S], S crtp.FieldElement[S]]      crtp.Vector[V, S]
)

type (
	Algebra[AE crtp.AlgebraElement[AE, S], S crtp.RingElement[S]]        crtp.Algebra[AE, S]
	AlgebraElement[AE crtp.AlgebraElement[AE, S], S crtp.RingElement[S]] crtp.AlgebraElement[AE, S]
)

type (
	PolynomialLikeStructure[
		P crtp.PolynomialLike[P, S, C],
		S crtp.RingElement[S],
		C crtp.GroupElement[C],
	] = crtp.PolynomialLike[P, S, C]

	PolynomialLike[
		P crtp.PolynomialLike[P, S, C],
		S crtp.RingElement[S],
		C crtp.GroupElement[C],
	] = crtp.PolynomialLike[P, S, C]

	UnivariatePolynomialLikeStructure[
		P crtp.UnivariatePolynomialLike[P, S, C],
		S crtp.RingElement[S],
		C crtp.GroupElement[C],
	] = crtp.UnivariatePolynomialLikeStructure[P, S, C]

	UnivariatePolynomialLike[
		P crtp.UnivariatePolynomialLike[P, S, C],
		S crtp.RingElement[S],
		C crtp.GroupElement[C],
	] = crtp.UnivariatePolynomialLike[P, S, C]

	PolynomialModule[
		MP crtp.ModuleValuedPolynomial[MP, P, C, S],
		P crtp.Polynomial[P, S],
		C crtp.ModuleElement[C, S],
		S crtp.RingElement[S],
	] = crtp.PolynomialModule[MP, P, C, S]
	ModuleValuedPolynomial[
		MP crtp.ModuleValuedPolynomial[MP, P, C, S],
		P crtp.Polynomial[P, S],
		C crtp.ModuleElement[C, S],
		S crtp.RingElement[S],
	] = crtp.ModuleValuedPolynomial[MP, P, C, S]

	PolynomialRing[
		P crtp.Polynomial[P, S],
		S crtp.RingElement[S],
	] = crtp.PolynomialRing[P, S]
	Polynomial[
		P crtp.Polynomial[P, S],
		S crtp.RingElement[S],
	] = crtp.Polynomial[P, S]

	MultiVariatePolynomialRing[
		PP crtp.MultivariatePolynomial[PP, P, S],
		P crtp.Polynomial[P, S],
		S crtp.RingElement[S],
	] = crtp.MultivariatePolynomialRing[PP, P, S]
	MultivariatePolynomial[
		MP crtp.MultivariatePolynomial[MP, P, S],
		P crtp.Polynomial[P, S],
		S crtp.RingElement[S],
	] = crtp.MultivariatePolynomial[MP, P, S]
)
