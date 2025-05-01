package algebra

import "github.com/cronokirby/saferith"

type NPlusLike[E NatPlusLike[E]] interface {
	HemiRing[E]
}

type NatPlusLike[E HemiRingElement[E]] interface {
	HemiRingElement[E]
	Comparable[E]
}

type NLike[E NatLike[E]] interface {
	NPlusLike[E]
	EuclideanSemiDomain[E]
}

type NatLike[E EuclideanSemiDomainElement[E]] interface {
	NatPlusLike[E]
	EuclideanSemiDomainElement[E]
}

type ZLike[E IntLike[E]] EuclideanDomain[E]

type IntLike[E interface {
	EuclideanDomainElement[E]
	Comparable[E]
}] interface {
	EuclideanDomainElement[E]
	Comparable[E]
}

type ZnLike[E UintLike[E]] interface {
	ZLike[E]
	FiniteStructure[E]

	FromSafeNat(*saferith.Nat) (E, error)
}

type UintLike[E IntLike[E]] interface {
	IntLike[E]
	SafeNat() *saferith.Nat
	Exp(exponent E) E
}

type PrimeField[E interface {
	FiniteFieldElement[E]
	UintLike[E]
}] interface {
	FiniteField[E]
	ZnLike[E]
}

type PrimeFieldElement[E interface {
	FiniteFieldElement[E]
	UintLike[E]
}] interface {
	FiniteFieldElement[E]
	UintLike[E]
}
