package algebra

import (
	"github.com/cronokirby/saferith"
)

// ******************** HemiRing
type HemiRing[E HemiRingElement[E]] interface {
	AdditiveSemiGroup[E]
	MultiplicativeSemiGroup[E]
}

type HemiRingElement[E SemiGroupElement[E]] interface {
	AdditiveSemiGroupElement[E]
	MultiplicativeSemiGroupElement[E]
}

// ******************** SemiRing

type SemiRing[RE SemiRingElement[RE]] interface {
	HemiRing[RE]
	MultiplicativeMonoid[RE]
	Characteristic() Cardinal
}

type SemiRingElement[RE HemiRingElement[RE]] interface {
	HemiRingElement[RE]
	MultiplicativeMonoidElement[RE]
	OtherOp(rhs RE) RE
}

// ******************** SemiDomain

type EuclideanSemiDomain[RE EuclideanSemiDomainElement[RE]] interface {
	SemiRing[RE]
	UniqueFactorizationMonoid[RE]
}

type EuclideanSemiDomainElement[RE SemiRingElement[RE]] interface {
	SemiRingElement[RE]
	UniqueFactorizationMonoidElement[RE]
	EuclideanDiv(rhs RE) (quot, rem RE)
}

// ******************** Rig

type Rig[RE RigElement[RE]] interface {
	SemiRing[RE]
	AdditiveMonoid[RE]
}

type RigElement[RE SemiRingElement[RE]] interface {
	SemiRingElement[RE]
	AdditiveMonoidElement[RE]
}

// ******************** Ring

type Ring[RE RingElement[RE]] interface {
	Rig[RE]
	AdditiveGroup[RE]
}

type RingElement[RE interface {
	RigElement[RE]
	AdditiveGroupElement[RE]
}] interface {
	RigElement[RE]
	AdditiveGroupElement[RE]
}

// ******************** Domains

type EuclideanDomain[RE EuclideanDomainElement[RE]] interface {
	Ring[RE]
	EuclideanSemiDomain[RE]
}

type EuclideanDomainElement[RE interface {
	RingElement[RE]
	EuclideanSemiDomainElement[RE]
}] interface {
	RingElement[RE]
	EuclideanSemiDomainElement[RE]
}

// ******************** Fields

type Field[FE FieldElement[FE]] interface {
	EuclideanDomain[FE]
	MultiplicativeGroupWithZero[FE]

	ExtensionDegree() uint
	// SubFieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubFieldIdentity(i uint) (any, error)
}

type FieldElement[FE interface {
	EuclideanDomainElement[FE]
	MultiplicativeGroupWithZeroElement[FE]
}] interface {
	EuclideanDomainElement[FE]
	MultiplicativeGroupWithZeroElement[FE]
}

type FiniteField[FE FiniteFieldElement[FE]] interface {
	Field[FE]
	FiniteStructure[FE]
}

type FiniteFieldElement[FE FieldElement[FE]] FieldElement[FE]

type PrimeField[E FieldElement[E]] interface {
	FiniteField[E]

	FromNat(*saferith.Nat) E
}

type PrimeFieldElement[E FiniteFieldElement[E]] interface {
	FiniteFieldElement[E]
	IsEven() bool
	IsOdd() bool

	Nat() *saferith.Nat
}
