package algebra

// ******************** BiMagma

type DoubleMagma[E DoubleMagmaElement[E]] interface {
	Magma[E]
	OtherOperator() BinaryOperator[E]
}
type DoubleMagmaElement[E MagmaElement[E]] interface {
	MagmaElement[E]
	OtherOp(E) E
}

// ******************** HemiRing
type HemiRing[E HemiRingElement[E]] interface {
	DoubleMagma[E]
	AdditiveSemiGroup[E]
	MultiplicativeSemiGroup[E]
	Characteristic() Cardinal
}

type HemiRingElement[E SemiGroupElement[E]] interface {
	DoubleMagmaElement[E]
	AdditiveSemiGroupElement[E]
	MultiplicativeSemiGroupElement[E]
}

// ******************** SemiRing

type SemiRing[RE SemiRingElement[RE]] interface {
	HemiRing[RE]
	MultiplicativeMonoid[RE]
}

type SemiRingElement[RE HemiRingElement[RE]] interface {
	HemiRingElement[RE]
	MultiplicativeMonoidElement[RE]
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

// ******************** SemiDomain

type EuclideanSemiDomain[RE EuclideanSemiDomainElement[RE]] interface {
	Rig[RE]
	UniqueFactorizationMonoid[RE]
}

type EuclideanSemiDomainElement[RE RigElement[RE]] interface {
	RigElement[RE]
	UniqueFactorizationMonoidElement[RE]
	EuclideanDiv(rhs RE) (quot, rem RE, err error)
}

// ******************** Rng

type Rng[RE RngElement[RE]] interface {
	HemiRing[RE]
	AdditiveGroup[RE]
}

type RngElement[RE interface {
	HemiRingElement[RE]
	AdditiveGroupElement[RE]
}] interface {
	HemiRingElement[RE]
	AdditiveGroupElement[RE]
}

// ******************** Ring

type Ring[RE RingElement[RE]] interface {
	Rig[RE]
	Rng[RE]
}

type RingElement[RE interface {
	RigElement[RE]
	RngElement[RE]
}] interface {
	RigElement[RE]
	RngElement[RE]
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

	ExtensionDegree() uint
	// SubFieldElement returns a field element in F_p, a subfield of F_{p^k} depending on its extension degree k:
	//  - For k>1 (with subfields F_{p_1}, ..., F_{p_k}), the element of F_{p_((i+1)%k)}.
	//  - For k=1, the element itself (in F_p already) regardless of i.
	SubFieldIdentity(i uint) (any, error)
}

type FieldElement[FE EuclideanDomainElement[FE]] interface {
	EuclideanDomainElement[FE]
}

type FiniteField[FE FiniteFieldElement[FE]] interface {
	Field[FE]
	FiniteStructure[FE]
}

type FiniteFieldElement[FE FieldElement[FE]] interface {
	FieldElement[FE]
}
