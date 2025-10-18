package crtp

// ******************** BiMagma

type DoubleMagma[E any] Magma[E]
type DoubleMagmaElement[E any] interface {
	MagmaElement[E]
	OtherOp(E) E
}

// ******************** HemiRing
type HemiRing[E any] interface {
	DoubleMagma[E]
	AdditiveSemiGroup[E]
	MultiplicativeSemiGroup[E]
	Characteristic() Cardinal
}

type HemiRingElement[E any] interface {
	DoubleMagmaElement[E]
	AdditiveSemiGroupElement[E]
	MultiplicativeSemiGroupElement[E]
}

// ******************** SemiRing

type SemiRing[RE any] interface {
	HemiRing[RE]
	MultiplicativeMonoid[RE]
}

type SemiRingElement[RE any] interface {
	HemiRingElement[RE]
	MultiplicativeMonoidElement[RE]
}

// ******************** Rig

type Rig[RE any] interface {
	SemiRing[RE]
	AdditiveMonoid[RE]
}

type RigElement[RE any] interface {
	SemiRingElement[RE]
	AdditiveMonoidElement[RE]
}

// ******************** SemiDomain

type EuclideanSemiDomain[RE any] interface {
	Rig[RE]
	UniqueFactorizationMonoid[RE]
}

type EuclideanSemiDomainElement[RE any] interface {
	RigElement[RE]
	UniqueFactorizationMonoidElement[RE]
	EuclideanDiv(rhs RE) (quot, rem RE, err error)
	EuclideanValuation() RE
}

// ******************** Rng

type Rng[RE any] interface {
	HemiRing[RE]
	AdditiveGroup[RE]
}

type RngElement[RE any] interface {
	HemiRingElement[RE]
	AdditiveGroupElement[RE]
}

// ******************** Ring

type Ring[RE any] interface {
	Rig[RE]
	Rng[RE]
	IsSemiDomain() bool
}

type RingElement[RE any] interface {
	RigElement[RE]
	RngElement[RE]
}

// ******************** Domains

type EuclideanDomain[RE any] interface {
	Ring[RE]
	EuclideanSemiDomain[RE]
}

type EuclideanDomainElement[RE any] interface {
	RingElement[RE]
	EuclideanSemiDomainElement[RE]
}

// ******************** Fields

// TODO: add finite field back
type Field[FE any] interface {
	EuclideanDomain[FE]
	ExtensionDegree() uint
}

type FieldElement[FE any] EuclideanDomainElement[FE]

type FieldExtension[FE any] interface {
	Field[FE]
	FromComponentsBytes([][]byte) (FE, error)
}

type FieldExtensionElement[FE any] interface {
	FieldElement[FE]
	ComponentsBytes() [][]byte
}

type FiniteField[FE any] interface {
	Field[FE]
	FiniteStructure[FE]
}

type FiniteFieldElement[FE any] FieldElement[FE]
