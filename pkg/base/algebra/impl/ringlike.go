package impl

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
	IsDomain() bool
}

type RingElement[RE any] interface {
	RigElement[RE]
	RngElement[RE]
}

type FiniteRing[RE any] interface {
	Ring[RE]
	FiniteStructure[RE]
}

type FiniteRingElement[RE any] RingElement[RE]

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

type Field[FE any] interface {
	EuclideanDomain[FE]
	ExtensionDegree() uint
}

type FieldElement[FE any] EuclideanDomainElement[FE]

type FiniteField[FE any] interface {
	Field[FE]
	FiniteRing[FE]
	// TODO: move to prime field
	FromWideBytes([]byte) (FE, error)
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element.
	WideElementSize() int
}

type FiniteFieldElement[FE any] interface {
	FieldElement[FE]
	FiniteRingElement[FE]
}

type FiniteFieldExtension[FE any] interface {
	FiniteField[FE]
	FromComponentsBytes([][]byte) (FE, error)
}

type FiniteFieldExtensionElement[FE any] interface {
	FiniteFieldElement[FE]
	ComponentsBytes() [][]byte
}
