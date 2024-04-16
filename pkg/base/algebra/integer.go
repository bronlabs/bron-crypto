package algebra

type (
	PositiveN   IntegerInterval[PositiveN, PositiveNat]
	PositiveNat Number[PositiveN, PositiveNat]

	N   NaturalsRig[N, Nat]
	Nat NaturalNumber[N, Nat]

	Z   IntegerField[Z, Int]
	Int IntegerFieldElement[Z, Int]

	Zn   IntegerRing[Zn, Uint]
	Uint IntegerRingElement[Zn, Uint]

	ZnX  MultiplicativeIntegerGroup[ZnX, IntX]
	IntX MultiplicativeIntegerGroupElement[ZnX, IntX]

	Zp   IntegerFiniteField[Zp, IntP]
	IntP IntegerFieldElement[Zp, IntP]
)

type PositiveNaturalNumberGroupoid[S Structure, E Element] interface {
	Groupoid[S, E]
	Chain[S, E]
	New(v uint64) E
	One() E
}

type PositiveNaturalNumberGroupoidElement[S Structure, E Element] interface {
	GroupoidElement[S, E]
	ChainElement[S, E]
	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsNonZero() bool
	IsPositive() bool

	NatSerialization[E]
	IntSerialization[E]
}

type IntegerInterval[S Structure, E Element] interface {
	Rg[S, E]
	PositiveNaturalNumberGroupoid[S, E]
}

type Number[S Structure, E Element] interface {
	RgElement[S, E]
	PositiveNaturalNumberGroupoidElement[S, E]

	TrySub(x Number[S, E]) (E, error)
}

type NaturalNumberMonoid[S Structure, E Element] interface {
	Monoid[S, E]
	PositiveNaturalNumberGroupoid[S, E]
	Zero() E

	ConjunctiveMonoid[S, E]
	DisjunctiveMonoid[S, E]
	ExclusiveDisjunctiveGroup[S, E]
}

type NaturalNumberMonoidElement[S Structure, E Element] interface {
	MonoidElement[S, E]
	PositiveNaturalNumberGroupoidElement[S, E]
	IsZero() bool

	ConjunctiveMonoidElement[S, E]
	DisjunctiveMonoidElement[S, E]
	ExclusiveDisjunctiveGroupElement[S, E]
	BitWiseElement[E]
}

type NaturalsRig[S Structure, E Element] interface {
	Rig[S, E]
	NaturalNumberMonoid[S, E]
}

type NaturalNumber[S Structure, E Element] interface {
	RigElement[S, E]
	NaturalNumberMonoidElement[S, E]
}

// IntegerField defines methods for S for it to behave like the integers.
type IntegerField[S Structure, E Element] interface {
	NaturalsRig[S, E]
	EuclideanDomain[S, E]
}

// IntegerFieldElement defines methods for element of type E to be elements of the integers S.
type IntegerFieldElement[S Structure, E Element] interface {
	NaturalNumber[S, E] // Zigzag encoding nat
	EuclideanDomainElement[S, E]
}

// IntegerRing defines methods for S to behave like ring of integers modulo n.
type IntegerRing[S Structure, E Element] interface {
	NaturalsRig[S, E]
	FiniteRing[S, E]
	IsDecomposable(coprimeIdealNorms ...IntegerRingElement[S, E]) (bool, error)
}

// IntegerRingElement defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type IntegerRingElement[S Structure, E Element] interface {
	NaturalNumber[S, E]
	FiniteRingElement[S, E]
}

type MultiplicativeIntegerGroup[G Structure, E Element] interface {
	MultiplicativeGroup[G, E]
	NaturalNumberMonoid[G, E]
}

type MultiplicativeIntegerGroupElement[G Structure, E Element] interface {
	MultiplicativeGroupElement[G, E]
	NaturalNumberMonoidElement[G, E]
}

// IntegerFiniteField defines methods for S to behave the field of integers modulo prime.
type IntegerFiniteField[S Structure, E Element] interface {
	IntegerRing[S, E]
	EuclideanDomain[S, E]
	FiniteField[S, E]
}

// IntegerFiniteFieldElement defines methods for elements of type E to behave as
// elements of the integer field modulo prime.
type IntegerFiniteFieldElement[S Structure, E Element] interface {
	IntegerFieldElement[S, E]
	EuclideanDomainElement[S, E]
	FiniteFieldElement[S, E]
}
