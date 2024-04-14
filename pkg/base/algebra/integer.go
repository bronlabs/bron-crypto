package algebra

type N[S Structure, E Element] interface {
	Chain[S, E]
	New(v uint64) E
	Zero() E
	One() E
}

type Nat[S Structure, E Element] interface {
	ChainElement[S, E]
	Enumerable[E]
	IsZero() bool
	IsOne() bool

	IsEven() bool
	IsOdd() bool

	Increment()
	Decrement()
}

// type AbstractSetOfIntegers[S Structure, E Element] interface {
// 	OrderTheoreticLattice[S, E]
// 	New(v uint64) E
// 	Zero() E
// 	One() E
// }

// type AbstractInteger[S Structure, E Element] interface {
// 	OrderTheoreticLatticeElement[S, E]
// 	Enumerable[E]
// 	IsZero() bool
// 	IsOne() bool

// 	IsEven() bool
// 	IsOdd() bool

// 	Neg() E

// 	Increment()
// 	Decrement()

// 	NatSerialization[E]
// }

// type AbstractSetOfCongruentIntegers[S Structure, E Element] interface {
// 	FiniteStructure
// 	AbstractSetOfIntegers[S, E]
// 	Chain[S, E]
// 	ConjunctiveMonoid[S, E]
// 	DisjunctiveMonoid[S, E]
// 	ExclusiveDisjunctiveGroup[S, E]
// }

// type AbstractCongruentInteger[S Structure, E Element] interface {
// 	AbstractInteger[S, E]
// 	ChainElement[S, E]
// 	ConjunctiveMonoidElement[S, E]
// 	DisjunctiveMonoidElement[S, E]
// 	ExclusiveDisjunctiveGroupElement[S, E]
// 	BitWiseElement[E]
// }

// Z defines methods for S for it to behave like the integers.
type Z[S Structure, E Element] interface {
	AbstractSetOfIntegers[S, E]
	EuclideanDomain[S, E]
}

// Integer defines methods for element of type E to be elements of the integers S.
type Integer[S Structure, E Element] interface {
	AbstractInteger[S, E]
	EuclideanDomainElement[S, E]
}

// Zn defines methods for S to behave like ring of integers modulo n.
type Zn[S Structure, E Element] interface {
	AbstractSetOfCongruentIntegers[S, E]
	FiniteRing[S, E]
	IsDecomposable(coprimeIdealNorms ...E) (bool, error)
}

// Uint defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type Uint[S Structure, E Element] interface {
	AbstractCongruentInteger[S, E]
	FiniteRingElement[S, E]
}

type MultiplicativeIntegerGroup[G Structure, E Element] interface {
	MultiplicativeGroup[G, E]
	AbstractSetOfCongruentIntegers[G, E]
}

type MultiplicativeIntegerGroupElement[G Structure, E Element] interface {
	MultiplicativeGroupElement[G, E]
	AbstractCongruentInteger[G, E]
}

// Zp defines methods for S to behave the field of integers modulo prime.
type Zp[S Structure, E Element] interface {
	AbstractSetOfCongruentIntegers[S, E]
	FiniteField[S, E]
}

// IntegerFieldElement defines methods for elements of type E to behave as
// elements of the integer field modulo prime.
type IntegerFieldElement[S Structure, E Element] interface {
	AbstractCongruentInteger[S, E]
	FiniteFieldElement[S, E]
}
