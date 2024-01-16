package algebra

// AbstractZ defines methods for S for it to behave like the integers.
type AbstractZ[S Structure, E Element] interface {
	// Z forms a lattice.
	AbstractOrderTheoreticLattice[S, E]
	// New converts the input to an integer of type E.
	New(v uint64) E
	// Zero returns integer zero.
	Zero() E
	// One returns integer one.
	One() E
}

// AbstractInteger defines methods for element of type E to be elements of the integers S.
type AbstractInteger[S Structure, E Element] interface {
	// Integer is an element of a lattice.
	AbstractOrderTheoreticLatticeElement[S, E]
	// IsZero returns true if this element is zero.
	IsZero() bool
	// IsOne returns true if this element is one.
	IsOne() bool

	// IsEven returns true if this element is divisible by 2.
	IsEven() bool
	// IsOdd returns true if this element is not even.
	IsOdd() bool

	// Neg returns the additive inverse of this element.
	Neg() E

	// Increment mutates this element by adding one to it.
	Increment()
	// Decrement mutates this element by subtracting one from it.
	Decrement()
}

// AbstractZn defines methods for S to behave like ring of integers modulo n.
type AbstractZn[S Structure, E Element] interface {
	// Zn is a ring.
	AbstractRing[S, E]
	// Zn has methods of integers.
	AbstractZ[S, E]
	// Zn is totally ordered.
	AbstractChain[S, E]
}

// AbstractIntegerRingElement defines methods for elements of type E to behave
// like elements of the ring of integers modulo n.
type AbstractIntegerRingElement[S Structure, E Element] interface {
	// Integer ring element is a ring element.
	AbstractRingElement[S, E]
	// Integer ring element is an integer.
	AbstractInteger[S, E]
	// Integer rign element is part of a chain.
	AbstractChainElement[S, E]
}

// AbstractZp defines methods for S to behave the field of integers modulo prime.
type AbstractZp[S Structure, E Element] interface {
	// Zp is a finite field.
	AbstractFiniteField[S, E]
	// Zp has methods of integers.
	AbstractZ[S, E]
	// Zp is totally ordered.
	AbstractChain[S, E]
}

// AbstractIntegerFieldElement defines methods for elements of type E to behave as
// elements of the integer field modulo prime.
type AbstractIntegerFieldElement[S Structure, E Element] interface {
	// Integer field element is a field element.
	AbstractFiniteFieldElement[S, E]
	// Integer field element is an integer.
	AbstractInteger[S, E]
	// Integer field element is part of a chain.
	AbstractChainElement[S, E]
}
