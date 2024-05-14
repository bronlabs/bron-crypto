package algebra

type Ordering int

const (
	Incomparable Ordering = -2
	LessThan     Ordering = -1
	Equal        Ordering = 0
	GreaterThan  Ordering = 1
)

// OrderTheoreticLattice defines methods needed for a structured set to be a lattice.
// A lattice is a partially ordered set where every pair has a least upper bound (join) and a greatest lower bound (meet).
type OrderTheoreticLattice[L Structure, E Element] interface {
	// Lattice is a structured set.
	StructuredSet[L, E]
	// Join returns the least upper bound of x and y.
	Join(x OrderTheoreticLatticeElement[L, E], ys ...OrderTheoreticLatticeElement[L, E]) E
	// Meet returns the greatest lower bound of x and y.
	Meet(x OrderTheoreticLatticeElement[L, E], ys ...OrderTheoreticLatticeElement[L, E]) E

	LatticeElement() OrderTheoreticLatticeElement[L, E]
}

// OrderTheoreticLatticeElement defines methods needed for elements of type E to be elements of
// lattice S.
// A lattice is a set where every pair has a least upper bound (join) and a greatest lower bound (meet).
type OrderTheoreticLatticeElement[L Structure, E Element] interface {
	// Lattic element is an element of a structured set.
	StructuredSetElement[L, E]
	// Cmp returns one of:
	//  - Incomparable.
	//  - LessThan, if this element is less than rhs.
	//  - Equal, if this element is equal to rhs.
	//  - GreaterThan, if this element is greater than rhs.
	Cmp(rhs OrderTheoreticLatticeElement[L, E]) Ordering
	// Join returns the least upper bound of this element and rhs.
	Join(rhs OrderTheoreticLatticeElement[L, E]) E
	// Meet returns the greatest lower bound of this element and rhs.
	Meet(rhs OrderTheoreticLatticeElement[L, E]) E

	Lattice() OrderTheoreticLattice[L, E]
}

// Chain defines methods needed for S to be a totally ordered subset of some larger bounded lattice.
type Chain[C Structure, E Element] interface {
	OrderTheoreticLattice[C, E]
	// Max returns the maximum of the inputs.
	Max(x ChainElement[C, E], ys ...ChainElement[C, E]) E
	// Min returns the minimum of the inputs.
	Min(x ChainElement[C, E], ys ...ChainElement[C, E]) E

	ChainElement() ChainElement[C, E]
}

// ChainElement defined methods for elements of type E to be elements of chain S.
type ChainElement[C Structure, E Element] interface {
	OrderTheoreticLatticeElement[C, E]
	// Min returns the minimum of this element and rhs.
	Min(rhs ChainElement[C, E]) E
	// Max returns the maximum of this element and rhs.
	Max(rhs ChainElement[C, E]) E

	Chain() Chain[C, E]

	Increment() E
	Decrement() E
	NatLike[E]
}

// BoundedOrderTheoreticLattice defines additional methods for a lattice S for it to be considered as bounded.
type UpperBoundedOrderTheoreticLattice[L Structure, E Element] interface {
	OrderTheoreticLattice[L, E]
	// Top returns the maximum of S.
	Top() E

	UpperBoundedLatticeElement() UpperBoundedOrderTheoreticLatticeElement[L, E]
}

// BoundedOrderTheoreticLatticeElement defines additional methods for elements of type E to be elements of
// the bounded lattice S.
type UpperBoundedOrderTheoreticLatticeElement[L Structure, E Element] interface {
	OrderTheoreticLatticeElement[L, E]
	// IsTop returns true if this element is the maximum of S.
	IsTop() bool

	UpperBoundedLattice() UpperBoundedOrderTheoreticLattice[L, E]
}

// BoundedOrderTheoreticLattice defines additional methods for a lattice S for it to be considered as bounded.
type LowerBoundedOrderTheoreticLattice[L Structure, E Element] interface {
	OrderTheoreticLattice[L, E]
	// Bottom returns minimum of S.
	Bottom() E

	LowerBoundedLatticeElement() LowerBoundedOrderTheoreticLatticeElement[L, E]
}

// BoundedOrderTheoreticLatticeElement defines additional methods for elements of type E to be elements of
// the bounded lattice S.
type LowerBoundedOrderTheoreticLatticeElement[L Structure, E Element] interface {
	OrderTheoreticLatticeElement[L, E]
	// IsBottom returns true if this element is the minimum of S.
	IsBottom() bool

	LowerBoundedLattice() LowerBoundedOrderTheoreticLattice[L, E]
}

// BoundedOrderTheoreticLattice defines additional methods for a lattice S for it to be considered as bounded.
type BoundedOrderTheoreticLattice[L Structure, E Element] interface {
	UpperBoundedOrderTheoreticLattice[L, E]
	LowerBoundedOrderTheoreticLattice[L, E]

	BoundedLatticeElement() BoundedOrderTheoreticLatticeElement[L, E]
}

// BoundedOrderTheoreticLatticeElement defines additional methods for elements of type E to be elements of
// the bounded lattice S.
type BoundedOrderTheoreticLatticeElement[L Structure, E Element] interface {
	UpperBoundedOrderTheoreticLatticeElement[L, E]
	LowerBoundedOrderTheoreticLatticeElement[L, E]

	BoundedLattice() BoundedOrderTheoreticLattice[L, E]
}
