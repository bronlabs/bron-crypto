package algebra

type Ordering int

const (
	Incomparable Ordering = -2
	LessThan     Ordering = -1
	Equal        Ordering = 0
	GreaterThan  Ordering = 1
)

type Max[E Element] interface {
	BinaryOperator[E]
	Max(x, y E) E
}

type Min[E Element] interface {
	BinaryOperator[E]
	Min(x, y E) E
}

type Enumerable[E Element] interface {
	Next() (E, error)
	Previous() (E, error)
}

// OrderTheoreticLattice defines methods needed for a structured set to be a lattice.
// A lattice is a partially ordered set where every pair has a least upper bound (join) and a greatest lower bound (meet).
type OrderTheoreticLattice[L Structure, E Element] interface {
	// Lattice is a structured set.
	StructuredSet[L, E]
	// Join returns the least upper bound of x and y.
	Join(x, y OrderTheoreticLatticeElement[L, E]) E
	// Meet returns the greatest lower bound of x and y.
	Meet(x, y OrderTheoreticLatticeElement[L, E]) E

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
	Enumerable[E]
	// Min returns the minimum of this element and rhs.
	Min(rhs E) E
	// Max returns the maximum of this element and rhs.
	Max(rhs E) E

	Chain() Chain[C, E]

	Increment() E
	Decrement() E
	NatSerialization[E]
}

// BoundedOrderTheoreticLattice defines additional methods for a lattice S for it to be considered as bounded.
type BoundedOrderTheoreticLattice[L Structure, E Element] interface {
	OrderTheoreticLattice[L, E]
	// Top returns the maximum of S.
	Top() E
	// Bottom returns minimum of S.
	Bottom() E

	BoundedLatticeElement() BoundedOrderTheoreticLatticeElement[L, E]
}

// BoundedOrderTheoreticLatticeElement defines additional methods for elements of type E to be elements of
// the bounded lattice S.
type BoundedOrderTheoreticLatticeElement[L Structure, E Element] interface {
	OrderTheoreticLatticeElement[L, E]
	// IsTop returns true if this element is the maximum of S.
	IsTop() bool
	// IsBottom returns true if this element is the minimum of S.
	IsBottom() bool

	BoundedLattice() BoundedOrderTheoreticLattice[L, E]
}
