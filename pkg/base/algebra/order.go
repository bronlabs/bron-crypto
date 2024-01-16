package algebra

type Ordering int

const (
	Incomparable Ordering = -2
	LessThan     Ordering = -1
	Equal        Ordering = 0
	GreaterThan  Ordering = 1
)

// AbstractOrderTheoreticLattice defines methods needed for a structured set to be a lattice.
// A lattice is a partially ordered set where every pair has a least upper bound (join) and a greatest lower bound (meet).
type AbstractOrderTheoreticLattice[S Structure, E Element] interface {
	// Lattice is a structured set.
	AbstractStructuredSet[S, E]
	// Join returns the least upper bound of x and y.
	Join(x, y E) E
	// Meet returns the greatest lower bound of x and y.
	Meet(x, y E) E
}

// AbstractOrderTheoreticLatticeElement defines methods needed for elements of type E to be elements of
// lattice S.
// A lattice is a set where every pair has a least upper bound (join) and a greatest lower bound (meet).
type AbstractOrderTheoreticLatticeElement[S Structure, E Element] interface {
	// Lattic element is an element of a structured set.
	AbstractStructuredSetElement[S, E]
	// Cmp returns one of:
	//  - Incomparable.
	//  - LessThan, if this element is less than rhs.
	//  - Equal, if this element is equal to rhs.
	//  - GreaterThan, if this element is greater than rhs.
	Cmp(rhs E) Ordering
	// Join returns the least upper bound of this element and rhs.
	Join(rhs E) E
	// Meet returns the greatest lower bound of this element and rhs.
	Meet(rhs E) E
}

// BoundedOrderTheoreticLatticeTrait defines additional methods for a lattice S for it to be considered as bounded.
type BoundedOrderTheoreticLatticeTrait[S Structure, E Element] interface {
	// Top returns the maximum of S.
	Top() E
	// Bottom returns minimum of S.
	Bottom() E
}

// BoundedOrderTheoreticLatticeElementTrait defines additional methods for elements of type E to be elements of
// the bounded lattice S.
type BoundedOrderTheoreticLatticeElementTrait[S Structure, E Element] interface {
	// IsTop returns true if this element is the maximum of S.
	IsTop() bool
	// IsBottom returns true if this element is the minimum of S.
	IsBottom() bool
}

// AbstractChain defines methods needed for S to be a totally subset of some larger bounded lattice.
type AbstractChain[S Structure, E Element] interface {
	// Chain is a lattice.
	AbstractOrderTheoreticLattice[S, E]
	// Chain has methods of a bounded lattice.
	BoundedOrderTheoreticLatticeTrait[S, E]
	// Max returns the maximum of the inputs.
	Max(x E, ys ...E) E
	// Min returns the minimum of the inputs.
	Min(x E, ys ...E) E
}

// AbstractChainElement defined methods for elements of type E to be elements of chain S.
type AbstractChainElement[S Structure, E Element] interface {
	// Chain element is a lattice element.
	AbstractOrderTheoreticLatticeElement[S, E]
	// Chain element has methods of a bounded lattice element.
	BoundedOrderTheoreticLatticeElementTrait[S, E]
	// Min returns the minimum of this element and rhs.
	Min(rhs E) E
	// Max returns the maximum of this element and rhs.
	Max(rhs E) E
}
