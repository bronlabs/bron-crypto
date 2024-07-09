package algebra

type Ordering int

const (
	Incomparable Ordering = -2
	LessThan     Ordering = -1
	Equal        Ordering = 0
	GreaterThan  Ordering = 1
)

type PoSet[S Set[E], E Element[E]] interface {
	Set[E]
	StructureWrapping[S, E]
}

type PoSetElement[E Element[E]] interface {
	Element[E]
	// Cmp returns one of:
	//  - Incomparable.
	//  - LessThan, if this element is less than rhs.
	//  - Equal, if this element is equal to rhs.
	//  - GreaterThan, if this element is greater than rhs.
	Cmp(rhs E) Ordering
}

type Lattice[L BiStructure[L, LE, OpJoin, OpMeet], LE LatticeElement[LE], OpJoin Join[LE], OpMeet Meet[LE]] interface {
	PoSet[L, LE]
	BiStructure[L, LE, OpJoin, OpMeet]
}

type LatticeElement[LE PoSetElement[LE]] interface {
	PoSetElement[LE]
}

type Chain[C Lattice[C, CE, OpJoin, OpMeet], CE ChainElement[CE], OpJoin Join[CE], OpMeet Meet[CE]] interface {
	Lattice[C, CE, OpJoin, OpMeet]
	Min(x CE, ys ...CE) CE
	Max(x CE, ys ...CE) CE
}

type ChainElement[LE LatticeElement[LE]] interface {
	LatticeElement[LE]
}

type UpperBoundedLattice[L Lattice[L, LE, OpJoin, OpMeet], LE UpperBoundedLatticeElement[LE], OpJoin Join[LE], OpMeet Meet[LE]] interface {
	Lattice[L, LE, OpJoin, OpMeet]
	Top() LE
}

type UpperBoundedLatticeElement[LE LatticeElement[LE]] interface {
	LatticeElement[LE]
	IsTop() bool
}

type LowerBoundedLattice[L Lattice[L, LE, OpJoin, OpMeet], LE LowerBoundedLatticeElement[LE], OpJoin Join[LE], OpMeet Meet[LE]] interface {
	Lattice[L, LE, OpJoin, OpMeet]
	Bottom() LE
}

type LowerBoundedLatticeElement[LE LatticeElement[LE]] interface {
	LatticeElement[LE]
	Bottom() bool
}

type BoundedLattice[L Lattice[L, LE, OpJoin, OpMeet], LE BoundedLatticeElement[LE], OpJoin Join[LE], OpMeet Meet[LE]] interface {
	UpperBoundedLattice[L, LE, OpJoin, OpMeet]
	LowerBoundedLattice[L, LE, OpJoin, OpMeet]
}

type BoundedLatticeElement[LE LatticeElement[LE]] interface {
	UpperBoundedLatticeElement[LE]
	LowerBoundedLatticeElement[LE]
}
