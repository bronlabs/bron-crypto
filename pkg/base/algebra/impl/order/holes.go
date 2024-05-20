package order

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type HolesOrderTheoreticLattice[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] interface {
	Element() E
}

type HolesOrderTheoreticLatticeElement[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] interface {
	Structure() L
	Unwrap() E
	Cmp(rhs E) algebra.Ordering
	Equal(x E) bool
}

type HolesChain[C algebra.Chain[C, E], E algebra.ChainElement[C, E]] interface {
	HolesOrderTheoreticLattice[C, E]
}

type HolesChainElement[C algebra.Chain[C, E], E algebra.ChainElement[C, E]] interface {
	HolesOrderTheoreticLatticeElement[C, E]
}

type HolesUpperBoundedOrderTheoreticLattice[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLattice[L, E]
	Top() E
}

type HolesUpperBoundedOrderTheoreticLatticeElement[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLatticeElement[L, E]
}

type HolesLowerBoundedOrderTheoreticLattice[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLattice[L, E]
	Bottom() E
}

type HolesLowerBoundedOrderTheoreticLatticeElement[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLatticeElement[L, E]
}

type HolesBoundedOrderTheoreticLattice[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLattice[L, E]
	HolesUpperBoundedOrderTheoreticLattice[L, E]
	HolesLowerBoundedOrderTheoreticLattice[L, E]
}
type HolesBoundedOrderTheoreticLatticeElement[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] interface {
	HolesOrderTheoreticLatticeElement[L, E]
	HolesUpperBoundedOrderTheoreticLatticeElement[L, E]
	HolesLowerBoundedOrderTheoreticLatticeElement[L, E]
}

func NewOrderTheoreticLattice[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]](H HolesOrderTheoreticLattice[L, E]) OrderTheoreticLattice[L, E] {
	return OrderTheoreticLattice[L, E]{
		H: H,
	}
}

func NewOrderTheoreticLatticeElement[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]](H HolesOrderTheoreticLatticeElement[L, E]) OrderTheoreticLatticeElement[L, E] {
	return OrderTheoreticLatticeElement[L, E]{
		H: H,
	}
}

func NewChain[C algebra.Chain[C, E], E algebra.ChainElement[C, E]](H HolesChain[C, E]) Chain[C, E] {
	return Chain[C, E]{
		OrderTheoreticLattice: NewOrderTheoreticLattice(H),
		H:                     H,
	}
}

func NewChainElement[C algebra.Chain[C, E], E algebra.ChainElement[C, E]](H HolesChainElement[C, E]) ChainElement[C, E] {
	return ChainElement[C, E]{
		OrderTheoreticLatticeElement: NewOrderTheoreticLatticeElement(H),
		H:                            H,
	}
}

func NewUpperBoundedOrderTheoreticLattice[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]](H HolesUpperBoundedOrderTheoreticLattice[L, E]) UpperBoundedOrderTheoreticLattice[L, E] {
	return UpperBoundedOrderTheoreticLattice[L, E]{
		OrderTheoreticLattice: NewOrderTheoreticLattice(H),
		H:                     H,
	}
}

func NewUpperBoundedOrderTheoreticLatticeElement[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]](H HolesUpperBoundedOrderTheoreticLatticeElement[L, E]) UpperBoundedOrderTheoreticLatticeElement[L, E] {
	return UpperBoundedOrderTheoreticLatticeElement[L, E]{
		OrderTheoreticLatticeElement: NewOrderTheoreticLatticeElement(H),
		H:                            H,
	}
}

func NewLowerBoundedOrderTheoreticLattice[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]](H HolesLowerBoundedOrderTheoreticLattice[L, E]) LowerBoundedOrderTheoreticLattice[L, E] {
	return LowerBoundedOrderTheoreticLattice[L, E]{
		OrderTheoreticLattice: NewOrderTheoreticLattice(H),
		H:                     H,
	}
}

func NewLowerBoundedOrderTheoreticLatticeElement[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]](H HolesLowerBoundedOrderTheoreticLatticeElement[L, E]) LowerBoundedOrderTheoreticLatticeElement[L, E] {
	return LowerBoundedOrderTheoreticLatticeElement[L, E]{
		OrderTheoreticLatticeElement: NewOrderTheoreticLatticeElement(H),
		H:                            H,
	}
}

func NewBoundedOrderTheoreticLattice[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]](H HolesBoundedOrderTheoreticLattice[L, E]) BoundedOrderTheoreticLattice[L, E] {
	return BoundedOrderTheoreticLattice[L, E]{
		UpperBoundedOrderTheoreticLattice: NewUpperBoundedOrderTheoreticLattice(H),
		LowerBoundedOrderTheoreticLattice: NewLowerBoundedOrderTheoreticLattice(H),
		H:                                 H,
	}
}

func NewBoundedOrderTheoreticLatticeElement[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]](H HolesBoundedOrderTheoreticLatticeElement[L, E]) BoundedOrderTheoreticLatticeElement[L, E] {
	return BoundedOrderTheoreticLatticeElement[L, E]{
		UpperBoundedOrderTheoreticLatticeElement: NewUpperBoundedOrderTheoreticLatticeElement(H),
		LowerBoundedOrderTheoreticLatticeElement: NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}
