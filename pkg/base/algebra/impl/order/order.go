package order

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type OrderTheoreticLattice[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] struct {
	H HolesOrderTheoreticLattice[L, E]
}

func (l *OrderTheoreticLattice[L, E]) LatticeElement() algebra.OrderTheoreticLatticeElement[L, E] {
	return l.H.Element()
}

func (l *OrderTheoreticLattice[L, E]) Join(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	res := x
	for _, y := range ys {
		res = res.Join(y)
	}
	return res.Unwrap()
}

func (l *OrderTheoreticLattice[L, E]) Meet(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	res := x
	for _, y := range ys {
		res = res.Meet(y)
	}
	return res.Unwrap()
}

type Chain[C algebra.Chain[C, E], E algebra.ChainElement[C, E]] struct {
	OrderTheoreticLattice[C, E]
	H HolesChain[C, E]
}

func (c *Chain[C, E]) Max(x algebra.ChainElement[C, E], ys ...algebra.ChainElement[C, E]) E {
	res := x
	for _, y := range ys {
		res = res.Max(y)
	}
	return res.Unwrap()
}

func (c *Chain[C, E]) Min(x algebra.ChainElement[C, E], ys ...algebra.ChainElement[C, E]) E {
	res := x
	for _, y := range ys {
		res = res.Min(y)
	}
	return res.Unwrap()
}

func (c *Chain[C, E]) ChainElement() algebra.ChainElement[C, E] {
	return c.H.Element()
}

type UpperBoundedOrderTheoreticLattice[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]] struct {
	OrderTheoreticLattice[L, E]
	H HolesUpperBoundedOrderTheoreticLattice[L, E]
}

func (l *UpperBoundedOrderTheoreticLattice[L, E]) Join(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	top := l.H.Top()
	if x.Equal(top) {
		return x.Unwrap()
	}
	res := x
	for _, y := range ys {
		if y.Equal(top) {
			return y.Unwrap()
		}
		res = res.Join(y)
	}
	return res.Unwrap()
}

func (l *UpperBoundedOrderTheoreticLattice[L, E]) UpperBoundedLatticeElement() algebra.UpperBoundedOrderTheoreticLatticeElement[L, E] {
	return l.H.Element()
}

type LowerBoundedOrderTheoreticLattice[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]] struct {
	OrderTheoreticLattice[L, E]
	H HolesLowerBoundedOrderTheoreticLattice[L, E]
}

func (l *LowerBoundedOrderTheoreticLattice[L, E]) Meet(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	bottom := l.H.Bottom()
	if x.Equal(bottom) {
		return x.Unwrap()
	}
	res := x
	for _, y := range ys {
		if y.Equal(bottom) {
			return y.Unwrap()
		}
		res = res.Meet(y)
	}
	return res.Unwrap()
}

func (l *LowerBoundedOrderTheoreticLattice[L, E]) LowerBoundedLatticeElement() algebra.LowerBoundedOrderTheoreticLatticeElement[L, E] {
	return l.H.Element()
}

type BoundedOrderTheoreticLattice[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] struct {
	OrderTheoreticLattice[L, E]
	UpperBoundedOrderTheoreticLattice[L, E]
	LowerBoundedOrderTheoreticLattice[L, E]
	H HolesBoundedOrderTheoreticLattice[L, E]
}

func (l *BoundedOrderTheoreticLattice[L, E]) BoundedLatticeElement() algebra.BoundedOrderTheoreticLatticeElement[L, E] {
	return l.H.Element()
}
