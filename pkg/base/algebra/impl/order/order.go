package order

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type OrderTheoreticLattice[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] struct {
	algebra.OrderTheoreticLattice[L, E]
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
	algebra.Chain[C, E]
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

type BoundedOrderTheoreticLattice[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] struct {
	algebra.BoundedOrderTheoreticLattice[L, E]
}

func (l *BoundedOrderTheoreticLattice[L, E]) Join(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	top := l.Top()
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

func (l *BoundedOrderTheoreticLattice[L, E]) Meet(x algebra.OrderTheoreticLatticeElement[L, E], ys ...algebra.OrderTheoreticLatticeElement[L, E]) E {
	bottom := l.Bottom()
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
