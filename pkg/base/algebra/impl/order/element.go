package order

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type OrderTheoreticLatticeElement[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] struct {
	algebra.OrderTheoreticLatticeElement[L, E]
}

type ChainElement[C algebra.Chain[C, E], E algebra.ChainElement[C, E]] struct {
	algebra.ChainElement[C, E]
}

func (c *ChainElement[C, E]) Meet(rhs algebra.OrderTheoreticLatticeElement[C, E]) E {
	if c.Cmp(rhs) == algebra.LessThan {
		return c.Unwrap()
	}
	return rhs.Unwrap()
}

func (c *ChainElement[C, E]) Join(rhs algebra.OrderTheoreticLatticeElement[C, E]) E {
	if c.Cmp(rhs) == algebra.LessThan {
		return rhs.Unwrap()
	}
	return c.Unwrap()
}

func (c *ChainElement[C, E]) Min(rhs algebra.ChainElement[C, E]) E {
	return c.Meet(rhs)
}

func (c *ChainElement[C, E]) Max(rhs algebra.ChainElement[C, E]) E {
	return c.Join(rhs)
}

type BoundedOrderTheoreticLatticeElement[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] struct {
	algebra.BoundedOrderTheoreticLatticeElement[L, E]
}

func (l *BoundedOrderTheoreticLatticeElement[L, E]) IsTop() bool {
	return l.Equal(l.Structure().Top())
}

func (l *BoundedOrderTheoreticLatticeElement[L, E]) IsBottom() bool {
	return l.Equal(l.Structure().Bottom())
}
