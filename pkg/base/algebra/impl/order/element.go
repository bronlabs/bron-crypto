package order

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type OrderTheoreticLatticeElement[L algebra.OrderTheoreticLattice[L, E], E algebra.OrderTheoreticLatticeElement[L, E]] struct {
	algebra.OrderTheoreticLatticeElement[L, E]
}

func (l *OrderTheoreticLatticeElement[L, E]) Lattice() algebra.OrderTheoreticLattice[L, E] {
	return l.Structure()
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

func (c *ChainElement[C, E]) Chain() algebra.Chain[C, E] {
	return c.Structure()
}

type UpperBoundedOrderTheoreticLatticeElement[L algebra.UpperBoundedOrderTheoreticLattice[L, E], E algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]] struct {
	algebra.UpperBoundedOrderTheoreticLatticeElement[L, E]
}

func (l *UpperBoundedOrderTheoreticLatticeElement[L, E]) IsTop() bool {
	return l.Equal(l.Structure().Top())
}

func (l *UpperBoundedOrderTheoreticLatticeElement[L, E]) UpperBoundedLattice() algebra.UpperBoundedOrderTheoreticLattice[L, E] {
	return l.Structure()
}

type LowerBoundedOrderTheoreticLatticeElement[L algebra.LowerBoundedOrderTheoreticLattice[L, E], E algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]] struct {
	algebra.LowerBoundedOrderTheoreticLatticeElement[L, E]
}

func (l *LowerBoundedOrderTheoreticLatticeElement[L, E]) IsBottom() bool {
	return l.Equal(l.Structure().Bottom())
}

func (l *LowerBoundedOrderTheoreticLatticeElement[L, E]) LowerBoundedLattice() algebra.LowerBoundedOrderTheoreticLattice[L, E] {
	return l.Structure()
}

type BoundedOrderTheoreticLatticeElement[L algebra.BoundedOrderTheoreticLattice[L, E], E algebra.BoundedOrderTheoreticLatticeElement[L, E]] struct {
	algebra.BoundedOrderTheoreticLatticeElement[L, E]
	UpperBoundedOrderTheoreticLattice[L, E]
	LowerBoundedOrderTheoreticLattice[L, E]
}

func (l *BoundedOrderTheoreticLatticeElement[L, E]) BoundedLattice() algebra.BoundedOrderTheoreticLattice[L, E] {
	return l.Structure()
}
