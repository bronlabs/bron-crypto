package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative"
	pimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
)

type wrappedS[G multiplicative.ZnX[G, E], E multiplicative.IntX[G, E]] struct {
	groupoid.Groupoid[G, E]
	group.MultiplicativeGroup[G, E]
}

type ZnX_[G multiplicative.ZnX[G, E], E multiplicative.IntX[G, E]] struct {
	wrappedS[G, E]
	pimpl.NaturalPreSemiRing[G, E]
	order.BoundedOrderTheoreticLattice[G, E]

	H HolesZnX[G, E]
}

func (n *ZnX_[S, E]) Identity(under algebra.Operator) (E, error) {
	out, defined := n.GetOperator(under)
	if !defined {
		return *new(E), errs.NewType("structure is not defined under operator (%s)", under)
	}
	_, ok := out.(algebra.Multiplication[E])
	if !ok {
		return *new(E), errs.NewType("operator is not multiplication")
	}
	return n.One(), nil
}

func (n *ZnX_[S, E]) Bottom() E {
	return n.One()
}

func (n *ZnX_[G, E]) Top() E {
	panic("impelement me")
}

func (z *ZnX_[S, E]) Iter() <-chan E {
	ch := make(chan E, 1)
	go func() {
		current := z.One()
		ch <- current
		for algebra.IsLessThan(current, z.Top()) {
			current = current.Increment()
			if z.Contains(current) {
				ch <- current
			}
		}
	}()
	return ch
}

func (z *ZnX_[S, E]) Contains(x E) bool {
	interval := algebra.ClosedInterval[S, E]{
		Left:  z.Bottom(),
		Right: z.H.Top(),
	}
	areCoPrime := z.H.Modulus().CoPrime(z.H.Modulus().SetNat(x.Nat()))
	return interval.ContainsElement(x) && areCoPrime
}

type IntX_[G multiplicative.ZnX[G, E], E multiplicative.IntX[G, E]] struct {
	groupoid.MultiplicativeGroupoidElement[G, E]
	group.MultiplicativeGroupElement[G, E]
	pimpl.NaturalPreSemiRingElement[G, E]
	order.BoundedOrderTheoreticLatticeElement[G, E]

	H HolesIntX[G, E]
}

func (z *IntX_[G, E]) Increment() E {
	panic("implement me")
}

func (z *IntX_[G, E]) Decrement() E {
	panic("implement me")
}

func (n *IntX_[S, E]) Inverse(under algebra.Operator) (E, error) {
	out, defined := n.H.Structure().GetOperator(under)
	if !defined {
		return *new(E), errs.NewType("structure is not defined under operator (%s)", under)
	}
	_, ok := out.(algebra.Multiplication[E])
	if !ok {
		return *new(E), errs.NewType("operator is not multiplication")
	}
	n.H.Structure().MultiplicativeInverse()
	return n.One(), nil
}

func (n *IntX_[G, E]) MultiplicativeInverse() (E, error) {

}
