package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type PositiveNaturalNumberGroupoidMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	groupoid.AdditiveGroupoid[NS, N]
	groupoid.MultiplicativeGroupoid[NS, N]
	groupoid.Groupoid[NS, N]
}

func (n *PositiveNaturalNumberGroupoidMixin[NS, N]) Arithmetic() integer.Arithmetic[N] {
	panic("in mixin")
}

func (n *PositiveNaturalNumberGroupoidMixin[NS, N]) One() N {
	return n.Arithmetic().One().Unwrap()
}

type PositiveNaturalNumberGroupoidElementMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	groupoid.AdditiveGroupoidElement[NS, N]
	groupoid.MultiplicativeGroupoidElement[NS, N]
	groupoid.GroupoidElement[NS, N]
	order.ChainElement[NS, N]
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Structure() NS {
	panic("in mixin")
}
func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Unwrap() N {
	panic("in mixin")
}
func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Arithmetic() integer.Arithmetic[N] {
	panic("in mixin")
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Mod(modulus integer.PositiveNaturalNumberGroupoidElement[NS, N]) (N, error) {
	out, err := n.Structure().Arithmetic().Mod(n.Unwrap(), modulus.Unwrap())
	if err != nil {
		return *new(N), errs.WrapFailed(err, "could not compute mod")
	}
	return out.Unwrap(), nil
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Cmp(x algebra.OrderTheoreticLatticeElement[NS, N]) algebra.Ordering {
	return n.Structure().Arithmetic().Cmp(n.Unwrap(), x.Unwrap())
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) IsOne() bool {
	return n.Structure().One().Equal(n.Unwrap())
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) IsEven() bool {
	return n.Structure().Arithmetic().IsEven(n.Unwrap())
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) IsOdd() bool {
	return n.Structure().Arithmetic().IsOdd(n.Unwrap())
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) IsPositive() bool {
	res := n.Cmp(n.Structure().One())
	return res == algebra.Equal || res == algebra.GreaterThan
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Increment() N {
	return n.Add(n.Structure().One())
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Decrement() N {
	arith := n.Arithmetic()
	res, err := arith.Sub(n.Unwrap(), n.Structure().One())
	if err != nil {
		res = n.Structure().Bottom()
	}
	return res
}

func (n *PositiveNaturalNumberGroupoidElementMixin[NS, N]) Uint64() uint64 {
	return n.Arithmetic().Uint64(n.Unwrap())
}

type NPlusMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalNumberGroupoidMixin[NS, N]
	order.LowerBoundedOrderTheoreticLattice[NS, N]
	order.Chain[NS, N]
}

type NatPlusMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	ring.RgElement[NS, N]
	PositiveNaturalNumberGroupoidElementMixin[NS, N]
	order.OrderTheoreticLatticeElement[NS, N]
	order.ChainElement[NS, N]
	order.LowerBoundedOrderTheoreticLatticeElement[NS, N]
}

func (n *NatPlusMixin[NS, N]) TrySub(x integer.NatPlus[NS, N]) (N, error) {
	arith := n.Arithmetic()
	return arith.Sub(n.Unwrap(), x.Unwrap())
}
