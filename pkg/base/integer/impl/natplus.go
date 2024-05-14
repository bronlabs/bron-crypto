package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type PositiveNaturalRgMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	ring.Rg[NS, N]
	order.Chain[NS, N]
}

func (n *PositiveNaturalRgMixin[NS, N]) Arithmetic() integer.Arithmetic[N] {
	panic("in mixin")
}

func (n *PositiveNaturalRgMixin[NS, N]) One() N {
	return n.Arithmetic().One().Unwrap()
}

type PositiveNaturalRgElementMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	ring.RgElement[NS, N]
	order.ChainElement[NS, N]
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Structure() NS {
	panic("in mixin")
}
func (n *PositiveNaturalRgElementMixin[NS, N]) Unwrap() N {
	panic("in mixin")
}
func (n *PositiveNaturalRgElementMixin[NS, N]) Arithmetic() integer.Arithmetic[N] {
	panic("in mixin")
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Equal(x N) bool {
	return n.Arithmetic().Equal(n.Unwrap(), x)
}

func (n *PositiveNaturalRgElementMixin[NS, N]) HashCode() uint64 {
	return n.Uint64()
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Mod(modulus integer.PositiveNaturalRgElement[NS, N]) (N, error) {
	out, err := n.Structure().Arithmetic().Mod(n.Unwrap(), modulus.Unwrap())
	if err != nil {
		return *new(N), errs.WrapFailed(err, "could not compute mod")
	}
	return out.Unwrap(), nil
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Cmp(x algebra.OrderTheoreticLatticeElement[NS, N]) algebra.Ordering {
	return n.Structure().Arithmetic().Cmp(n.Unwrap(), x.Unwrap())
}

func (n *PositiveNaturalRgElementMixin[NS, N]) IsOne() bool {
	return n.Structure().One().Equal(n.Unwrap())
}

func (n *PositiveNaturalRgElementMixin[NS, N]) IsEven() bool {
	return n.Structure().Arithmetic().IsEven(n.Unwrap())
}

func (n *PositiveNaturalRgElementMixin[NS, N]) IsOdd() bool {
	return n.Structure().Arithmetic().IsOdd(n.Unwrap())
}

func (n *PositiveNaturalRgElementMixin[NS, N]) IsPositive() bool {
	res := n.Cmp(n.Structure().One())
	return res == algebra.Equal || res == algebra.GreaterThan
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Increment() N {
	return n.Add(n.Structure().One())
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Decrement() N {
	arith := n.Arithmetic()
	res, err := arith.Sub(n.Unwrap(), n.Structure().One())
	if err != nil {
		res = n.Structure().Bottom()
	}
	return res
}

func (n *PositiveNaturalRgElementMixin[NS, N]) Uint64() uint64 {
	return n.Arithmetic().Uint64(n.Unwrap())
}

type NPlusMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalRgMixin[NS, N]
	order.LowerBoundedOrderTheoreticLattice[NS, N]
}

type NatPlusMixin[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalRgElementMixin[NS, N]
	order.LowerBoundedOrderTheoreticLatticeElement[NS, N]
}

func (n *NatPlusMixin[NS, N]) TrySub(x integer.NatPlus[NS, N]) (N, error) {
	arith := n.Arithmetic()
	return arith.Sub(n.Unwrap(), x.Unwrap())
}

func (n *NatPlusMixin[NS, N]) CanGenerateAllElements(with algebra.Operator) bool {
	_, defined := n.Structure().GetOperator(with)
	return n.IsOne() && defined && n.Structure().Addition().Name() == with
}
