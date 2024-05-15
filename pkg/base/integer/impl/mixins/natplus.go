package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type PositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] struct {
	ring.Rg[NS, N]
	order.Chain[NS, N]

	H HolesPositiveNaturalRg[NS, N]
}

func (n *PositiveNaturalRg[NS, N]) One() N {
	return n.H.Arithmetic().One().Unwrap()
}

type PositiveNaturalRgElement[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] struct {
	ring.RgElement[NS, N]
	order.ChainElement[NS, N]

	H HolesPositiveNaturalRgElement[NS, N]
}

func (n *PositiveNaturalRgElement[NS, N]) Equal(x N) bool {
	return n.H.Arithmetic().Equal(n.H.Unwrap(), x)
}

func (n *PositiveNaturalRgElement[NS, N]) HashCode() uint64 {
	return n.Uint64()
}

func (n *PositiveNaturalRgElement[NS, N]) Mod(modulus integer.PositiveNaturalRgElement[NS, N]) (N, error) {
	out, err := n.H.Structure().Arithmetic().Mod(n.H.Unwrap(), modulus.Unwrap())
	if err != nil {
		return *new(N), errs.WrapFailed(err, "could not compute mod")
	}
	return out.Unwrap(), nil
}

func (n *PositiveNaturalRgElement[NS, N]) Cmp(x algebra.OrderTheoreticLatticeElement[NS, N]) algebra.Ordering {
	return n.H.Structure().Arithmetic().Cmp(n.H.Unwrap(), x.Unwrap())
}

func (n *PositiveNaturalRgElement[NS, N]) Add(x algebra.AdditiveGroupoidElement[NS, N]) N {
	out, err := n.H.Arithmetic().Add(n.H.Unwrap(), x.Unwrap())
	if err != nil {
		panic(err)
	}
	return out
}

func (n *PositiveNaturalRgElement[NS, N]) Mul(x algebra.MultiplicativeGroupoidElement[NS, N]) N {
	out, err := n.H.Arithmetic().Mul(n.H.Unwrap(), x.Unwrap())
	if err != nil {
		panic(err)
	}
	return out
}

func (n *PositiveNaturalRgElement[NS, N]) IsOne() bool {
	return n.H.Structure().One().Equal(n.H.Unwrap())
}

func (n *PositiveNaturalRgElement[NS, N]) IsEven() bool {
	return n.H.Structure().Arithmetic().IsEven(n.H.Unwrap())
}

func (n *PositiveNaturalRgElement[NS, N]) IsOdd() bool {
	return n.H.Structure().Arithmetic().IsOdd(n.H.Unwrap())
}

func (n *PositiveNaturalRgElement[NS, N]) IsPositive() bool {
	res := n.Cmp(n.H.Structure().One())
	return res == algebra.Equal || res == algebra.GreaterThan
}

func (n *PositiveNaturalRgElement[NS, N]) Increment() N {
	return n.H.Add(n.H.Structure().One())
}

func (n *PositiveNaturalRgElement[NS, N]) Decrement() N {
	arith := n.H.Arithmetic()
	res, err := arith.Sub(n.H.Unwrap(), n.H.Structure().One())
	if err != nil {
		switch n.H.Arithmetic().Type() {
		case integer.ForNPlus:
			res = n.H.Arithmetic().One()
		case integer.ForN:
			res = n.H.Arithmetic().Zero()
		default:
			panic(errs.WrapFailed(err, "could not sub for arithmetic type %s", n.H.Arithmetic().Type()))
		}
	}
	return res
}

func (n *PositiveNaturalRgElement[NS, N]) Uint64() uint64 {
	return n.H.Arithmetic().Uint64(n.H.Unwrap())
}

type NPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalRg[NS, N]
	order.LowerBoundedOrderTheoreticLattice[NS, N]

	H HolesNPlus[NS, N]
}

type NatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalRgElement[NS, N]
	order.LowerBoundedOrderTheoreticLatticeElement[NS, N]

	H HolesNatPlus[NS, N]
}

func (n *NatPlus[NS, N]) TrySub(x integer.NatPlus[NS, N]) (N, error) {
	arith := n.H.Arithmetic()
	return arith.Sub(n.H.Unwrap(), x.Unwrap())
}

func (n *NatPlus[NS, N]) CanGenerateAllElements(with algebra.Operator) bool {
	_, defined := n.H.Structure().GetOperator(with)
	return n.IsOne() && defined && n.H.Structure().Addition().Name() == with
}
