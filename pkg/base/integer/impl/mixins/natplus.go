package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type PositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] struct {
	ring.Rg[NS, N]
	order.Chain[NS, N]
	operator.OperatorSuite[N]

	H HolesPositiveNaturalRg[NS, N]
}

func (n *PositiveNaturalRg[NS, N]) Arithmetic() integer.Arithmetic[N] {
	return n.H.Element().Arithmetic()
}

func (n *PositiveNaturalRg[NS, N]) One() N {
	return n.H.Element().Arithmetic().One().Unwrap()
}

func (np *PositiveNaturalRg[NS, N]) Addition() algebra.Addition[N] {
	op, defined := np.GetOperator(integer.Addition)
	if !defined {
		panic(errs.NewMissing("object is malformed. does not have integer addition"))
	}
	addition, ok := op.(algebra.Addition[N])
	if !ok {
		panic(errs.NewType("object is malfored. addition operator is invalid"))
	}
	return addition
}

func (np *PositiveNaturalRg[NS, N]) Multiplication() algebra.Multiplication[N] {
	op, defined := np.GetOperator(integer.Multiplication)
	if !defined {
		panic(errs.NewMissing("object is malformed. does not have integer multiplication"))
	}
	multiplication, ok := op.(algebra.Multiplication[N])
	if !ok {
		panic(errs.NewType("object is malfored. multiplication operator is invalid"))
	}
	return multiplication
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

func (n *PositiveNaturalRgElement[NS, N]) CanGenerateAllElements(with algebra.Operator) bool {
	return n.IsOne() && with == integer.Addition
}

type NPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	PositiveNaturalRg[NS, N]
	order.LowerBoundedOrderTheoreticLattice[NS, N]

	H HolesNPlus[NS, N]
}

func (np *NPlus[NS, N]) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (np *NPlus[NS, N]) Contains(x N) bool {
	return x.IsPositive()
}

func (n *NPlus[NS, N]) Bottom() N {
	return n.One()
}

func (np *NPlus[NS, N]) Iter() <-chan N {
	ch := make(chan N, 1)
	current := np.Bottom()
	ch <- current
	go func() {
		defer close(ch)
		var err error
		for {
			current, err = np.H.Successor().Map(current)
			if err != nil {
				panic(errs.WrapFailed(err, "could not compute S(current)"))
			}
			ch <- current
		}
	}()
	return ch
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
