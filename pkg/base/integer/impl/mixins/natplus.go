package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type NaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] struct {
	ring.FactorialSemiRing[NS, N]
	order.Chain[NS, N]
	operator.OperatorSuite[N]

	H HolesNaturalSemiRing[NS, N]
}

func (n *NaturalSemiRing[NS, N]) Element() N {
	return n.Unit()
}

func (n *NaturalSemiRing[NS, N]) One() N {
	return n.Unit()
}

func (n *NaturalSemiRing[S, E]) Identity(under algebra.Operator) (E, error) {
	if under == integer.Multiplication {
		return n.One(), nil
	}
	return *new(E), errs.NewType("operator (%s) is not integer multiplication", under)
}

func (np *NaturalSemiRing[NS, N]) Addition() algebra.Addition[N] {
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

func (np *NaturalSemiRing[NS, N]) Multiplication() algebra.Multiplication[N] {
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

type NaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] struct {
	ring.FactorialSemiRingElement[NS, N]
	order.ChainElement[NS, N]

	H HolesNaturalSemiRingElement[NS, N]
}

func (n *NaturalSemiRingElement[NS, N]) Equal(x N) bool {
	return n.H.Arithmetic().Cmp(n.H.Unwrap(), x) == algebra.Equal
}

func (n *NaturalSemiRingElement[NS, N]) HashCode() uint64 {
	return n.H.Uint64()
}

func (n *NaturalSemiRingElement[NS, N]) Cmp(x N) algebra.Ordering {
	return n.H.Arithmetic().Cmp(n.H.Unwrap(), x.Unwrap())
}

func (n *NaturalSemiRingElement[NS, N]) Add(x algebra.AdditiveGroupoidElement[NS, N]) N {
	out, err := n.H.Arithmetic().Add(n.H.Unwrap(), x.Unwrap(), -1)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *NaturalSemiRingElement[NS, N]) Mul(x algebra.MultiplicativeGroupoidElement[NS, N]) N {
	out, err := n.H.Arithmetic().Mul(n.H.Unwrap(), x.Unwrap(), -1)
	if err != nil {
		panic(err)
	}
	return out
}

func (n *NaturalSemiRingElement[NS, N]) IsOne() bool {
	return n.IsUnit()
}

func (n *NaturalSemiRingElement[NS, N]) IsEven() bool {
	return n.H.Arithmetic().IsEven(n.H.Unwrap())
}

func (n *NaturalSemiRingElement[NS, N]) IsOdd() bool {
	return !n.IsEven()
}

func (n *NaturalSemiRingElement[NS, N]) IsPositive() bool {
	res := n.Cmp(n.H.Structure().One())
	return res == algebra.Equal || res == algebra.GreaterThan
}

func (n *NaturalSemiRingElement[NS, N]) Increment() N {
	return n.H.Add(n.H.Structure().One())
}

func (n *NaturalSemiRingElement[NS, N]) Uint64() uint64 {
	return n.H.Arithmetic().Uint64(n.H.Unwrap())
}

func (n *NaturalSemiRingElement[NS, N]) CanGenerateAllElements(with algebra.Operator) bool {
	return n.IsOne() && with == integer.Addition
}

func (n *NaturalSemiRingElement[S, E]) IsPrime() bool {
	return n.H.Arithmetic().IsProbablyPrime(n.H.Unwrap())
}

func (n *NaturalSemiRingElement[S, E]) Factorise() ds.Map[E, int] {
	panic("implement me")
}

type NPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] struct {
	NaturalSemiRing[NS, N]
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
	NaturalSemiRingElement[NS, N]
	order.LowerBoundedOrderTheoreticLatticeElement[NS, N]

	H HolesNatPlus[NS, N]
}

func (n *NatPlus[NS, N]) Decrement() N {
	arith := n.H.Arithmetic()
	res, err := arith.Sub(n.H.Unwrap(), n.H.Structure().One(), -1)
	if err != nil {
		res = n.H.Structure().Bottom()
	}
	return res
}

func (n *NatPlus[NS, N]) TrySub(x integer.NatPlus[NS, N]) (N, error) {
	arith := n.H.Arithmetic()
	return arith.Sub(n.H.Unwrap(), x.Unwrap(), -1)
}
