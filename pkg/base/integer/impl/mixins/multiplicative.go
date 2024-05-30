package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type ZnX[G integer.ZnX[G, E], E integer.IntX[G, E]] struct {
	groupoid.Groupoid[G, E]
	group.MultiplicativeGroup[G, E]
	order.Chain[G, E]
	order.BoundedOrderTheoreticLattice[G, E]
	operator.OperatorSuite[E]

	arithmetic integer.ModularArithmetic[E]

	H HolesZnX[G, E]
}

func (n *ZnX[S, E]) Identity(under algebra.Operator) (E, error) {
	out, defined := n.GetOperator(under)
	if !defined {
		return *new(E), errs.NewType("structure is not defined under operator (%s)", under)
	}
	_, ok := out.(algebra.Multiplication[E])
	if !ok {
		return *new(E), errs.NewType("operator is not multiplication")
	}
	return n.H.Bottom(), nil
}

func (n *ZnX[G, E]) Bottom() E {
	return n.arithmetic.New(1)
}

func (n *ZnX[G, E]) Top() E {
	// TODO: fix overflow
	return n.arithmetic.New(new(saferith.Nat).Sub(n.H.Modulus().Nat(), new(saferith.Nat).SetUint64(1), -1).Uint64())
}

func (z *ZnX[S, E]) Iter() <-chan E {
	ch := make(chan E, 1)
	go func() {
		current := z.Bottom()
		ch <- current
		for algebra.IsLessThan(current, z.Top()) {
			current = current.Increment()
			if z.H.Contains(current) {
				ch <- current
			}
		}
	}()
	return ch
}

// func (z *ZnX[S, E]) Contains(x E) bool {
// 	interval := algebra.ClosedInterval[S, E]{
// 		Left:  z.Bottom(),
// 		Right: z.Top(),
// 	}
// 	areCoPrime, err := z.H.Arithmetic().GCD
// 	areCoPrime := z.H.Modulus().CoPrime(z.H.Modulus().SetNat(x.Nat()))
// 	return interval.ContainsElement(x) && areCoPrime
// }

type IntX[G integer.ZnX[G, E], E integer.IntX[G, E]] struct {
	groupoid.GroupoidElement[G, E]
	group.MultiplicativeGroupElement[G, E]
	order.BoundedOrderTheoreticLatticeElement[G, E]
	order.ChainElement[G, E]

	arithmetic integer.ModularArithmetic[E]

	H HolesIntX[G, E]
}

func (z *IntX[G, E]) Increment() E {
	var err error
	current := z.H.Clone()
	for !current.IsTop() {
		current, err = z.arithmetic.Add(current.Unwrap(), current.Structure().MultiplicativeIdentity(), -1)
		if err != nil {
			panic(err)
		}
		if z.H.Structure().Contains(current) {
			return current
		}
	}
	return z.H.Structure().Bottom()
}

func (z *IntX[G, E]) Decrement() E {
	var err error
	current := z.H.Clone()
	for !current.IsBottom() {
		current, err = z.arithmetic.Sub(current.Unwrap(), current.Structure().MultiplicativeIdentity(), -1)
		if err != nil {
			panic(err)
		}
		if z.H.Structure().Contains(current) {
			return current
		}
	}
	return z.H.Structure().Top()
}

func (n *IntX[S, E]) Inverse(under algebra.Operator) (E, error) {
	out, defined := n.H.Structure().GetOperator(under)
	if !defined {
		return *new(E), errs.NewType("structure is not defined under operator (%s)", under)
	}
	_, ok := out.(algebra.Multiplication[E])
	if !ok {
		return *new(E), errs.NewType("operator is not multiplication")
	}
	return n.MultiplicativeInverse()
}

func (n *IntX[G, E]) MultiplicativeInverse() (E, error) {
	out, err := n.arithmetic.Inverse(n.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute inverse")
	}
	return out, nil
}
