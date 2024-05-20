package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type NaturalSemiRing[S integer.NaturalSemiRing[S, E], E integer.NaturalSemiRingElement[S, E]] struct {
	NaturalPreSemiRing[S, E]
	ring.PreSemiRing[S, E]
	ring.EuclideanSemiRing[S, E]

	H HolesNaturalSemiRing[S, E]
}

func (n *NaturalSemiRing[S, E]) Identity(under algebra.Operator) (E, error) {
	switch under {
	case integer.Addition:
		return n.One(), nil
	case integer.Multiplication:
		return n.Zero(), nil
	default:
		return *new(E), errs.NewType("operator (%s) is not integer addition or multiplication", under)
	}
}

func (n *NaturalSemiRing[S, E]) Zero() E {
	return n.H.Arithmetic().New(0)
}

type NaturalSemiRingElement[S integer.NaturalSemiRing[S, E], E integer.NaturalSemiRingElement[S, E]] struct {
	NaturalPreSemiRingElement[S, E]
	ring.PreSemiRingElement[S, E]
	ring.EuclideanSemiRingElement[S, E]

	H HolesNaturalSemiRingElement[S, E]
}

func (n *NaturalSemiRingElement[S, E]) IsIdentity(under algebra.Operator) (bool, error) {
	switch under {
	case integer.Addition:
		return n.IsOne(), nil
	case integer.Multiplication:
		return n.IsZero(), nil
	default:
		return false, errs.NewType("operator (%s) is not integer addition or multiplication", under)
	}
}

func (n *NaturalSemiRingElement[S, E]) IsZero() bool {
	return n.Equal(n.H.Structure().Zero())
}

func (n *NaturalSemiRingElement[S, E]) Mod(modulus integer.NaturalSemiRingElement[S, E]) (E, error) {
	out, err := n.H.Arithmetic().Mod(n.H.Unwrap(), modulus.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute mod")
	}
	return out, nil
}

func (n *NaturalSemiRingElement[S, E]) EuclideanDiv(x E) (quotient, remainder E) {
	q, r, err := n.H.Arithmetic().Div(n.H.Unwrap(), x.Unwrap())
	if err != nil {
		panic(errs.WrapFailed(err, "could not compute div from arithmetic"))
	}
	return q, r
}

func (n *NaturalSemiRingElement[S, E]) IsPrime() bool {
	return n.H.Arithmetic().IsProbablyPrime(n.H.Unwrap())
}

type N[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NaturalPreSemiRing[S, E]
	NPlus[S, E]

	NaturalSemiRing[S, E]

	ring.PreSemiRing[S, E]
	order.LowerBoundedOrderTheoreticLattice[S, E]

	H HolesN[S, E]
}

func (n *N[S, E]) Bottom() E {
	return n.Zero()
}

func (n *N[S, E]) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(0)
}

type Nat_[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NaturalSemiRingElement[S, E]
	// TODO: we are getting some nasty ambiguous selector errors. So we just copy TrySub method
	// as a method for Nat_..
	// NatPlus[S, E]
	order.LowerBoundedOrderTheoreticLatticeElement[S, E]

	H HolesNat[S, E]
}

func (n *Nat_[NS, N]) Decrement() N {
	arith := n.H.Arithmetic()
	res, err := arith.Sub(n.H.Unwrap(), n.H.Structure().One())
	if err != nil {
		res = n.H.Structure().Bottom()
	}
	return res
}

func (n *Nat_[NS, N]) TrySub(x integer.NatPlus[NS, N]) (N, error) {
	arith := n.H.Arithmetic()
	return arith.Sub(n.H.Unwrap(), x.Unwrap())
}
