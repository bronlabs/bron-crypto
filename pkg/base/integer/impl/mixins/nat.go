package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type NaturalRig[S integer.NaturalRig[S, E], E integer.NaturalRigElement[S, E]] struct {
	PositiveNaturalRg[S, E]
	ring.Rig[S, E]

	H HolesNaturalRig[S, E]
}

func (n *NaturalRig[S, E]) Identity(under algebra.Operator) (E, error) {
	switch under {
	case integer.Addition:
		return n.One(), nil
	case integer.Multiplication:
		return n.Zero(), nil
	default:
		return *new(E), errs.NewType("operator (%s) is not integer addition or multiplication")
	}
}

func (n *NaturalRig[S, E]) Zero() E {
	return n.Arithmetic().Zero()
}

type NaturalRigElement[S integer.NaturalRig[S, E], E integer.NaturalRigElement[S, E]] struct {
	PositiveNaturalRgElement[S, E]
	ring.RigElement[S, E]

	H HolesNaturalRigElement[S, E]
}

func (n *NaturalRigElement[S, E]) IsZero() bool {
	return n.Equal(n.H.Structure().Zero())
}

func (n *NaturalRigElement[S, E]) Mod(modulus NaturalRigElement[S, E]) (E, error) {
	out, err := n.H.Arithmetic().WithBottomAtZeroAndModulus(modulus.H.Unwrap()).Mod(n.H.Unwrap(), modulus.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute mod")
	}
	return out, nil
}

type wrappedNPlus[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NPlus[S, E]
}
type wrappedNaturalRig[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NaturalRig[S, E]
}

type wrappedNatPlus[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NatPlus[S, E]
}

type N[S integer.N[S, E], E integer.Nat[S, E]] struct {
	wrappedNaturalRig[S, E]
	NPlus[S, E]

	H HolesN[S, E]
}

func (n *N[S, E]) Bottom() E {
	n.Add
	return n.Zero()
}

func (n *N[S, E]) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(0)
}

type Nat[S integer.N[S, E], E integer.Nat[S, E]] struct {
	NaturalRigElement[S, E]
	wrappedNatPlus[S, E]

	H HolesNat[S, E]
}

func (n *Nat[S, E]) test() {
	n.Mod
}
