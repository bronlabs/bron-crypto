package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type HolesPositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] interface {
	ring.HolesRg[NS, N]
	order.HolesChain[NS, N]
}

type HolesPositiveNaturalRgElement[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] interface {
	ring.HolesRgElement[NS, N]
	order.HolesChainElement[NS, N]

	Arithmetic() integer.Arithmetic[N]
}

type HolesNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesPositiveNaturalRg[NS, N]
	order.HolesLowerBoundedOrderTheoreticLattice[NS, N]

	Successor() algebra.Successor[N]
}

type HolesNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesPositiveNaturalRgElement[NS, N]
	order.HolesLowerBoundedOrderTheoreticLatticeElement[NS, N]
}

type HolesNaturalRig[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	HolesPositiveNaturalRg[NS, N]
	ring.HolesRig[NS, N]
}

type HolesNaturalRigElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	HolesPositiveNaturalRgElement[NS, N]
	ring.HolesRigElement[NS, N]
}

type HolesN[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalRig[NS, N]
	HolesNPlus[NS, N]
}

type HolesNat[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalRigElement[NS, N]
	HolesNatPlus[NS, N]
}

func NewPositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesPositiveNaturalRg[NS, N]) PositiveNaturalRg[NS, N] {
	addition := integer.NewAdditionOperator(arithmetic)
	multiplication := integer.NewMultiplicationOperator(arithmetic)
	b, err := operator.NewOperatorSuiteBuilder[N]().WithAddition(addition).WithMultiplication(multiplication).Build()
	if err != nil {
		panic(err)
	}
	return PositiveNaturalRg[NS, N]{
		Rg:            ring.NewRg(H),
		Chain:         order.NewChain(H),
		OperatorSuite: b,
		H:             H,
	}
}

func NewPositiveNaturalRgElement[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]](H HolesPositiveNaturalRgElement[NS, N]) PositiveNaturalRgElement[NS, N] {
	return PositiveNaturalRgElement[NS, N]{
		RgElement:    ring.NewRgElement(H),
		ChainElement: order.NewChainElement(H),
		H:            H,
	}
}

func NewNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](arithmetic integer.Arithmetic[N], H HolesNPlus[NS, N]) NPlus[NS, N] {
	return NPlus[NS, N]{
		PositiveNaturalRg:                 NewPositiveNaturalRg(arithmetic, H),
		LowerBoundedOrderTheoreticLattice: order.NewLowerBoundedOrderTheoreticLattice(H),
		H:                                 H,
	}
}

func NewNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](H HolesNatPlus[NS, N]) NatPlus[NS, N] {
	return NatPlus[NS, N]{
		PositiveNaturalRgElement:                 NewPositiveNaturalRgElement(H),
		LowerBoundedOrderTheoreticLatticeElement: order.NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}

func NewNaturalRig[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalRig[NS, N]) NaturalRig[NS, N] {
	return NaturalRig[NS, N]{
		PositiveNaturalRg: NewPositiveNaturalRg(arithmetic, H),
		Rig:               ring.NewRig(H),
		H:                 H,
	}
}

func NewNaturalRigElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](H HolesNaturalRigElement[NS, N]) NaturalRigElement[NS, N] {
	return NaturalRigElement[NS, N]{
		PositiveNaturalRgElement: NewPositiveNaturalRgElement(H),
		RigElement:               ring.NewRigElement(H),
		H:                        H,
	}
}

func NewN[S integer.N[S, E], E integer.Nat[S, E]](arithmetic integer.Arithmetic[E], H HolesN[S, E]) N[S, E] {
	return N[S, E]{
		NaturalRig: NewNaturalRig(arithmetic, H),
		NPlus:      NewNPlus(arithmetic, H),
		H:          H,
	}
}

func NewNat[S integer.N[S, E], E integer.Nat[S, E]](H HolesNat[S, E]) Nat[S, E] {
	return Nat[S, E]{
		NaturalRigElement: NewNaturalRigElement(H),
		NatPlus:           NewNatPlus(H),
		H:                 H,
	}
}
