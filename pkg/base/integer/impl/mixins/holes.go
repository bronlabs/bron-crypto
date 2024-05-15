package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type HolesPositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] interface {
	ring.HolesRg[NS, N]
	order.HolesChain[NS, N]
	Arithmetic() integer.Arithmetic[N]
}

type HolesPositiveNaturalRgElement[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]] interface {
	ring.HolesRgElement[NS, N]
	order.HolesChainElement[NS, N]

	Arithmetic() integer.Arithmetic[N]
}

type HolesNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesPositiveNaturalRg[NS, N]
	order.HolesLowerBoundedOrderTheoreticLattice[NS, N]
}

type HolesNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesPositiveNaturalRgElement[NS, N]
	order.HolesLowerBoundedOrderTheoreticLatticeElement[NS, N]
}

func NewPositiveNaturalRg[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]](H HolesPositiveNaturalRg[NS, N]) PositiveNaturalRg[NS, N] {
	return PositiveNaturalRg[NS, N]{
		Rg:    ring.NewRg(H),
		Chain: order.NewChain(H),
		H:     H,
	}
}

func NewPositiveNaturalRgElement[NS integer.PositiveNaturalRg[NS, N], N integer.PositiveNaturalRgElement[NS, N]](H HolesPositiveNaturalRgElement[NS, N]) PositiveNaturalRgElement[NS, N] {
	return PositiveNaturalRgElement[NS, N]{
		RgElement:    ring.NewRgElement(H),
		ChainElement: order.NewChainElement(H),
		H:            H,
	}
}

func NewNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](H HolesNPlus[NS, N]) NPlus[NS, N] {
	return NPlus[NS, N]{
		PositiveNaturalRg:                 NewPositiveNaturalRg(H),
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
