package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type HolesNaturalPreSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	ring.HolesSemiRing[NS, N]
	order.HolesChain[NS, N]

	Arithmetic() integer.Arithmetic[N]
}

type HolesNaturalPreSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	ring.HolesSemiRingElement[NS, N]
	order.HolesChainElement[NS, N]

	Arithmetic() integer.Arithmetic[N]
	Uint64() uint64
}

type HolesNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesNaturalPreSemiRing[NS, N]
	order.HolesLowerBoundedOrderTheoreticLattice[NS, N]

	Successor() algebra.Successor[N]
}

type HolesNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesNaturalPreSemiRingElement[NS, N]
	order.HolesLowerBoundedOrderTheoreticLatticeElement[NS, N]
}

func NewNaturalPreSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalPreSemiRing[NS, N]) NaturalPreSemiRing[NS, N] {
	addition := integer.NewAdditionOperator(arithmetic)
	multiplication := integer.NewMultiplicationOperator(arithmetic)
	b := operator.NewOperatorSuiteBuilder[N]().WithPrimary(addition).WithSecondary(multiplication).Build()
	return NaturalPreSemiRing[NS, N]{
		SemiRing:      ring.NewSemiRing(H),
		Chain:         order.NewChain(H),
		OperatorSuite: b,
		H:             H,
	}
}

func NewNaturalPreSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](H HolesNaturalPreSemiRingElement[NS, N]) NaturalPreSemiRingElement[NS, N] {
	return NaturalPreSemiRingElement[NS, N]{
		SemiRingElement: ring.NewSemiRingElement(H),
		ChainElement:    order.NewChainElement(H),
		H:               H,
	}
}

func NewNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](arithmetic integer.Arithmetic[N], H HolesNPlus[NS, N]) NPlus[NS, N] {
	return NPlus[NS, N]{
		NaturalPreSemiRing:                NewNaturalPreSemiRing(arithmetic, H),
		LowerBoundedOrderTheoreticLattice: order.NewLowerBoundedOrderTheoreticLattice(H),
		H:                                 H,
	}
}

func NewNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](H HolesNatPlus[NS, N]) NatPlus[NS, N] {
	return NatPlus[NS, N]{
		NaturalPreSemiRingElement:                NewNaturalPreSemiRingElement(H),
		LowerBoundedOrderTheoreticLatticeElement: order.NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}
