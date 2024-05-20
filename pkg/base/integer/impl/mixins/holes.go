package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type HolesNaturalPreSemiRing[NS integer.NaturalPreSemiRing[NS, N], N integer.NaturalPreSemiRingElement[NS, N]] interface {
	ring.HolesPreSemiRing[NS, N]
	order.HolesChain[NS, N]

	Arithmetic() integer.Arithmetic[N]
}

type HolesNaturalPreSemiRingElement[NS integer.NaturalPreSemiRing[NS, N], N integer.NaturalPreSemiRingElement[NS, N]] interface {
	ring.HolesPreSemiRingElement[NS, N]
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

type HolesNaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	HolesNaturalPreSemiRing[NS, N]
	ring.HolesEuclideanSemiRing[NS, N]
}

type HolesNaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	HolesNaturalPreSemiRingElement[NS, N]
	ring.HolesEuclideanSemiRingElement[NS, N]
}

type HolesN[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	HolesNPlus[NS, N]
}

type HolesNat[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	HolesNatPlus[NS, N]
}

type HolesZ[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	ring.HolesEuclideanDomain[NS, N]
}

type HolesInt[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	ring.HolesEuclideanDomainElement[NS, N]
}

func NewNaturalPreSemiRing[NS integer.NaturalPreSemiRing[NS, N], N integer.NaturalPreSemiRingElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalPreSemiRing[NS, N]) NaturalPreSemiRing[NS, N] {
	addition := integer.NewAdditionOperator(arithmetic)
	multiplication := integer.NewMultiplicationOperator(arithmetic)
	b := operator.NewOperatorSuiteBuilder[N]().WithPrimary(addition).WithSecondary(multiplication).Build()
	return NaturalPreSemiRing[NS, N]{
		PreSemiRing:   ring.NewPreSemiRing(H),
		Chain:         order.NewChain(H),
		OperatorSuite: b,
		H:             H,
	}
}

func NewNaturalPreSemiRingElement[NS integer.NaturalPreSemiRing[NS, N], N integer.NaturalPreSemiRingElement[NS, N]](H HolesNaturalPreSemiRingElement[NS, N]) NaturalPreSemiRingElement[NS, N] {
	return NaturalPreSemiRingElement[NS, N]{
		PreSemiRingElement: ring.NewPreSemiRingElement(H),
		ChainElement:       order.NewChainElement(H),
		H:                  H,
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

func NewNaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalSemiRing[NS, N]) NaturalSemiRing[NS, N] {
	return NaturalSemiRing[NS, N]{
		NaturalPreSemiRing: NewNaturalPreSemiRing(arithmetic, H),
		EuclideanSemiRing:  ring.NewEuclideanSemiRing(H),
		H:                  H,
	}
}

func NewNaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](H HolesNaturalSemiRingElement[NS, N]) NaturalSemiRingElement[NS, N] {
	return NaturalSemiRingElement[NS, N]{
		NaturalPreSemiRingElement: NewNaturalPreSemiRingElement(H),
		EuclideanSemiRingElement:  ring.NewEuclideanSemiRingElement(H),
		H:                         H,
	}
}

func NewN_[S integer.N[S, E], E integer.Nat[S, E]](arithmetic integer.Arithmetic[E], H HolesN[S, E]) N[S, E] {
	return N[S, E]{
		NaturalSemiRing: NewNaturalSemiRing(arithmetic, H),
		NPlus:           NewNPlus(arithmetic, H),
		H:               H,
	}
}

func NewNat_[S integer.N[S, E], E integer.Nat[S, E]](H HolesNat[S, E]) Nat_[S, E] {
	return Nat_[S, E]{
		NaturalSemiRingElement:                   NewNaturalSemiRingElement(H),
		LowerBoundedOrderTheoreticLatticeElement: order.NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}

func NewZ_[S integer.Z[S, E], E integer.Int[S, E]](arithmetic integer.Arithmetic[E], H HolesZ[S, E]) Z_[S, E] {
	return Z_[S, E]{
		Groupoid:         groupoid.NewGroupoid(H),
		AdditiveGroupoid: groupoid.NewAdditiveGroupoid(H),
		AdditiveGroup:    group.NewAdditiveGroup(H),
		NaturalSemiRing:  NewNaturalSemiRing(arithmetic, H),
		H:                H,
	}
}

func NewInt_[S integer.Z[S, E], E integer.Int[S, E]](H HolesInt[S, E]) Int_[S, E] {
	return Int_[S, E]{
		NaturalSemiRingElement:  NewNaturalSemiRingElement(H),
		GroupoidElement:         groupoid.NewGroupoidElement(H),
		AdditiveGroupoidElement: groupoid.NewAdditiveGroupoidElement(H),
		AdditiveGroupElement:    group.NewAdditiveGroupElement(H),
		H:                       H,
	}
}
