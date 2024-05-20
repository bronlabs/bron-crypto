package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	npimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
)

type HolesNaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	npimpl.HolesNaturalPreSemiRing[NS, N]
	ring.HolesEuclideanSemiRing[NS, N]
}

type HolesNaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	npimpl.HolesNaturalPreSemiRingElement[NS, N]
	ring.HolesEuclideanSemiRingElement[NS, N]
}

type HolesN[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	npimpl.HolesNPlus[NS, N]
}

type HolesNat[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	npimpl.HolesNatPlus[NS, N]
}

func NewNaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalSemiRing[NS, N]) NaturalSemiRing[NS, N] {
	return NaturalSemiRing[NS, N]{
		NaturalPreSemiRing: npimpl.NewNaturalPreSemiRing(arithmetic, H),
		EuclideanSemiRing:  ring.NewEuclideanSemiRing(H),
		H:                  H,
	}
}

func NewNaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](H HolesNaturalSemiRingElement[NS, N]) NaturalSemiRingElement[NS, N] {
	return NaturalSemiRingElement[NS, N]{
		NaturalPreSemiRingElement: npimpl.NewNaturalPreSemiRingElement(H),
		EuclideanSemiRingElement:  ring.NewEuclideanSemiRingElement(H),
		H:                         H,
	}
}

func NewN_[S integer.N[S, E], E integer.Nat[S, E]](arithmetic integer.Arithmetic[E], H HolesN[S, E]) N[S, E] {
	return N[S, E]{
		NaturalSemiRing: NewNaturalSemiRing(arithmetic, H),
		NPlus:           npimpl.NewNPlus(arithmetic, H),
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
