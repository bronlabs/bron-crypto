package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	npimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
)

type HolesNaturalSemiRing[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	npimpl.HolesNaturalPreSemiRing[NS, N]
	ring.HolesEuclideanRig[NS, N]
}

type HolesNaturalSemiRingElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	npimpl.HolesNaturalPreSemiRingElement[NS, N]
	ring.HolesEuclideanRigElement[NS, N]
}

type HolesN[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	npimpl.HolesNPlus[NS, N]
}

type HolesNat[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	npimpl.HolesNatPlus[NS, N]
}

func NewNaturalSemiRing[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalSemiRing[NS, N]) NaturalSemiRing[NS, N] {
	return NaturalSemiRing[NS, N]{
		NaturalPreSemiRing: npimpl.NewNaturalPreSemiRing(arithmetic, H),
		EuclideanRig:       ring.NewEuclideanRig(H),
		H:                  H,
	}
}

func NewNaturalSemiRingElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](H HolesNaturalSemiRingElement[NS, N]) NaturalSemiRingElement[NS, N] {
	return NaturalSemiRingElement[NS, N]{
		NaturalPreSemiRingElement: npimpl.NewNaturalPreSemiRingElement(H),
		EuclideanRigElement:       ring.NewEuclideanRigElement(H),
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
