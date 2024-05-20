package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	zimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/ints/impl"
	nimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/impl"
)

type HolesZn[S integer.Zn[S, E], E integer.Uint[S, E]] interface {
	groupoid.HolesGroupoid[S, E]
	group.HolesAdditiveGroup[S, E]
	nimpl.HolesNaturalSemiRing[S, E]
	order.HolesBoundedOrderTheoreticLattice[S, E]

	ModularArithmetic() integer.ModularArithmetic[E]
}

type HolesUint[S integer.Zn[S, E], E integer.Uint[S, E]] interface {
	zimpl.HolesInt[S, E]
	order.HolesBoundedOrderTheoreticLatticeElement[S, E]
	ring.HolesFiniteRingElement[S, E]

	ModularArithmetic() integer.ModularArithmetic[E]
}

func NewZn_[S integer.Zn[S, E], E integer.Uint[S, E]](arithmetic integer.Arithmetic[E], H HolesZn[S, E]) Zn_[S, E] {
	return Zn_[S, E]{
		Groupoid:                     groupoid.NewGroupoid(H),
		NaturalSemiRing:              nimpl.NewNaturalSemiRing(arithmetic, H),
		BoundedOrderTheoreticLattice: order.NewBoundedOrderTheoreticLattice(H),
		wrappedS: wrappedS[S, E]{
			AdditiveGroup: group.NewAdditiveGroup(H),
		},
		H: H,
	}
}

func NewUint_[S integer.Zn[S, E], E integer.Uint[S, E]](H HolesUint[S, E]) Uint_[S, E] {
	return Uint_[S, E]{
		Int_:                                zimpl.NewInt_(H),
		BoundedOrderTheoreticLatticeElement: order.NewBoundedOrderTheoreticLatticeElement(H),
		wrappedE: wrappedE[S, E]{
			FiniteRingElement: ring.NewFiniteRingElement(H),
		},
		H: H,
	}
}
