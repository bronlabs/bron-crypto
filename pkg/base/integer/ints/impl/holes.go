package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	nimpl "github.com/copperexchange/krypton-primitives/pkg/base/integer/nat/impl"
)

type HolesZ[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	nimpl.HolesNaturalSemiRing[NS, N]
	ring.HolesEuclideanDomain[NS, N]
}

type HolesInt[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	nimpl.HolesNaturalSemiRingElement[NS, N]
	ring.HolesEuclideanDomainElement[NS, N]
}

func NewZ_[S integer.Z[S, E], E integer.Int[S, E]](arithmetic integer.Arithmetic[E], H HolesZ[S, E]) Z_[S, E] {
	return Z_[S, E]{
		Groupoid:         groupoid.NewGroupoid(H),
		AdditiveGroupoid: groupoid.NewAdditiveGroupoid(H),
		AdditiveGroup:    group.NewAdditiveGroup(H),
		NaturalSemiRing:  nimpl.NewNaturalSemiRing(arithmetic, H),
		H:                H,
	}
}

func NewInt_[S integer.Z[S, E], E integer.Int[S, E]](H HolesInt[S, E]) Int_[S, E] {
	return Int_[S, E]{
		NaturalSemiRingElement:  nimpl.NewNaturalSemiRingElement(H),
		GroupoidElement:         groupoid.NewGroupoidElement(H),
		AdditiveGroupoidElement: groupoid.NewAdditiveGroupoidElement(H),
		AdditiveGroupElement:    group.NewAdditiveGroupElement(H),
		H:                       H,
	}
}
