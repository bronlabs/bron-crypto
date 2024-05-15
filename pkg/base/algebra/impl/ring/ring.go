package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type Rg[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	groupoid.Groupoid[R, E]
	groupoid.AdditiveGroupoid[R, E]
	groupoid.MultiplicativeGroupoid[R, E]
	H HolesRg[R, E]
}

type Rig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	Rg[R, E]
	monoid.Monoid[R, E]
	monoid.AdditiveMonoid[R, E]
	monoid.MultiplicativeMonoid[R, E]
	H HolesRig[R, E]
}

type Ring[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	Rig[R, E]
	group.Group[R, E]
	group.AdditiveGroup[R, E]
	monoid.MultiplicativeMonoid[R, E]
	H HolesRing[R, E]
}

type FiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	Ring[R, E]
	H HolesFiniteRing[R, E]
}
