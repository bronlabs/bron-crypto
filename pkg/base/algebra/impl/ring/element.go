package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type RgElement[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]] struct {
	groupoid.GroupoidElement[R, E]
	groupoid.AdditiveGroupoidElement[R, E]
	groupoid.MultiplicativeGroupoidElement[R, E]

	H HolesRgElement[R, E]
}

func (e *RgElement[R, E]) MulAdd(p, q algebra.PreSemiRingElement[R, E]) E {
	return e.H.Mul(p).Add(q)
}

type RigElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] struct {
	monoid.MonoidElement[R, E]
	monoid.AdditiveMonoidElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesRigElement[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	RigElement[R, E]
	group.GroupElement[R, E]
	group.AdditiveGroupElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesRingElement[R, E]
}

type FiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	RingElement[R, E]

	H HolesFiniteRingElement[R, E]
}
