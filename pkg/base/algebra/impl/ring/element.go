package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type RgElement[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	groupoid.GroupoidElement[R, E]
	groupoid.AdditiveGroupoidElement[R, E]
	groupoid.MultiplicativeGroupoidElement[R, E]
}

func (e *RgElement[R, E]) MulAdd(p, q algebra.RgElement[R, E]) E {
	return e.Mul(p).Add(q)
}

type RigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	monoid.MonoidElement[R, E]
	monoid.AdditiveMonoidElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	group.GroupElement[R, E]
	group.AdditiveGroupElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]
}

type FiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	RingElement[R, E]
}
