package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type RgElement[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	algebra.RgElement[R, E]
}

func (e *RgElement[R, E]) MulAdd(p, q algebra.RgElement[R, E]) E {
	return e.Mul(p).Add(q)
}

type RigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	algebra.RigElement[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	algebra.RingElement[R, E]
}

type FiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	algebra.FiniteRingElement[R, E]
}
