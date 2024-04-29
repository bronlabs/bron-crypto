package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Rg[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	algebra.Rg[R, E]
}

type RgElement[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	algebra.RgElement[R, E]
}

type Rig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	algebra.Rig[R, E]
}

type RigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	algebra.RigElement[R, E]
}

type Ring[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	algebra.Ring[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	algebra.RingElement[R, E]
}

type FiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	algebra.FiniteRing[R, E]
}

type FiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	algebra.FiniteRingElement[R, E]
}
