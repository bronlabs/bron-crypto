package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Rg[R algebra.Rg[R, E], E algebra.RgElement[R, E]] struct {
	algebra.Rg[R, E]
}

type Rig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	algebra.Rig[R, E]
}

type Ring[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	algebra.Ring[R, E]
}

type FiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	algebra.FiniteRing[R, E]
}
