package constructions_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
)

func _[G algebra.FiniteGroup[E], E algebra.GroupElement[E]]() {
	var (
		_ algebra.Group[*constructions.DirectPowerGroupElement[E]]        = (*constructions.DirectPowerGroup[G, E])(nil)
		_ algebra.GroupElement[*constructions.DirectPowerGroupElement[E]] = (*constructions.DirectPowerGroupElement[E])(nil)

		_ algebra.Group[*constructions.FiniteDirectPowerGroupElement[E]]        = (*constructions.FiniteDirectPowerGroup[G, E])(nil)
		_ algebra.GroupElement[*constructions.FiniteDirectPowerGroupElement[E]] = (*constructions.FiniteDirectPowerGroupElement[E])(nil)
	)
}

func _[R algebra.FiniteRing[E], E algebra.RingElement[E]]() {
	var (
		_ algebra.Ring[*constructions.DirectPowerRingElement[E]]        = (*constructions.DirectPowerRing[R, E])(nil)
		_ algebra.RingElement[*constructions.DirectPowerRingElement[E]] = (*constructions.DirectPowerRingElement[E])(nil)

		_ algebra.Ring[*constructions.FiniteDirectPowerRingElement[E]]        = (*constructions.FiniteDirectPowerRing[R, E])(nil)
		_ algebra.RingElement[*constructions.FiniteDirectPowerRingElement[E]] = (*constructions.FiniteDirectPowerRingElement[E])(nil)
	)
}

func _[M algebra.FiniteModule[E, S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]]() {
	var (
		_ algebra.Module[*constructions.DirectSumModuleElement[E, S], S]        = (*constructions.DirectSumModule[M, E, S])(nil)
		_ algebra.ModuleElement[*constructions.DirectSumModuleElement[E, S], S] = (*constructions.DirectSumModuleElement[E, S])(nil)

		_ algebra.Module[*constructions.FiniteDirectSumModuleElement[E, S], S]        = (*constructions.FiniteDirectSumModule[M, E, S])(nil)
		_ algebra.ModuleElement[*constructions.FiniteDirectSumModuleElement[E, S], S] = (*constructions.FiniteDirectSumModuleElement[E, S])(nil)
	)
}
