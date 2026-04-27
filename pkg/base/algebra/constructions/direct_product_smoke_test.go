package constructions_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
)

func _[G1 algebra.FiniteGroup[E1], G2 algebra.FiniteGroup[E2], E1 algebra.GroupElement[E1], E2 algebra.GroupElement[E2]]() {
	var (
		_ algebra.Group[*constructions.DirectProductGroupElement[E1, E2]]        = (*constructions.DirectProductGroup[G1, G2, E1, E2])(nil)
		_ algebra.GroupElement[*constructions.DirectProductGroupElement[E1, E2]] = (*constructions.DirectProductGroupElement[E1, E2])(nil)

		_ algebra.Group[*constructions.FiniteDirectProductGroupElement[E1, E2]]        = (*constructions.FiniteDirectProductGroup[G1, G2, E1, E2])(nil)
		_ algebra.GroupElement[*constructions.FiniteDirectProductGroupElement[E1, E2]] = (*constructions.FiniteDirectProductGroupElement[E1, E2])(nil)
	)
}

func _[R1 algebra.FiniteRing[E1], R2 algebra.FiniteRing[E2], E1 algebra.RingElement[E1], E2 algebra.RingElement[E2]]() {
	var (
		_ algebra.Ring[*constructions.DirectProductRingElement[E1, E2]]        = (*constructions.DirectProductRing[R1, R2, E1, E2])(nil)
		_ algebra.RingElement[*constructions.DirectProductRingElement[E1, E2]] = (*constructions.DirectProductRingElement[E1, E2])(nil)

		_ algebra.Ring[*constructions.FiniteDirectProductRingElement[E1, E2]]        = (*constructions.FiniteDirectProductRing[R1, R2, E1, E2])(nil)
		_ algebra.RingElement[*constructions.FiniteDirectProductRingElement[E1, E2]] = (*constructions.FiniteDirectProductRingElement[E1, E2])(nil)
	)
}

func _[M1 algebra.FiniteModule[E1, S], M2 algebra.FiniteModule[E2, S], E1 algebra.ModuleElement[E1, S], E2 algebra.ModuleElement[E2, S], S algebra.RingElement[S]]() {
	var (
		_ algebra.Module[*constructions.DirectProductModuleElement[E1, E2, S], S]        = (*constructions.DirectProductModule[M1, M2, E1, E2, S])(nil)
		_ algebra.ModuleElement[*constructions.DirectProductModuleElement[E1, E2, S], S] = (*constructions.DirectProductModuleElement[E1, E2, S])(nil)

		_ algebra.Module[*constructions.FiniteDirectProductModuleElement[E1, E2, S], S]        = (*constructions.FiniteDirectProductModule[M1, M2, E1, E2, S])(nil)
		_ algebra.ModuleElement[*constructions.FiniteDirectProductModuleElement[E1, E2, S], S] = (*constructions.FiniteDirectProductModuleElement[E1, E2, S])(nil)
	)
}
