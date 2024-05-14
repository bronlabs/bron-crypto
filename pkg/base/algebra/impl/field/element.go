package field

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/domain"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type FieldElement[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct {
	domain.EuclideanDomainElement[F, E]
	group.MultiplicativeGroupElement[F, E]
}

type FiniteFieldElement[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct {
	FieldElement[F, E]
	ring.FiniteRingElement[F, E]
}

type ExtensionFieldElement[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] struct {
	FieldElement[L, LE]
}
