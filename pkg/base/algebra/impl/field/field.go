package field

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/domain"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
)

type Field[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct {
	domain.EuclideanDomain[F, E]
	group.MultiplicativeGroup[F, E]
	H HolesField[F, E]
}

type FiniteField[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct {
	Field[F, E]
	domain.FiniteEuclideanDomain[F, E]
	H HolesFiniteField[F, E]
}

type ExtensionField[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] struct {
	Field[L, LE]
	H HolesExtensionField[L, K, LE, KE]
}
