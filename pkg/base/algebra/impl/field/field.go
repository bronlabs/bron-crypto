package field

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type Field[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct {
	algebra.Field[F, E]
}

type FiniteField[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct {
	algebra.FiniteField[F, E]
}

type ExtensionField[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] struct {
	algebra.ExtensionField[L, K, LE, KE]
}
