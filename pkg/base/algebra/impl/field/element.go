package field

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type FieldElement[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct {
	algebra.FieldElement[F, E]
}

type FiniteFieldElement[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct {
	algebra.FiniteFieldElement[F, E]
}

type ExtensionFieldElement[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] struct {
	algebra.ExtensionFieldElement[L, K, LE, KE]
}
