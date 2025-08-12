package fields

import "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"

type (
	FiniteFieldElement[E impl.FiniteFieldElement[E]]           = impl.FiniteFieldElement[E]
	FiniteFieldElementPtr[E impl.FiniteFieldElement[E], T any] = impl.FiniteFieldElementPtr[E, T]

	PrimeFieldElement[E impl.PrimeFieldElement[E]]           = impl.PrimeFieldElement[E]
	PrimeFieldElementPtr[E impl.PrimeFieldElement[E], T any] = impl.PrimeFieldElementPtr[E, T]
)
