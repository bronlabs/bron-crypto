package fields

import "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"

type (
	FiniteFieldElement[E impl.FiniteFieldElementLowLevel[E]]                 = impl.FiniteFieldElementLowLevel[E]
	FiniteFieldElementPtr[E impl.FiniteFieldElementPtrLowLevel[E, T], T any] = impl.FiniteFieldElementPtrLowLevel[E, T]

	PrimeFieldElement[E impl.PrimeFieldElementLowLevel[E]]                 = impl.PrimeFieldElementLowLevel[E]
	PrimeFieldElementPtr[E impl.PrimeFieldElementPtrLowLevel[E, T], T any] = impl.PrimeFieldElementPtrLowLevel[E, T]
)
