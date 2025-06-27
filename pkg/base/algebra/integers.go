package algebra

import (
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
)

type (
	NPlusLike[E NatPlusLike[E]]         aimpl.NPlusLike[E]
	NatPlusLike[E aimpl.NatPlusLike[E]] aimpl.NatPlusLike[E]

	NLike[E NatLike[E]]         aimpl.NLike[E]
	NatLike[E aimpl.NatLike[E]] aimpl.NatLike[E]

	ZLike[E IntLike[E]]         aimpl.ZLike[E]
	IntLike[E aimpl.IntLike[E]] aimpl.IntLike[E]

	ZnLike[E UintLike[E]]         aimpl.ZnLike[E]
	UintLike[E aimpl.UintLike[E]] aimpl.UintLike[E]

	PrimeField[E PrimeFieldElement[E]]              aimpl.PrimeField[E]
	PrimeFieldElement[E aimpl.PrimeFieldElement[E]] aimpl.PrimeFieldElement[E]
)
