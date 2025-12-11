package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	Cardinal                       = crtp.Cardinal
	NumericStructure[E Numeric[E]] = crtp.NumericStructure[E]
	Numeric[E any]                 = crtp.Numeric[E]

	NPlusLike[E NatPlusLike[E]]        crtp.NPlusLike[E]
	NatPlusLike[E crtp.NatPlusLike[E]] crtp.NatPlusLike[E]

	NLike[E NatLike[E]]        crtp.NLike[E]
	NatLike[E crtp.NatLike[E]] crtp.NatLike[E]

	ZLike[E IntLike[E]]        crtp.ZLike[E]
	IntLike[E crtp.IntLike[E]] crtp.IntLike[E]

	ZModLike[E UintLike[E]]      crtp.ZModLike[E]
	UintLike[E crtp.UintLike[E]] crtp.UintLike[E]

	PrimeField[E PrimeFieldElement[E]]             crtp.PrimeField[E]
	PrimeFieldElement[E crtp.PrimeFieldElement[E]] crtp.PrimeFieldElement[E]
)
