package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	Cardinal = crtp.Cardinal

	NPlusLike[E NatPlusLike[E]]        crtp.NPlusLike[E]
	NatPlusLike[E crtp.NatPlusLike[E]] crtp.NatPlusLike[E]

	NLike[E NatLike[E]]        crtp.NLike[E]
	NatLike[E crtp.NatLike[E]] crtp.NatLike[E]

	ZLike[E IntLike[E]]        crtp.ZLike[E]
	IntLike[E crtp.IntLike[E]] crtp.IntLike[E]

	ZnLike[E UintLike[E]]        crtp.ZnLike[E]
	UintLike[E crtp.UintLike[E]] crtp.UintLike[E]

	PrimeField[E PrimeFieldElement[E]]             crtp.PrimeField[E]
	PrimeFieldElement[E crtp.PrimeFieldElement[E]] crtp.PrimeFieldElement[E]
)
