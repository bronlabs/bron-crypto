package crtp

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

// === Interfaces

type Element[E any] interface {
	Structure() Structure[E]
	base.BytesLike
	base.Clonable[E]
	base.Hashable[E]
	fmt.Stringer
}

type Structure[E any] interface {
	Name() string
	Order() Cardinal
	base.BytesLikeFactory[E]
}

type Quotient[E any] interface {
	Structure[E]
	Modulus() E
	AmbientStructure() Structure[E]
}

type Residue[E any] interface {
	Element[E]
	Modulus() E
}
