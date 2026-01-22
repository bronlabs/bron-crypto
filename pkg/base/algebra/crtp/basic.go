package crtp

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

// === Interfaces.

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

type FiniteStructure[E any] interface {
	base.BytesLikeFactory[E]
	Random(prng io.Reader) (E, error)
	Hash(bytes []byte) (E, error)
}

type Quotient[E, M, A any] interface {
	Structure[E]
	Modulus() M
	AmbientStructure() Structure[A]
}

type Residue[E, M any] interface {
	Element[E]
	Modulus() M
	EqualModulus(other E) bool
}
