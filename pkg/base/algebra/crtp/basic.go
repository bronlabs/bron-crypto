package crtp

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
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
	Model() *universal.Model[E]
	base.BytesLikeFactory[E]
}

type FiniteStructure[E any] interface {
	base.BytesLikeFactory[E]
	Random(prng io.Reader) (E, error)
	Hash(bytes []byte) (E, error)
}

type Quotient[E any] interface {
	Structure[E]
	Modulus() E
	AmbientModel() *universal.Model[E]
}

type Residue[E any] interface {
	Element[E]
	Modulus() E
}
