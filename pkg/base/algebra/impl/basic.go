package impl

import (
	"fmt"
	"io"

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

type FiniteStructure[E any] interface {
	Structure[E]
	Random(prng io.Reader) (E, error)
	Hash(bytes []byte) (E, error)
	base.BytesLikeFactory[E]
}

type NAry[C any] interface {
	Arity() Cardinal
	Components() []C
}

type Mapping[E, C any] interface {
	NAry[C]
	New(...C) (E, error)
}

type Product[P, C any] interface {
	NAry[C]
	Diagonal(C) P
}

type CoProduct[P, C any] interface {
	NAry[C]
	CoDiagonal() C
}
type Power[P, C any] interface {
	Product[P, C]
	Factor() C
}

type TensorProduct[E, C, S any] interface {
	Module[E, S]
	Mapping[E, C]
}

type Tensor[E, S any] ModuleElement[E, S]
