package algebra

import (
	"encoding"
	"io"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/cronokirby/saferith"
)

type Multiplicity uint
type Cardinal = *saferith.Nat

var Infinite Cardinal = nil

// === Interfaces

type Element[E any] interface {
	ds.Clonable[E]
	ds.Hashable[E]

	Structure() Structure[E]

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type Structure[E any] interface {
	Name() string
	Order() Cardinal
}

// === Aspects

type FiniteStructure[E any] interface {
	Random(prng io.Reader) (E, error)
	Hash(bytes []byte) (E, error)
	// ElementSize returns the **exact** number of bytes required to represent an element, required for `SetBytes()`
	ElementSize() int
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element, required for `SetBytesWide()`
	WideElementSize() int
}

type NPointedSet[E NPointedSetElement[E]] interface {
	Structure[E]
	BasePoints() ds.ImmutableMap[string, E]
}

type NPointedSetElement[E Element[E]] interface {
	Element[E]
	IsBasePoint(id string) bool
}
