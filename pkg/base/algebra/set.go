package algebra

import (
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
)

// Structure is a type that implements methods needed for the corresponding structured set. Example: Some struct that
// implements methods needed for a group.
type Structure Object

// Element is a type of an element of a structured set. Examples are elements of a group or points of a curve.
type Element Object

type Set[E Element] ds.AbstractSet[E, *saferith.Nat]

// StructuredSet implements the basic methods shared by all other higher level structures.
type StructuredSet[S Structure, E Element] interface {
	Set[E]

	Random(prng io.Reader) (E, error)

	// Element returns an unspecified element of the structure S with type E.
	Element() E
	// Name returns the name of the structure S.
	Name() string
	Order() *saferith.Modulus
	// Operators returns an ordered list of operators over which the structure S is defined.
	Operators() []BinaryOperator[E]

	Unwrap() S

	ConditionallySelectable[E]
}

// StructuredSetElement implements the basic methods shared by elements of all other higher level structures.
type StructuredSetElement[S Structure, E Element] interface {
	Structure() S

	// Equal returns true if this element and the input element are equal.
	Unwrap() E

	// Clone returns a deep copy of this element.
	Clone() E

	ds.Hashable[E]
	// We regularly want to unmarshal into an interface. To do that we'll use a helper function instead of embedding the unmarshaller here.
	json.Marshaler
}

type FiniteStructure[S Structure, E Element] interface {
	StructuredSet[S, E]
	Hash(bytes []byte) (E, error)
	// ElementSize returns the **exact** number of bytes required to represent an element, required for `SetBytes()`
	ElementSize() int
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element, required for `SetBytesWide()`
	WideElementSize() int
}

type PointedSet[S Structure, E Element] interface {
	StructuredSet[S, E]
	BasePoint() E
}

type PointedSetElement[S Structure, E Element] interface {
	StructuredSetElement[S, E]
	IsBasePoint() bool
}
