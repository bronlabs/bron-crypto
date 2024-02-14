package algebra

import (
	"encoding/json"
	"io"

	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

// Structure is a type that implements methods needed for the corresponding structured set. Example: Some struct that
// implements methods needed for a group.
type Structure any

// Element is a type of an element of a structured set. Examples are elements of a group or points of a curve.
type Element any

// EnrichedElement is a parameter of a module-like structure corresponding to some structured. Example: Base field of a vector space where E is the element of the base field.
type EnrichedElement[E Element] any

// AbstractStructuredSet implements the basic methods shared by all other higher level structures.
type AbstractStructuredSet[S Structure, E Element] interface {
	// Name returns the name of the structure S.
	Name() string
	// Element returns an unspecified element of the structure S with type E.
	Element() E

	// Order is the number of all elements in structure S.
	Order() *saferith.Modulus
	// Operators returns an ordered list of operators over which the structure S is defined.
	Operators() []Operator
	// OperateOver accepts an operator and type E elements of structure S, and returns application of the operator
	// to those elements.
	// If the operator is returned by the Operators(), it will return an error.
	// It may return an error if S is not right associative and len(xs) > 2.
	OperateOver(operator Operator, xs ...E) (E, error)

	// Random accepts a prng and returns a type E element of structure S.
	Random(prng io.Reader) (E, error)
	// Hash maps a byte array to a type E element of structure S.
	Hash(x []byte) (E, error)
	// Select returns (in constant time) x0 if choice is false, and x1 if choice is true.
	Select(choice bool, x0, x1 E) E
}

// AbstractStructuredSetElement implements the basic methods shared by elements of all other higher level structures.
type AbstractStructuredSetElement[S Structure, E Element] interface {
	// Equal returns true if this element and the input element are equal.
	Equal(e E) bool
	// Clone returns a deep copy of this element.
	Clone() E

	ds.Hashable[E]
	// We regularly want to unmarshal into an interfacel To do that we'll use a helper function instead of embedding the unmarshaller here.
	json.Marshaler
}

type NatLike[E Element] interface {
	// Uint64 casts the scalar down to a 64-bit integer. Might overflow.
	Uint64() uint64
	// SetNat returns a new element set to the value of `v mod S.Order()`.
	SetNat(v *saferith.Nat) E
	// Nat casts this element as a Nat.
	Nat() *saferith.Nat
}

type BytesLike[E Element] interface {
	// Bytes returns the canonical big-endian byte representation of this element.
	// s.t. this = Σ_{i=0}^{k-1} (this.Bytes()[i] << 8*(k-i-1) ). The result
	// is always FieldBytes long.
	Bytes() []byte
	// SetBytes creates an element from a big-endian byte representation
	// s.t. element = Σ_{i=0}^{k-1} (input[i] << 8*(k-i-1) ). The input must be exactly
	// FieldBytes long.
	// WARNING: do not use it for uniform sampling, use SetBytesWide instead.
	SetBytes(bytes []byte) (E, error)
	// SetBytesWide creates an element from uniformly sampled bytes, reducing the result
	// with S.Order(). The input must be at most k*WideFieldBytes long.
	SetBytesWide(bytes []byte) (E, error)
}
