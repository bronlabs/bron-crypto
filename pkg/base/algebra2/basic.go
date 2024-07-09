package algebra

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/cronokirby/saferith"
)

// === Interfaces

type Multiplicity = int

type Set[E any] ds.AbstractSet[E]

type SpaceWrapping[S any] interface {
	Name() string
	Unwrap() S
}

type StructureWrapping[S, E any] interface {
	SpaceWrapping[S]
	GetUnaryOperator(op OperatorName) (UnaryOperator[E], error)
	GetOperator(op OperatorName) (BinaryOperator[E], error)
}

type ElementWrapping[E any] interface {
	// Equal returns true if this element and the input element are equal.
	Unwrap() E
	// Clone returns a deep copy of this element.
	Clone() E
	ds.Equatable[E]
}

type Element[E any] interface {
	ElementWrapping[E]
	ds.Hashable[E]
}

type Space[S Set[E], E Element[E]] interface {
	Set[E]
	SpaceWrapping[S]

	Order() *saferith.Nat
}

// StructuredSet implements the basic methods shared by all other higher level structures.
type Structure[S Set[E], E Element[E], Op BinaryOperator[E]] interface {
	Space[S, E]
	StructureWrapping[S, E]
	Operator() Op
}

type BiStructure[S Set[E], E Element[E], Op1, Op2 BinaryOperator[E]] interface {
	Structure[S, E, Op1]
	OtherOperator() Op2
}

type SuperSpace[S Space[S, E], US any, E Element[E]] interface {
	Space[S, E]
	SubStructure() US
}

type SuperStructure[S Structure[S, E, Op], US any, E Element[E], Op BinaryOperator[E]] interface {
	SuperSpace[S, US, E]
	Structure[S, E, Op]
}

type BiSuperStructure[S Structure[S, E, Op1], US any, E Element[E], Op1, Op2 BinaryOperator[E]] interface {
	SuperSpace[S, US, E]
	BiStructure[S, E, Op1, Op2]
}

// === Aspects

type FiniteStructure[E any] interface {
	Random(prng io.Reader) (E, error)
	Hash(bytes []byte) (E, error)
	// ElementSize returns the **exact** number of bytes required to represent an element, required for `SetBytes()`
	ElementSize() int
	// WideElementSize returns the **maximum** number of bytes used to map uniformly to an element, required for `SetBytesWide()`
	WideElementSize() int

	// ConditionallySelectable[E]
}

type StructuralCyclicness[E any] interface {
	Generator() E
}

type ElementalCyclicness interface {
	IsDesignatedGenerator() bool
	CanGenerateAllElements() bool
}

type StructuralUnitality[E any] interface {
	Unit() E
}

type ElementalUnitality[E any] interface {
	IsUnit() E
}

type (
	AssociativeStructure[E any, Op BinaryOperator[E]]         any
	AssociativeBiStructure[E any, Op1, Op2 BinaryOperator[E]] interface {
		AssociativeStructure[E, Op1]
		AssociativeStructure[E, Op2]
	}

	DistributiveBiStructure[E any, OpOuter, OpInner BinaryOperator[E]] any

	CommutativeStructure[E any, Op BinaryOperator[E]]         any
	CommutativeBiStructure[E any, Op1, Op2 BinaryOperator[E]] interface {
		CommutativeStructure[E, Op1]
		CommutativeStructure[E, Op2]
	}
)
