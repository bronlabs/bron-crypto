package universal

import (
	"iter"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Element[E any] base.Equatable[E]

type CarrierSet[E any] interface {
	Iter() iter.Seq[E]
}

type Constant string
type UnaryProperty[E Element[E]] func(E) bool
type BinaryProperty[E Element[E]] func(E, E) bool
type TernaryProperty[E Element[E]] func(E, E, E) bool
type MixedSortedBinaryProperty[E1 Element[E1], E2 Element[E2]] func(E1, E2) bool
type MixedSortedTernaryProperty[E1 Element[E1], E2 Element[E2]] func(E1, E2, E2) bool

const (
	Identity Constant = "identity"
	Zero     Constant = "zero"
	One      Constant = "one"
)

type Signature[E Element[E]] struct {
	Nullary map[Constant]E
	Unary   []UnaryOperator[E]
	Binary  []BinaryOperator[E]
}

// NewSignature creates a new Signature instance with the provided nullary, unary, and binary operators.
// If any of the maps or slices are nil, they will be initialized to empty structures.
func NewSignature[E Element[E]](
	nullary map[Constant]E, unary []UnaryOperator[E], binary []BinaryOperator[E],
) Signature[E] {
	sig := Signature[E]{}
	if nullary != nil {
		sig.Nullary = maps.Clone(nullary)
	} else {
		sig.Nullary = map[Constant]E{}
	}
	if unary != nil {
		sig.Unary = slices.Clone(unary)
	} else {
		sig.Unary = []UnaryOperator[E]{}
	}
	if binary != nil {
		sig.Binary = slices.Clone(binary)
	} else {
		sig.Binary = []BinaryOperator[E]{}
	}
	return sig
}

type MixedSignature[E1 Element[E1], E2 Element[E2]] struct {
	Binary []MixedSortedBinaryOperator[E1, E2]
}

func NewMixedSignature[E1 Element[E1], E2 Element[E2]](
	binary []MixedSortedBinaryOperator[E1, E2],
) MixedSignature[E1, E2] {
	mixed := MixedSignature[E1, E2]{}
	if binary != nil {
		mixed.Binary = slices.Clone(binary)
	} else {
		mixed.Binary = []MixedSortedBinaryOperator[E1, E2]{}
	}
	return mixed
}

type Axioms[E Element[E]] struct {
	Unary   []UnaryProperty[E]
	Binary  []BinaryProperty[E]
	Ternary []TernaryProperty[E]
}

// NewAxioms creates a new Axioms instance with the provided unary, binary, and ternary properties.
// If any of the slices are nil, they will be initialized to empty slices.
func NewAxioms[E Element[E]](
	unary []UnaryProperty[E], binary []BinaryProperty[E], ternary []TernaryProperty[E],
) Axioms[E] {
	axiom := Axioms[E]{}
	if unary != nil {
		axiom.Unary = slices.Clone(unary)
	} else {
		axiom.Unary = []UnaryProperty[E]{}
	}
	if binary != nil {
		axiom.Binary = slices.Clone(binary)
	} else {
		axiom.Binary = []BinaryProperty[E]{}
	}
	if ternary != nil {
		axiom.Ternary = slices.Clone(ternary)
	} else {
		axiom.Ternary = []TernaryProperty[E]{}
	}
	return axiom
}

type MixedAxioms[E1 Element[E1], E2 Element[E2]] struct {
	Binary  []MixedSortedBinaryProperty[E1, E2]
	Ternary []MixedSortedTernaryProperty[E1, E2]
}

// NewMixedAxioms creates a new MixedAxioms instance with the provided binary and ternary properties.
// If any of the slices are nil, they will be initialized to empty slices.
func NewMixedAxioms[E1 Element[E1], E2 Element[E2]](
	binary []MixedSortedBinaryProperty[E1, E2],
	ternary []MixedSortedTernaryProperty[E1, E2],
) MixedAxioms[E1, E2] {
	mixed := MixedAxioms[E1, E2]{}
	if binary != nil {
		mixed.Binary = slices.Clone(binary)
	} else {
		mixed.Binary = []MixedSortedBinaryProperty[E1, E2]{}
	}
	if ternary != nil {
		mixed.Ternary = slices.Clone(ternary)
	} else {
		mixed.Ternary = []MixedSortedTernaryProperty[E1, E2]{}
	}
	return mixed
}

type Theory[C CarrierSet[E], E Element[E]] struct {
	CarrierSet C
	Signature  Signature[E]
	Axiom      Axioms[E]
}

func (t Theory[C, E]) Clone() Theory[C, E] {
	return Theory[C, E]{
		CarrierSet: t.CarrierSet,
		Signature:  NewSignature(maps.Clone(t.Signature.Nullary), slices.Clone(t.Signature.Unary), slices.Clone(t.Signature.Binary)),
		Axiom:      NewAxioms(slices.Clone(t.Axiom.Unary), slices.Clone(t.Axiom.Binary), slices.Clone(t.Axiom.Ternary)),
	}
}

// NewTheory creates a new Theory instance with the provided carrier set, signature, and axioms.
// If any of the components are nil, they will be initialized to empty structures.
func NewTheory[C CarrierSet[E], E Element[E]](c C, s Signature[E], a Axioms[E]) Theory[C, E] {
	t := Theory[C, E]{
		CarrierSet: c,
		Signature:  s,
		Axiom:      a,
	}
	return t
}

type TwoSortedTheory[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]] struct {
	First          Theory[C1, E1]
	Second         Theory[C2, E2]
	MixedSignature MixedSignature[E1, E2]
	MixedAxioms    MixedAxioms[E1, E2]
}

func NewTwoSortedTheory[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]](
	first Theory[C1, E1], second Theory[C2, E2], mixedSignature MixedSignature[E1, E2], mixedAxioms MixedAxioms[E1, E2],
) TwoSortedTheory[C1, C2, E1, E2] {
	return TwoSortedTheory[C1, C2, E1, E2]{
		First:       first,
		Second:      second,
		MixedAxioms: mixedAxioms,
	}
}

func MakeAbelian[C CarrierSet[E], E Element[E]](t Theory[C, E], under ...BinaryOperator[E]) (Theory[C, E], error) {
	for i, targetOp := range under {
		for _, op := range t.Signature.Binary {
			if op.Equal(targetOp) {
				t.Axiom.Binary = append(t.Axiom.Binary, targetOp.IsCommutative)
				return t, nil
			}
		}
		return *new(Theory[C, E]), errs.NewMissing("theory is not defined under the %d provided operator", i)
	}
	return *new(Theory[C, E]), errs.NewMissing("no operator provided to make the theory abelian")
}

func ExpandTheory[C CarrierSet[E], E Element[E]](t1, t2 Theory[C, E]) Theory[C, E] {
	t := t1.Clone()
	for c, op := range t2.Signature.Nullary {
		if _, exists := t.Signature.Nullary[c]; !exists {
			t.Signature.Nullary[c] = op
		}
	}
	t.Signature.Unary = append(t.Signature.Unary, t2.Signature.Unary...)
	t.Signature.Binary = append(t.Signature.Binary, t2.Signature.Binary...)
	t.Axiom.Unary = append(t.Axiom.Unary, t2.Axiom.Unary...)
	t.Axiom.Binary = append(t.Axiom.Binary, t2.Axiom.Binary...)
	t.Axiom.Ternary = append(t.Axiom.Ternary, t2.Axiom.Ternary...)
	return t
}
