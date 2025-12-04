package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"pgregory.net/rapid"
)

// Model combines a Structure with a Theory of properties to test.
// It represents a complete testable algebraic model.
type Model[S algebra.Structure[E], E algebra.Element[E]] struct {
	*Structure[S, E]
	Theory Theory[S, E]
}

// NewModel creates a new model from a structure.
func NewModel[S algebra.Structure[E], E algebra.Element[E]](
	structure *Structure[S, E],
) *Model[S, E] {
	return &Model[S, E]{
		Structure: structure,
	}
}

// NewModelFrom creates a new model from carrier and generator.
func NewModelFrom[S algebra.Structure[E], E algebra.Element[E]](
	carrier S,
	gen *rapid.Generator[E],
) *Model[S, E] {
	return &Model[S, E]{
		Structure: NewStructure(carrier, gen),
	}
}

// With adds properties to the model's theory.
func (m *Model[S, E]) With(props ...Property[S, E]) *Model[S, E] {
	m.Theory = m.Theory.Append(props...)
	return m
}

// WithTheory adds all properties from a theory.
func (m *Model[S, E]) WithTheory(theory Theory[S, E]) *Model[S, E] {
	m.Theory = m.Theory.AppendTheory(theory)
	return m
}

// WithAddition sets the addition operator and returns the model.
func (m *Model[S, E]) WithAddition(add *BinaryOp[E]) *Model[S, E] {
	m.Structure.WithAddition(add)
	return m
}

// WithMultiplication sets the multiplication operator and returns the model.
func (m *Model[S, E]) WithMultiplication(mul *BinaryOp[E]) *Model[S, E] {
	m.Structure.WithMultiplication(mul)
	return m
}

// Check runs all properties in the model's theory.
func (m *Model[S, E]) Check(t *testing.T) {
	t.Helper()
	ctx := NewContext(t, m.Structure)
	for _, prop := range m.Theory {
		prop.Run(t, ctx)
	}
}

// CheckSerial runs all properties serially (not in parallel).
// Useful for debugging.
func (m *Model[S, E]) CheckSerial(t *testing.T) {
	t.Helper()
	ctx := NewContext(t, m.Structure)
	for _, prop := range m.Theory {
		t.Run(prop.Name, func(t *testing.T) {
			prop.Check(t, ctx)
		})
	}
}
