package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Suite provides a fluent API for building and running property tests.
// It's an alternative to using Model directly, offering a more
// builder-pattern style interface.
type Suite[S algebra.Structure[E], E algebra.Element[E]] struct {
	t      *testing.T
	model  *Model[S, E]
	ctx    *Context[S, E]
	frozen bool
}

// New creates a new property test suite.
func New[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T,
	carrier S,
	gen *rapid.Generator[E],
) *Suite[S, E] {
	t.Helper()
	require.NotNil(t, gen, "generator must not be nil")

	structure := NewStructure(carrier, gen)
	model := NewModel(structure)

	return &Suite[S, E]{
		t:     t,
		model: model,
	}
}

// WithAddition sets the addition operator.
func (s *Suite[S, E]) WithAddition(add *BinaryOp[E]) *Suite[S, E] {
	s.requireNotFrozen()
	s.model.WithAddition(add)
	return s
}

// WithMultiplication sets the multiplication operator.
func (s *Suite[S, E]) WithMultiplication(mul *BinaryOp[E]) *Suite[S, E] {
	s.requireNotFrozen()
	s.model.WithMultiplication(mul)
	return s
}

// With adds properties to the suite.
func (s *Suite[S, E]) With(props ...Property[S, E]) *Suite[S, E] {
	s.requireNotFrozen()
	s.model.With(props...)
	return s
}

// WithTheory adds all properties from a theory.
func (s *Suite[S, E]) WithTheory(theory Theory[S, E]) *Suite[S, E] {
	s.requireNotFrozen()
	s.model.WithTheory(theory)
	return s
}

// CheckAll runs all properties in the suite.
func (s *Suite[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	s.freeze()
	s.model.Check(t)
}

// Context returns the testing context.
// Freezes the suite (no more modifications allowed).
func (s *Suite[S, E]) Context() *Context[S, E] {
	s.freeze()
	return s.ctx
}

// Structure returns the underlying structure.
func (s *Suite[S, E]) Structure() *Structure[S, E] {
	return s.model.Structure
}

// Carrier returns the algebraic structure.
func (s *Suite[S, E]) Carrier() S {
	return s.model.Carrier
}

// Generator returns the element generator.
func (s *Suite[S, E]) Generator() *rapid.Generator[E] {
	return s.model.Generator
}

// Model returns the underlying model.
func (s *Suite[S, E]) Model() *Model[S, E] {
	return s.model
}

// freeze prevents further modifications and creates the context.
func (s *Suite[S, E]) freeze() {
	if !s.frozen {
		s.frozen = true
		s.ctx = NewContext(s.t, s.model.Structure)
	}
}

// requireNotFrozen panics if the suite has been frozen.
func (s *Suite[S, E]) requireNotFrozen() {
	if s.frozen {
		panic("suite has been frozen (CheckAll or Context was called)")
	}
}
