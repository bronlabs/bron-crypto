package properties3

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Suite is the main entry point for property-based testing.
// It holds a context and a list of traits to check.
type Suite[S any, E any] struct {
	ctx    *Context[S, E]
	traits []Trait[S, E]
}

// New creates a new property test suite.
func New[S any, E any](t *testing.T, s S, g *rapid.Generator[E]) *Suite[S, E] {
	t.Helper()
	require.NotNil(t, g, "generator must not be nil")
	return &Suite[S, E]{
		ctx: NewContext(t, s, g),
	}
}

// With adds traits to the suite. Returns the suite for chaining.
func (s *Suite[S, E]) With(traits ...Trait[S, E]) *Suite[S, E] {
	s.traits = append(s.traits, traits...)
	return s
}

// CheckAll runs all property tests in the suite.
func (s *Suite[S, E]) CheckAll(t *testing.T) {
	t.Helper()
	for _, trait := range s.traits {
		trait.Check(t, s.ctx)
	}
}

// Context returns the testing context for use in custom tests.
func (s *Suite[S, E]) Context() *Context[S, E] {
	return s.ctx
}

// Generator returns the element generator for convenience.
func (s *Suite[S, E]) Generator() *rapid.Generator[E] {
	return s.ctx.Generator()
}

// Structure returns the algebraic structure for convenience.
func (s *Suite[S, E]) Structure() S {
	return s.ctx.Structure()
}
