package properties3

import (
	"testing"

	"pgregory.net/rapid"
)

// Context holds everything needed for property testing.
// It provides a clean interface for accessing the structure under test
// and drawing random elements from the generator.
type Context[S any, E any] struct {
	t         *testing.T
	structure S
	generator *rapid.Generator[E]
}

// NewContext creates a new testing context.
func NewContext[S any, E any](t *testing.T, s S, g *rapid.Generator[E]) *Context[S, E] {
	t.Helper()
	return &Context[S, E]{
		t:         t,
		structure: s,
		generator: g,
	}
}

// T returns the testing.T instance.
func (c *Context[S, E]) T() *testing.T {
	return c.t
}

// Structure returns the algebraic structure being tested.
func (c *Context[S, E]) Structure() S {
	return c.structure
}

// Generator returns the random element generator.
func (c *Context[S, E]) Generator() *rapid.Generator[E] {
	return c.generator
}

// Draw draws a random element from the generator with the given name.
func (c *Context[S, E]) Draw(rt *rapid.T, name string) E {
	return c.generator.Draw(rt, name)
}
