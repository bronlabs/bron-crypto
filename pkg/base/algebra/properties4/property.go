package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// Property represents a single testable algebraic property.
// Properties are composable and can be grouped into theories.
type Property[S algebra.Structure[E], E algebra.Element[E]] struct {
	// Name identifies the property for test output.
	Name string
	// Check runs the property test.
	Check func(t *testing.T, ctx *Context[S, E])
}

// Run executes the property test as a subtest.
func (p *Property[S, E]) Run(t *testing.T, ctx *Context[S, E]) {
	t.Helper()
	t.Run(p.Name, func(t *testing.T) {
		t.Parallel()
		p.Check(t, ctx)
	})
}

// Theory is a collection of properties that define an algebraic structure.
type Theory[S algebra.Structure[E], E algebra.Element[E]] []Property[S, E]

// Append adds properties to the theory.
func (th Theory[S, E]) Append(props ...Property[S, E]) Theory[S, E] {
	return append(th, props...)
}

// AppendTheory adds all properties from another theory.
func (th Theory[S, E]) AppendTheory(other Theory[S, E]) Theory[S, E] {
	return append(th, other...)
}
