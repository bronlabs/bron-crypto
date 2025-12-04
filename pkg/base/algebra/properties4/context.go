package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"pgregory.net/rapid"
)

// Context provides the testing context for property checks.
// It holds the structure under test and provides convenient access methods.
type Context[S algebra.Structure[E], E algebra.Element[E]] struct {
	t         *testing.T
	structure *Structure[S, E]
}

// NewContext creates a new testing context.
func NewContext[S algebra.Structure[E], E algebra.Element[E]](
	t *testing.T,
	structure *Structure[S, E],
) *Context[S, E] {
	t.Helper()
	return &Context[S, E]{
		t:         t,
		structure: structure,
	}
}

// Draw generates a random element using the structure's generator.
func (c *Context[S, E]) Draw(rt *rapid.T, name string) E {
	return c.structure.Generator.Draw(rt, name)
}

// Generator returns the element generator.
func (c *Context[S, E]) Generator() *rapid.Generator[E] {
	return c.structure.Generator
}

// Structure returns the full structure.
func (c *Context[S, E]) Structure() *Structure[S, E] {
	return c.structure
}

// Carrier returns the algebraic structure (e.g., the ring, field, etc.).
func (c *Context[S, E]) Carrier() S {
	return c.structure.Carrier
}

// Add returns the addition operator, or nil if not defined.
func (c *Context[S, E]) Add() *BinaryOp[E] {
	return c.structure.Add
}

// Mul returns the multiplication operator, or nil if not defined.
func (c *Context[S, E]) Mul() *BinaryOp[E] {
	return c.structure.Mul
}

// Zero returns the additive identity.
// Panics if addition has no identity.
func (c *Context[S, E]) Zero() E {
	if c.structure.Add == nil || c.structure.Add.Identity == nil {
		panic("Zero called but addition has no identity")
	}
	return c.structure.Add.Identity()
}

// One returns the multiplicative identity.
// Panics if multiplication has no identity.
func (c *Context[S, E]) One() E {
	if c.structure.Mul == nil || c.structure.Mul.Identity == nil {
		panic("One called but multiplication has no identity")
	}
	return c.structure.Mul.Identity()
}

// HasZero returns true if the additive identity is defined.
func (c *Context[S, E]) HasZero() bool {
	return c.structure.Add != nil && c.structure.Add.HasIdentity()
}

// HasOne returns true if the multiplicative identity is defined.
func (c *Context[S, E]) HasOne() bool {
	return c.structure.Mul != nil && c.structure.Mul.HasIdentity()
}

// Neg returns the additive inverse of a.
// Panics if addition has no inverse.
func (c *Context[S, E]) Neg(a E) E {
	if c.structure.Add == nil || c.structure.Add.Inverse == nil {
		panic("Neg called but addition has no inverse")
	}
	return c.structure.Add.Inverse(a)
}

// Inv returns the multiplicative inverse of a.
// Panics if multiplication has no inverse.
func (c *Context[S, E]) Inv(a E) E {
	if c.structure.Mul == nil || c.structure.Mul.Inverse == nil {
		panic("Inv called but multiplication has no inverse")
	}
	return c.structure.Mul.Inverse(a)
}

// HasNeg returns true if additive inverse is defined.
func (c *Context[S, E]) HasNeg() bool {
	return c.structure.Add != nil && c.structure.Add.HasInverse()
}

// HasInv returns true if multiplicative inverse is defined.
func (c *Context[S, E]) HasInv() bool {
	return c.structure.Mul != nil && c.structure.Mul.HasInverse()
}
