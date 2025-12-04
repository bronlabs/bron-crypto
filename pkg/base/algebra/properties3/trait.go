package properties3

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// Trait represents a single algebraic property that can be tested.
// Traits are composable - you can combine multiple traits to test
// complex algebraic structures.
type Trait[S any, E any] interface {
	// Name returns the trait name for test output.
	Name() string
	// Check runs the property test.
	Check(t *testing.T, ctx *Context[S, E])
}

// ClosureTrait verifies that an operation is closed (result is of the same type).
type ClosureTrait[S any, E any] struct {
	OpName string
	Op     func(a, b E) E
}

func (tr *ClosureTrait[S, E]) Name() string { return tr.OpName + "_Closure" }

func (tr *ClosureTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Draw(rt, "b")
			c := tr.Op(a, b)
			require.NotNil(t, c, "operation should return non-nil result")
		})
	})
}

// AssociativityTrait verifies (a op b) op c = a op (b op c).
type AssociativityTrait[S any, E algebra.Element[E]] struct {
	OpName string
	Op     func(a, b E) E
}

func (tr *AssociativityTrait[S, E]) Name() string { return tr.OpName + "_Associativity" }

func (tr *AssociativityTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Draw(rt, "b")
			c := ctx.Draw(rt, "c")
			left := tr.Op(tr.Op(a, b), c)
			right := tr.Op(a, tr.Op(b, c))
			require.True(t, left.Equal(right), "associativity failed: (a op b) op c != a op (b op c)")
		})
	})
}

// CommutativityTrait verifies a op b = b op a.
type CommutativityTrait[S any, E algebra.Element[E]] struct {
	OpName string
	Op     func(a, b E) E
}

func (tr *CommutativityTrait[S, E]) Name() string { return tr.OpName + "_Commutativity" }

func (tr *CommutativityTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Draw(rt, "b")
			left := tr.Op(a, b)
			right := tr.Op(b, a)
			require.True(t, left.Equal(right), "commutativity failed: a op b != b op a")
		})
	})
}

// IdentityTrait verifies identity op a = a and a op identity = a.
type IdentityTrait[S any, E algebra.Element[E]] struct {
	OpName   string
	Op       func(a, b E) E
	Identity func(s S) E
}

func (tr *IdentityTrait[S, E]) Name() string { return tr.OpName + "_Identity" }

func (tr *IdentityTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			identity := tr.Identity(ctx.Structure())

			// Left identity: identity op a = a
			left := tr.Op(identity, a)
			require.True(t, left.Equal(a), "left identity failed: identity op a != a")

			// Right identity: a op identity = a
			right := tr.Op(a, identity)
			require.True(t, right.Equal(a), "right identity failed: a op identity != a")
		})
	})
}

// InverseTrait verifies a op inv(a) = identity and inv(a) op a = identity.
type InverseTrait[S any, E algebra.Element[E]] struct {
	OpName   string
	Op       func(a, b E) E
	Inv      func(a E) E
	Identity func(s S) E
}

func (tr *InverseTrait[S, E]) Name() string { return tr.OpName + "_Inverse" }

func (tr *InverseTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			identity := tr.Identity(ctx.Structure())
			invA := tr.Inv(a)

			// Right inverse: a op inv(a) = identity
			right := tr.Op(a, invA)
			require.True(t, right.Equal(identity), "right inverse failed: a op inv(a) != identity")

			// Left inverse: inv(a) op a = identity
			left := tr.Op(invA, a)
			require.True(t, left.Equal(identity), "left inverse failed: inv(a) op a != identity")
		})
	})
}

// LeftDistributivityTrait verifies a * (b + c) = (a * b) + (a * c).
type LeftDistributivityTrait[S any, E algebra.Element[E]] struct {
	Add func(a, b E) E
	Mul func(a, b E) E
}

func (tr *LeftDistributivityTrait[S, E]) Name() string { return "Mul_LeftDistributesOver_Add" }

func (tr *LeftDistributivityTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Draw(rt, "b")
			c := ctx.Draw(rt, "c")

			// a * (b + c)
			left := tr.Mul(a, tr.Add(b, c))
			// (a * b) + (a * c)
			right := tr.Add(tr.Mul(a, b), tr.Mul(a, c))

			require.True(t, left.Equal(right), "left distributivity failed: a * (b + c) != (a * b) + (a * c)")
		})
	})
}

// RightDistributivityTrait verifies (a + b) * c = (a * c) + (b * c).
type RightDistributivityTrait[S any, E algebra.Element[E]] struct {
	Add func(a, b E) E
	Mul func(a, b E) E
}

func (tr *RightDistributivityTrait[S, E]) Name() string { return "Mul_RightDistributesOver_Add" }

func (tr *RightDistributivityTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			b := ctx.Draw(rt, "b")
			c := ctx.Draw(rt, "c")

			// (a + b) * c
			left := tr.Mul(tr.Add(a, b), c)
			// (a * c) + (b * c)
			right := tr.Add(tr.Mul(a, c), tr.Mul(b, c))

			require.True(t, left.Equal(right), "right distributivity failed: (a + b) * c != (a * c) + (b * c)")
		})
	})
}

// ZeroAnnihilationTrait verifies 0 * a = 0 and a * 0 = 0.
type ZeroAnnihilationTrait[S any, E algebra.Element[E]] struct {
	Mul  func(a, b E) E
	Zero func(s S) E
}

func (tr *ZeroAnnihilationTrait[S, E]) Name() string { return "Mul_ZeroAnnihilation" }

func (tr *ZeroAnnihilationTrait[S, E]) Check(t *testing.T, ctx *Context[S, E]) {
	t.Run(tr.Name(), func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			a := ctx.Draw(rt, "a")
			zero := tr.Zero(ctx.Structure())

			// 0 * a = 0
			left := tr.Mul(zero, a)
			require.True(t, left.Equal(zero), "left zero annihilation failed: 0 * a != 0")

			// a * 0 = 0
			right := tr.Mul(a, zero)
			require.True(t, right.Equal(zero), "right zero annihilation failed: a * 0 != 0")
		})
	})
}
