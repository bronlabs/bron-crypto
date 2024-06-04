package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type CommutativeOperatorInvariants[S algebra.Monoid[S, E], E algebra.MonoidElement[S, E]] struct{}

type AssociativeOperatorInvariants[S algebra.Monoid[S, E], E algebra.MonoidElement[S, E]] struct{}

func (coi *CommutativeOperatorInvariants[S, E]) IsCommutative(t *testing.T, operator func(E, E) E, element1, element2 E) {
	t.Helper()
	output1 := operator(element1, element2)
	output2 := operator(element2, element1)
	require.True(t, output1.Equal(output2), "a * b should be equal to b * a")
}

func (aoi *AssociativeOperatorInvariants[S, E]) IsAssociative(t *testing.T, operator func(E, E) E, element1, element2, element3 E) {
	t.Helper()
	output1 := operator(operator(element1, element2), element3)
	output2 := operator(element1, operator(element2, element3))

	require.True(t, output1.Equal(output2),
		"(a * b) * c should be equal to a * (b * c)")
}

func CheckAddCommutativeOperatorInvariants[S algebra.AdditiveMonoid[S, E], E algebra.AdditiveMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	t.Helper()

	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	coi := &CommutativeOperatorInvariants[S, E]{}
	t.Run("IsCommutative", func(t *testing.T) {
		t.Parallel()
		coi.IsCommutative(t, monoid.Addition().Add, gen.Generate(), gen.Generate())
	})
}
func CheckMulCommutativeOperatorInvariants[S algebra.MultiplicativeMonoid[S, E], E algebra.MultiplicativeMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	coi := &CommutativeOperatorInvariants[S, E]{}
	t.Run("IsCommutative", func(t *testing.T) {
		t.Parallel()
		coi.IsCommutative(t, monoid.Multiplication().Multiply, gen.Generate(), gen.Generate())
	})
}

func CheckaMulAssociativeOperatorInvariants[S algebra.MultiplicativeMonoid[S, E], E algebra.MultiplicativeMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, elementGenerator)
	require.NotNil(t, monoid)
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	aoi := &AssociativeOperatorInvariants[S, E]{}
	t.Run("IsAssociative", func(t *testing.T) {
		t.Parallel()
		aoi.IsAssociative(t, monoid.Multiplication().Multiply, gen.Generate(), gen.Generate(), gen.Generate())
	})
}
func CheckaAddAssociativeOperatorInvariants[S algebra.AdditiveMonoid[S, E], E algebra.AdditiveMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, elementGenerator)
	require.NotNil(t, monoid)
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	aoi := &AssociativeOperatorInvariants[S, E]{}
	t.Run("IsAssociative", func(t *testing.T) {
		t.Parallel()
		aoi.IsAssociative(t, monoid.Addition().Add, gen.Generate(), gen.Generate(), gen.Generate())
	})
}
