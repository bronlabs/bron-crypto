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

	require.True(t, operator(element1, element2).Equal(operator(element2, element1)), "a * b should be equal to b * a")
}

func (coi *AssociativeOperatorInvariants[S, E]) IsAssociative(t *testing.T, operator func(E, E) E, element1, element2, element3 E) {
	t.Helper()
	output1 := operator(operator(element1, element2), element3)
	output2 := operator(element1, operator(element2, element3))

	require.True(t, output1.Equal(output2),
		"(a * b) * c should be equal to a * (b * c)")
}

func CheckAddCommutativeOperatorInvariants[S algebra.AdditiveMonoid[S, E], E algebra.AdditiveMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	coi := &CommutativeOperatorInvariants[S, E]{}
	t.Run("IsCommutative", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen2.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		el2 := gen2.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		if isEmpty2 != 0 {
			el2 = gen2.GenerateNonZero()
		}
		coi.IsCommutative(t, monoid.Addition().Add, el1, el2)
	})
}
func CheckMulCommutativeOperatorInvariants[S algebra.MultiplicativeMonoid[S, E], E algebra.MultiplicativeMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()

	coi := &CommutativeOperatorInvariants[S, E]{}
	t.Run("IsCommutative", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen2.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		el2 := gen2.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		if isEmpty2 != 0 {
			el2 = gen2.GenerateNonZero()
		}
		coi.IsCommutative(t, monoid.Multiplication().Multiply, el1, el2)
	})
}

func CheckaMulAssociativeOperatorInvariants[S algebra.MultiplicativeMonoid[S, E], E algebra.MultiplicativeMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	aoi := &AssociativeOperatorInvariants[S, E]{}
	t.Run("IsAssociative", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		gen3 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen2.Prng().IntRange(0, 16)
		isEmpty3 := gen3.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		el2 := gen2.Empty()
		el3 := gen3.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		if isEmpty2 != 0 {
			el2 = gen2.GenerateNonZero()
		}
		if isEmpty3 != 0 {
			el3 = gen3.GenerateNonZero()
		}
		aoi.IsAssociative(t, monoid.Multiplication().Multiply, el1, el2, el3)
	})
}
func CheckaAddAssociativeOperatorInvariants[S algebra.AdditiveMonoid[S, E], E algebra.AdditiveMonoidElement[S, E]](t *testing.T, monoid S, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	aoi := &AssociativeOperatorInvariants[S, E]{}
	t.Run("IsAssociative", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		gen3 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen2.Prng().IntRange(0, 16)
		isEmpty3 := gen3.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		el2 := gen2.Empty()
		el3 := gen3.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		if isEmpty2 != 0 {
			el2 = gen2.GenerateNonZero()
		}
		if isEmpty3 != 0 {
			el3 = gen3.GenerateNonZero()
		}
		aoi.IsAssociative(t, monoid.Addition().Add, el1, el2, el3)
	})
}
