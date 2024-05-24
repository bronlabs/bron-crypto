package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type MonoidInvariants[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]] struct{}

type MonoidElementInvariants[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]] struct{}

type AdditiveMonoidInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]] struct{}

type AdditiveMonoidElementInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]] struct{}

type MultiplicativeMonoidInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]] struct{}

type MultiplicativeMonoidELementInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]] struct{}

type CyclicMonoidInvariants[M algebra.CyclicMonoid[M, ME], ME algebra.CyclicMonoidElement[M, ME]] struct{}

type CyclicMonoidElementInvariants[M algebra.CyclicMonoid[M, ME], ME algebra.CyclicMonoidElement[M, ME]] struct{}

func (mi *MonoidInvariants[M, ME]) Identity(t *testing.T, monoid algebra.Monoid[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()
	// TODO:
}

func (mei *MonoidElementInvariants[M, ME]) IsIdentity(t *testing.T, monoid algebra.Monoid[M, ME], element algebra.MonoidElement[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()
	// TODO
}

func (ami *AdditiveMonoidInvariants[M, ME]) AdditiveIdentity(t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x algebra.AdditiveMonoidElement[M, ME]) {
	t.Helper()

	addIdentity := monoid.AdditiveIdentity()

	output1 := addIdentity.Add(addIdentity)
	require.True(t, addIdentity.Equal(output1),
		"identityElement + identityElement should be equal to identityElement")

	output2 := addIdentity.Add(x)
	require.True(t, x.Equal(output2),
		"identityElement + x should be equal to x")

	output3 := x.Add(addIdentity)
	require.True(t, x.Equal(output3),
		"x + identityElement should be equal to x")
}

func (amei *AdditiveMonoidElementInvariants[M, ME]) IsAdditiveIdentity(t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x, y algebra.AdditiveMonoidElement[M, ME]) {
	t.Helper()

	isAdditiveIdentity := x.IsAdditiveIdentity()

	if isAdditiveIdentity {
		output1 := x.Add(x)
		require.True(t, x.Equal(output1),
			"identityElement + identityElement should be equal to identityElement")

		output2 := x.Add(y)
		require.True(t, y.Equal(output2),
			"x + identityElement should be equal to identityElement")

		output3 := y.Add(x)
		require.True(t, x.Equal(output3),
			"x + identityElement should be equal to x")
	} else {
		output1 := x.Add(x)
		require.False(t, x.Equal(output1))

		output2 := x.Add(y)
		require.False(t, y.Equal(output2))

		output3 := y.Add(x)
		require.False(t, x.Equal(output3))
	}
}

func (mmi *MultiplicativeMonoidInvariants[M, ME]) MultiplicativeIdentity(t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x algebra.MultiplicativeMonoidElement[M, ME]) {

	t.Helper()

	mulIdentity := monoid.MultiplicativeIdentity()

	output1 := mulIdentity.Mul(mulIdentity)
	require.True(t, mulIdentity.Equal(output1),
		"identityElement * identityElement should be equal to identityElement")

	output2 := mulIdentity.Mul(x)
	require.True(t, x.Equal(output2),
		"x * identityElement should be equal to x")

	output3 := x.Mul(mulIdentity)
	require.True(t, x.Equal(output3),
		"identityElement * x should be equal to x")
}

func (mmei *MultiplicativeMonoidELementInvariants[M, ME]) IsMultiplicativeIdentity(t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x, y algebra.MultiplicativeMonoidElement[M, ME]) {
	t.Helper()

	isMulIdentity := x.IsMultiplicativeIdentity()

	if isMulIdentity {

		output1 := x.Mul(x)
		require.True(t, x.Equal(output1),
			"x * x should be equal to x")

		output2 := x.Mul(y)
		require.True(t, x.Equal(output2),
			"x * y should be equal to x")

		output3 := y.Mul(x)
		require.True(t, x.Equal(output3),
			"y * x should be equal to x")
	} else {
		output1 := x.Mul(x)
		require.False(t, x.Equal(output1))

		output2 := x.Mul(y)
		require.False(t, x.Equal(output2))

		output3 := y.Mul(x)
		require.False(t, x.Equal(output3))
	}
}

func CheckMonoidInvariant[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()

	CheckGroupoidInvariant[M, ME](t, monoid, elementGenerator)
	// mi := &MonoidInvariants[M, ME]{}
	// t.Run("Identity", func(t *testing.T) {
	// 	t.Parallel()
	// 	for _, under := range monoid.Operators() {
	// 		mi.Identity(t, monoid, under)
	// 	}
	// })

	// mei := &MonoidElementInvariants[M, ME]{}
	// t.Run("IsIdentity", func(t *testing.T) {
	// 	gen1 := elementGenerator.Clone()
	// 	isEmpty1 := gen1.Prng().IntRange(0, 16)
	// 	element := gen1.Empty()
	// 	if isEmpty1 != 0 {
	// 		element = gen1.GenerateNonZero()
	// 	}
	// 	for _, under := range monoid.Operators() {
	// 		mei.IsIdentity(t, monoid, element, under)
	// 	}
	// })
}

func CheckAdditiveMonoidInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()

	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)
	ami := &AdditiveMonoidInvariants[M, ME]{}
	t.Run("AdditiveIdentity", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		ami.AdditiveIdentity(t, monoid, el1)
	})

	amei := &AdditiveMonoidElementInvariants[M, ME]{}
	t.Run("IsAdditiveIdentity", func(t *testing.T) {
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
		amei.IsAdditiveIdentity(t, monoid, el1, el2)
	})
}

func CheckMultiplicativeMonoidInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()

	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)

	mmi := &MultiplicativeMonoidInvariants[M, ME]{}
	t.Run("MultiplicativeIdentity", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		mmi.MultiplicativeIdentity(t, monoid, el1)
	})

	mmei := &MultiplicativeMonoidELementInvariants[M, ME]{}
	t.Run("IsMultiplicativeIdentity", func(t *testing.T) {
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
		mmei.IsMultiplicativeIdentity(t, monoid, el1, el2)
	})
}

func CheckCyclicMonoidInvariants[M algebra.CyclicMonoid[M, ME], ME algebra.CyclicMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()
	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)
	CheckGroupoidInvariant[M, ME](t, monoid, elementGenerator)
}
