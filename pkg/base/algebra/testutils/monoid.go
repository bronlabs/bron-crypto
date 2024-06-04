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

	CheckGroupoidInvariants[M, ME](t, monoid, elementGenerator)
	// Identity // TODO: operator method
	// IsIdentity // TODO: operator method
}

func CheckAdditiveMonoidInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)
	ami := &AdditiveMonoidInvariants[M, ME]{}
	t.Run("AdditiveIdentity", func(t *testing.T) {
		t.Parallel()
		ami.AdditiveIdentity(t, monoid, gen.Generate())
	})

	amei := &AdditiveMonoidElementInvariants[M, ME]{}
	t.Run("IsAdditiveIdentity", func(t *testing.T) {
		t.Parallel()
		amei.IsAdditiveIdentity(t, monoid, gen.Generate(), gen.Generate())
	})
}

func CheckMultiplicativeMonoidInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()
	gen := fu.NewSkewedObjectGenerator(elementGenerator, 5) // 5% chance of generating zero

	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)

	mmi := &MultiplicativeMonoidInvariants[M, ME]{}
	t.Run("MultiplicativeIdentity", func(t *testing.T) {
		t.Parallel()
		mmi.MultiplicativeIdentity(t, monoid, gen.Generate())
	})

	mmei := &MultiplicativeMonoidELementInvariants[M, ME]{}
	t.Run("IsMultiplicativeIdentity", func(t *testing.T) {
		t.Parallel()
		mmei.IsMultiplicativeIdentity(t, monoid, gen.Generate(), gen.Generate())
	})
}

func CheckCyclicMonoidInvariants[M algebra.CyclicMonoid[M, ME], ME algebra.CyclicMonoidElement[M, ME]](t *testing.T, monoid M, elementGenerator fu.ObjectGenerator[ME]) {
	t.Helper()
	CheckMonoidInvariant[M, ME](t, monoid, elementGenerator)
	CheckCyclicGroupoidInvariants[M, ME](t, monoid, elementGenerator)
}
