package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type MonoidInvariants[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]] struct{}

type MonoidElementInvariants[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]] struct{}

type AdditiveMonoidInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]] struct{}

type AdditiveMonoidElementInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]] struct{}

type MultiplicativeMonoidInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]] struct{}

type MultiplicativeMonoidELementInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]] struct{}

func (mi *MonoidInvariants[M, ME]) Identity(t *testing.T, monoid algebra.Monoid[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()
	// TODO:
}

func (mei *MonoidElementInvariants[M, ME]) IsIdentity(t *testing.T, monoid algebra.Monoid[M, ME], element algebra.MonoidElement[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()
	// TODO
}

func (ami *AdditiveMonoidInvariants[M, ME]) AdditiveIdentity(t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x algebra.AdditiveMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()
	//TODO: is n the number of times the operation applies to the element ?
	addIdentity := monoid.AdditiveIdentity()

	output1 := addIdentity.Add(addIdentity)
	require.Equal(t, addIdentity, output1,
		"identityElement + identityElement should be equal to identityElement")

	output2 := addIdentity.Add(x)
	require.Equal(t, x, output2,
		"identityElement + x should be equal to x")

	output3 := x.Add(addIdentity)
	require.Equal(t, x, output3,
		"x + identityElement should be equal to x")
}

func (amei *AdditiveMonoidElementInvariants[M, ME]) IsAdditiveIdentity(t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x, y algebra.AdditiveMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()
	//TODO: making sure y isn't an identity element
	isAdditiveIdentity := x.IsAdditiveIdentity()

	if isAdditiveIdentity {
		output1 := x.Add(x)
		require.Equal(t, x, output1,
			"identityElement + identityElement should be equal to identityElement")

		output2 := x.Add(y)
		require.Equal(t, y, output2,
			"x + identityElement should be equal to identityElement")

		output3 := y.Add(x)
		require.Equal(t, x, output3,
			"x + identityElement should be equal to x")
	} else {
		output1 := x.Add(x)
		require.NotEqual(t, x, output1)

		output2 := x.Add(y)
		require.NotEqual(t, y, output2)

		output3 := y.Add(x)
		require.Equal(t, x, output3)
	}
}

func (mmi *MultiplicativeMonoidInvariants[M, ME]) MultiplicativeIdentity(t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x algebra.MultiplicativeMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()

	t.Helper()
	//TODO: is n the number of times the operation applies to the element ?
	mulIdentity := monoid.MultiplicativeIdentity()

	output1 := mulIdentity.Mul(mulIdentity)
	require.Equal(t, mulIdentity, output1,
		"identityElement * identityElement should be equal to identityElement")

	output2 := mulIdentity.Mul(x)
	require.Equal(t, x, output2,
		"x * identityElement should be equal to x")

	output3 := x.Mul(mulIdentity)
	require.Equal(t, x, output3,
		"identityElement * x should be equal to x")
}

func (mmei *MultiplicativeMonoidELementInvariants[M, ME]) IsMultiplicativeIdentity(t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x, y algebra.MultiplicativeMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()
	//TODO: making sure y isn't an identity element
	isMulIdentity := x.IsMultiplicativeIdentity()

	if isMulIdentity {
		mulIdentity := monoid.MultiplicativeIdentity()

		output1 := x.Mul(x)
		require.Equal(t, mulIdentity, output1,
			"x * x should be equal to x")

		output2 := x.Mul(y)
		require.Equal(t, x, output2,
			"x * y should be equal to x")

		output3 := y.Mul(x)
		require.Equal(t, x, output3,
			"y * x should be equal to x")
	} else {
		output1 := x.Mul(x)
		require.NotEqual(t, x, output1)

		output2 := x.Mul(y)
		require.NotEqual(t, y, output2)

		output3 := y.Mul(x)
		require.Equal(t, x, output3)
	}
}

func CheckMonoidInvariant[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]](t *testing.T, monoid algebra.Monoid[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()

	mi := &MonoidInvariants[M, ME]{}
	mi.Identity(t, monoid, under)
}

func CheckMonoidElementInvariants[M algebra.Monoid[M, ME], ME algebra.MonoidElement[M, ME]](t *testing.T, monoid algebra.Monoid[M, ME], element algebra.MonoidElement[M, ME], under algebra.BinaryOperator[ME]) {
	t.Helper()

	mei := &MonoidElementInvariants[M, ME]{}
	mei.IsIdentity(t, monoid, element, under)
}

func CheckAdditiveMonoidInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]](t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x algebra.AdditiveMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()

	ami := &AdditiveMonoidInvariants[M, ME]{}
	ami.AdditiveIdentity(t, monoid, x, n)
}

func CheckAdditiveMonoidElementInvariants[M algebra.AdditiveMonoid[M, ME], ME algebra.AdditiveMonoidElement[M, ME]](t *testing.T, monoid algebra.AdditiveMonoid[M, ME], x, y algebra.AdditiveMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()

	amei := &AdditiveMonoidElementInvariants[M, ME]{}
	amei.IsAdditiveIdentity(t, monoid, x, y, n)
}

func CheckMultiplicativeMonoidInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]](t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x algebra.MultiplicativeMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()

	mmi := &MultiplicativeMonoidInvariants[M, ME]{}
	mmi.MultiplicativeIdentity(t, monoid, x, n)
}

func CheckMultiplicativeMonoidELementInvariants[M algebra.MultiplicativeMonoid[M, ME], ME algebra.MultiplicativeMonoidElement[M, ME]](t *testing.T, monoid algebra.MultiplicativeMonoid[M, ME], x, y algebra.MultiplicativeMonoidElement[M, ME], n *saferith.Nat) {
	t.Helper()

	mmei := &MultiplicativeMonoidELementInvariants[M, ME]{}
	mmei.IsMultiplicativeIdentity(t, monoid, x, y, n)
}
