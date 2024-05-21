package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type GroupElementInvariants[G algebra.Group[G, GE], GE algebra.GroupElement[G, GE]] struct{}

type SubGroupInvariants[G algebra.Group[G, GE], GE algebra.GroupElement[G, GE]] struct{}

type SubGroupElementInvariants[G algebra.Group[G, GE], GE algebra.GroupElement[G, GE]] struct{}

type AdditiveGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]] struct{}

func (gei *GroupElementInvariants[G, GE]) Inverse(t *testing.T, group algebra.Group[G, GE], random algebra.GroupElement[G, GE], under algebra.BinaryOperator[GE], n *saferith.Nat) {
	t.Helper()

	identityElement, err := group.Identity(under)
	require.NoError(t, err)
	inverseOfIdentity, err1 := identityElement.Inverse(under)
	require.Equal(t, inverseOfIdentity, identityElement, "Inverse of identity element is itself")

	inverse, err := random.Inverse(under)
	require.NoError(t, err)
	inverseOfInverse, err1 := inverse.Inverse(under)
	require.NoError(t, err1)
	require.Equal(t, random, inverseOfInverse, "Inverse of inverse of X should be equal to X")

	output, err := random.ApplyOp(under, inverse, n.SetUint64(uint64(1)))
	require.Equal(t, identityElement, output, "Any element o inverse of the element should be equal to the identity element")
}
func (gei *GroupElementInvariants[G, GE]) IsInverse(t *testing.T, group algebra.Group[G, GE], random algebra.GroupElement[G, GE], under algebra.BinaryOperator[GE], n *saferith.Nat) {
	t.Helper()

	identityElement, err0 := group.Identity(under)
	require.NoError(t, err0)
	IsInverse, err1 := identityElement.IsInverse(identityElement, under)
	require.NoError(t, err1)
	require.True(t, IsInverse, "identity element is Inverse of itself")

	inverseOfRandom, err2 := random.Inverse(under)
	require.NoError(t, err2)
	IsInverseOfRandom, err3 := random.IsInverse(inverseOfRandom, under)
	require.NoError(t, err3)
	require.True(t, IsInverseOfRandom, "Inverse of inverse of X should be equal to X")

	output, err4 := random.ApplyOp(under, inverseOfRandom, n.SetUint64(uint64(1)))
	require.NoError(t, err4)
	IsInverse, err5 := output.IsInverse(output, under)
	require.NoError(t, err5)
	require.True(t, IsInverse, "identity element is Inverse of itself")
}
func (gei *GroupElementInvariants[G, GE]) IsTorsionElement(t *testing.T, random algebra.GroupElement[G, GE], order *saferith.Modulus, under algebra.BinaryOperator[GE], n *saferith.Nat) {
	t.Helper()
	// TODO: need help with the syntax
	// IsIdentity, err := random.ApplyOp(under, order.Nat())
}

func (sgi *SubGroupInvariants[G, GE]) CoFactor(t *testing.T, group, subgroup algebra.SubGroup[G, GE]) {
	t.Helper()
	// TODO: need help with the syntax
	// expected := subgroup.Order() / group.Order()
	// actual := subgroup.cofactor()
	// require.Equal(t, expected, actual)
}

func (sgi *SubGroupInvariants[G, GE]) SuperGroupOrder(t *testing.T, group algebra.SubGroup[G, GE]) {
	t.Helper()
	// TODO
}

func (sgi *SubGroupElementInvariants[G, GE]) IsSmallOrder(t *testing.T, group algebra.SubGroup[G, GE], element algebra.SubGroupElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()
	// TODO: need help
	// expoected: el.ApplyOP(under, el, n= group.cofactor()) == group.identity()
	// actial: el.isSmallOrder()
	expected, err := element.ApplyOp(under, element, group.CoFactor())
	require.NoError(t, err)
	identityElement, err0 := group.Identity(under)
	require.NoError(t, err0)
	if expected.Equal(identityElement) {
		require.True(t, element.IsSmallOrder())
	} else {
		require.False(t, element.IsSmallOrder())
	}
}

func (sgi *SubGroupElementInvariants[G, GE]) ClearCofactor(t *testing.T, group algebra.SubGroup[G, GE], element algebra.SubGroupElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()
	// TODO: need help
	// expected: el.ApplyOP(under, el, n= group.cofactor())
	// Actual el.clearCofactor()
	expected, err := element.ApplyOp(under, element, group.CoFactor())
	require.NoError(t, err)
	require.Equal(t, expected, element.ClearCofactor())
}

func (agi *AdditiveGroupInvariants[G, GE]) AdditiveInverse(t *testing.T, group algebra.AdditiveGroup[G, GE], element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()
	// TODO: Will add more invariants after the Inverse tests are implemented
}
func (agi *AdditiveGroupInvariants[G, GE]) IsAdditiveInverse(t *testing.T) {
	t.Helper()
	// TODO: Is it OK that I call the isInverse test and pass it the Add operator ?

}
func (agi *AdditiveGroupInvariants[G, GE]) IsTorsionElementUnderAddition(t *testing.T) {
	t.Helper()
	// TODO: Will add more invariants after the IsTorsionElement tests are implemented

}
func (agi *AdditiveGroupInvariants[G, GE]) Neg(t *testing.T, element algebra.AdditiveGroupElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()

	negElement := element.Neg()
	inverse, err := negElement.Inverse(under)
	require.NoError(t, err)
	require.Equal(t, inverse, negElement,
		"inverse of X should be the same as negative of X")
	require.Equal(t, negElement.Neg(), negElement,
		"inverse of X should be the same as negative of X")
}
func (agi *AdditiveGroupInvariants[G, GE]) Sub(t *testing.T, group algebra.AdditiveGroup[G, GE], x algebra.AdditiveGroupElement[G, GE], ys ...algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()
	// TODO
	result := group.Add(x)
	for index := len(ys) - 1; index >= 0; index-- {
		result = group.Add(result, ys[index].Neg())
	}
	require.Equal(t, result, group.Sub(x, ys...),
		"Should get the same result for subtracting ys elements one by one from x")
}
func (agi *AdditiveGroupInvariants[G, GE]) ApplySub(t *testing.T) {
	t.Helper()

}

func (agi *AdditiveGroupInvariants[G, GE]) IsIdentity(t *testing.T,
	group algebra.AdditiveGroup[G, GE],
	element algebra.AdditiveGroupElement[G, GE],
) {
	t.Helper()
	require.NotNil(t, element)
	isIdentity := element.IsAdditiveIdentity()
	identity := group.AdditiveIdentity()
	equalToIdentity := element.Equal(identity)
	require.Equal(t, equalToIdentity, isIdentity,
		"IsIdentity must match with equality to group's Identity element.")
}

func (agi *AdditiveGroupInvariants[G, GE]) Add(t *testing.T,
	group algebra.AdditiveGroup[G, GE],
	el1 algebra.AdditiveGroupElement[G, GE],
	el2 algebra.AdditiveGroupElement[G, GE],
) {
	t.Helper()
	require.NotNil(t, el1)
	identity := group.AdditiveIdentity()
	require.True(t, el1.Equal(el1.Add(identity)),
		"Addition with identity must be equal to the element itself.")
	require.True(t, el2.Equal(el2.Add(identity)),
		"Addition with identity must be equal to the element itself.")
	sum := el1.Add(el2)
	require.True(t, sum.Equal(group.Add(el1, el2)),
		"Addition must be consistent with group's Add method.")
	require.True(t, group.Contains(sum),
		"Addition must result in an element that is in the group.")
}

// TODO: Write invariants for all the group methods

// TODO: Write invariants for the underlying algebraic structures (monoid, groupoid) and compose them below.

func CheckGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	invs := &AdditiveGroupInvariants[G, GE]{}
	t.Run("IsIdentity", func(t *testing.T) {
		t.Parallel()
		gen := elementGenerator.Clone()
		isEmpty := gen.Prng().Bool()
		element := gen.Empty()
		if !isEmpty {
			element = gen.GenerateNonZero()
		}
		invs.IsIdentity(t, group, element)
	})
	t.Run("Add", func(t *testing.T) {
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
		invs.Add(t, group, el1, el2)
	})
}
