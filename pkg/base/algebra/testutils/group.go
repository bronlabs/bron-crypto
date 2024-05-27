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

type AdditiveGroupElementInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]] struct{}

type MultiplicativeGroupInvariants[G algebra.MultiplicativeGroup[G, GE], GE algebra.MultiplicativeGroupElement[G, GE]] struct{}

type MultiplicativeGroupElementInvariants[G algebra.MultiplicativeGroup[G, GE], GE algebra.MultiplicativeGroupElement[G, GE]] struct{}

type CyclicGroupInvariants[G algebra.CyclicGroup[G, GE], GE algebra.CyclicGroupElement[G, GE]] struct{}

func (gei *GroupElementInvariants[G, GE]) Inverse(t *testing.T, group algebra.Group[G, GE], random algebra.GroupElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()

	identityElement, err := group.Identity(under)
	require.NoError(t, err)
	inverseOfIdentity, err1 := identityElement.Inverse(under)
	require.True(t, inverseOfIdentity.Equal(identityElement), "Inverse of identity element is itself")

	inverse, err := random.Inverse(under)
	require.NoError(t, err)
	inverseOfInverse, err1 := inverse.Inverse(under)
	require.NoError(t, err1)
	require.True(t, random.Equal(inverseOfInverse), inverseOfInverse, "Inverse of inverse of X should be equal to X")

	n := new(saferith.Nat).SetUint64(1)
	output, err := random.ApplyOp(under, inverse, n)
	require.True(t, identityElement.Equal(output), "Any element o inverse of the element should be equal to the identity element")
}
func (gei *GroupElementInvariants[G, GE]) IsInverse(t *testing.T, group algebra.Group[G, GE], random algebra.GroupElement[G, GE], under algebra.BinaryOperator[GE]) {
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

	n := new(saferith.Nat).SetUint64(1)
	output, err4 := random.ApplyOp(under, inverseOfRandom, n)
	require.NoError(t, err4)
	IsInverse, err5 := output.IsInverse(output, under)
	require.NoError(t, err5)
	require.True(t, IsInverse, "identity element is Inverse of itself")
}
func (gei *GroupElementInvariants[G, GE]) IsTorsionElement(t *testing.T, group algebra.Group[G, GE], random algebra.GroupElement[G, GE], order *saferith.Modulus, under algebra.BinaryOperator[GE]) {
	t.Helper()
	actual, err0 := random.IsTorsionElement(group.Order(), under)
	require.NoError(t, err0)
	expected, err1 := random.ApplyOp(under, random, group.Order().Nat())
	require.NoError(t, err1)
	expected1, err2 := expected.IsIdentity(under)
	require.NoError(t, err2)
	require.Equal(t, expected1, actual)
}

func (sgi *SubGroupInvariants[G, GE]) CoFactor(t *testing.T, group, subgroup algebra.SubGroup[G, GE]) {
	t.Helper()
	//TODO: Please check if implementation is correct
	// expected := group.Order()
	// var actual *saferith.Nat
	// output := actual.Mul(subgroup.CoFactor(), subgroup.Order().Nat(), -1)
	// require.Equal(t, expected, output)
}

func (sgi *SubGroupInvariants[G, GE]) SuperGroupOrder(t *testing.T, group algebra.SubGroup[G, GE]) {
	t.Helper()
	// TODO: how Should I call parent?
}

func (sgi *SubGroupElementInvariants[G, GE]) IsSmallOrder(t *testing.T, group algebra.SubGroup[G, GE], element algebra.SubGroupElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()

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

	expected, err := element.ApplyOp(under, element, group.CoFactor())
	require.NoError(t, err)
	require.True(t, expected.Equal(element.ClearCofactor()))
}

func (agi *AdditiveGroupElementInvariants[G, GE]) AdditiveInverse(t *testing.T, group algebra.AdditiveGroup[G, GE], element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	identityElement := group.AdditiveIdentity()
	inverseOfIdentity := identityElement.AdditiveInverse()
	require.True(t, inverseOfIdentity.Equal(identityElement), "Inverse of identity element is iteself")

	inverse := element.AdditiveInverse()
	inverseOfInverse := inverse.AdditiveInverse()
	require.True(t, element.Equal(inverseOfInverse), "Inverse of inverse of X should be equal to X")

	n := new(saferith.Nat).SetUint64(1)
	output := element.ApplyAdd(inverse, n)
	require.True(t, identityElement.Equal(output), "Any element o inverse of the element should be equal to the identity element")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) IsAdditiveInverse(t *testing.T, group algebra.AdditiveGroup[G, GE], element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	identityElement := group.AdditiveIdentity()
	inverseOfIdentity := identityElement.IsAdditiveInverse(identityElement)
	require.True(t, inverseOfIdentity, "Inverse of identity element is itself")

	inverseOfElement := element.AdditiveInverse()
	IsInverseOfElement := element.IsAdditiveInverse(inverseOfElement)
	require.True(t, IsInverseOfElement, "Inverse of inverse of X should be equal to X")

	n := new(saferith.Nat).SetUint64(1)
	output := element.ApplyAdd(inverseOfElement, n)
	IsInverse := output.IsAdditiveIdentity()
	require.True(t, IsInverse, "identity element is Inverse of itself")

}
func (agi *AdditiveGroupElementInvariants[G, GE]) IsTorsionElementUnderAddition(t *testing.T, random algebra.AdditiveGroupElement[G, GE], group algebra.AdditiveGroup[G, GE]) {
	t.Helper()

	actual := random.IsTorsionElementUnderAddition(group.Order())

	OrderMinusOne := new(saferith.Nat).Sub(group.Order().Nat(), new(saferith.Nat).SetUint64(1), -1)
	expected := random.ApplyAdd(random, OrderMinusOne).IsAdditiveIdentity() // TODO: Should be group.order() -1

	require.Equal(t, expected, actual)
}
func (agi *AdditiveGroupElementInvariants[G, GE]) Neg(t *testing.T, element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	negElement := element.Neg()
	inverse := element.AdditiveInverse()
	require.True(t, inverse.Equal(negElement),
		"inverse of X should be the same as (-X)")
	require.True(t, element.Equal(inverse.Neg()),
		"-(-X) should be the same as negative of X")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) Sub(t *testing.T, groupoid algebra.AdditiveGroup[G, GE], x, y algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	actual := x.Sub(y)
	require.True(t, actual.Equal(groupoid.Sub(x, y)),
		"Should get the same result for adding ys elements one by one to x")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) ApplySub(t *testing.T, x algebra.AdditiveGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	actual := x.ApplySub(x, n)
	result := x

	for i := 0; int64(i) < n.Big().Int64(); i++ {
		result = result.Add(x.Neg())
	}

	require.True(t, result.Equal(actual))
}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) MultiplicativeInverse(t *testing.T, group algebra.MultiplicativeGroup[G, GE], element algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()

	identityElement := group.MultiplicativeIdentity()
	inverseOfIdentity, err := identityElement.MultiplicativeInverse()
	require.NoError(t, err)
	require.True(t, inverseOfIdentity.Equal(identityElement), "Inverse of identity element is itself")

	inverse, err1 := element.MultiplicativeInverse()
	require.NoError(t, err1)
	inverseOfInverse, err2 := inverse.MultiplicativeInverse()
	require.NoError(t, err2)
	require.True(t, element.Equal(inverseOfInverse), "Inverse of inverse of X should be equal to X")

	n := new(saferith.Nat).SetUint64(1)
	output := element.ApplyMul(inverse, n)
	require.True(t, identityElement.Equal(output), "Any element o inverse of the element should be equal to the identity element")
}

func (mgi *MultiplicativeGroupInvariants[G, GE]) Div(t *testing.T, group algebra.MultiplicativeGroup[G, GE], x algebra.MultiplicativeGroupElement[G, GE], ys ...algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()

	result := group.Mul(x)
	for index := len(ys) - 1; index >= 0; index-- {
		temp, err := ys[index].MultiplicativeInverse()
		require.NoError(t, err)
		result = group.Mul(result, temp)
	}
	output, err := group.Div(x, ys...)
	require.NoError(t, err)
	require.True(t, result.Equal(output),
		"Should get the same result for Multiplying inverse of ys elements by x")
}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) IsMultiplicativeInverse(t *testing.T, group algebra.MultiplicativeGroup[G, GE], element algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	identityElement := group.MultiplicativeIdentity()
	inverseOfIdentity := identityElement.IsMultiplicativeInverse(identityElement)
	require.True(t, inverseOfIdentity, "Inverse of identity element is itself")

	inverseOfRandom := group.MultiplicativeIdentity()
	IsInverseOfRandom := element.IsMultiplicativeInverse(inverseOfRandom)
	require.True(t, IsInverseOfRandom, "Inverse of inverse of X should be equal to X")

	output := element.ApplyMul(inverseOfRandom, n.SetUint64(uint64(1)))
	IsInverse := output.IsMultiplicativeInverse(output)
	require.True(t, IsInverse, "identity element is Inverse of itself")
}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) IsTorsionElementUnderMultiplication(t *testing.T, group algebra.MultiplicativeGroup[G, GE], element algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()
	actual := element.IsTorsionElementUnderMultiplication(group.Order())
	expected := element.ApplyMul(element, group.Order().Nat()).IsMultiplicativeIdentity()
	require.Equal(t, expected, actual)
}
func (mgei *MultiplicativeGroupElementInvariants[G, GE]) Div(t *testing.T, group algebra.MultiplicativeGroup[G, GE], x, y algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()

	output, err := x.Div(y)
	require.NoError(t, err)
	yInverse, err := y.MultiplicativeInverse()
	require.NoError(t, err)
	expected := x.Mul(yInverse)
	require.True(t, expected.Equal(output))

}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) ApplyDiv(t *testing.T, group algebra.MultiplicativeGroup[G, GE], x, y algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	output, err := x.ApplyDiv(y, n)
	require.NoError(t, err)

	expected := x
	for i := 0; int64(i) < n.Big().Int64(); i++ {
		expected, err = x.Div(y)
		require.NoError(t, err)
	}

	require.True(t, expected.Equal(output))
}
func (mgei *CyclicGroupInvariants[G, GE]) DLog(t *testing.T, group algebra.CyclicGroup[G, GE]) {
	t.Helper()
	// TODO: dependent on Operator
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

func CheckGroupInvariants[G algebra.Group[G, GE], GE algebra.GroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckMonoidInvariant[G, GE](t, group, elementGenerator)

	// Dependant on Operators
	// Inverse
	// IsInverse
	// IsTorsionELement
}

func CheckSubGroupInvariants[G algebra.SubGroup[G, GE], GE algebra.SubGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	// TODO: Tests are not implemented.
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckGroupInvariants[G, GE](t, group, elementGenerator)
	sgi := &SubGroupInvariants[G, GE]{}
	t.Run("SuperGroupOrder", func(t *testing.T) {
		t.Parallel()
		sgi.SuperGroupOrder(t, group)
	})

	// sgei := &SubGroupElementInvariants[G, GE]{}
	// Dependent on operators
	// IsSamallOrder
	// ClearCoFactor
}
func CheckSubGroupConstant[G algebra.SubGroup[G, GE], GE algebra.SubGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckGroupInvariants[G, GE](t, group, elementGenerator)
	sgi := &SubGroupInvariants[G, GE]{}
	sgi.CoFactor(t, group, group)
}
func CheckAdditiveGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckAdditiveMonoidInvariants[G, GE](t, group, elementGenerator)
	CheckGroupInvariants[G, GE](t, group, elementGenerator)
	agi := &AdditiveGroupElementInvariants[G, GE]{}
	t.Run("Sub", func(t *testing.T) {
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
		agi.Sub(t, group, el1, el2)
	})

	agei := &AdditiveGroupElementInvariants[G, GE]{}
	t.Run("AdditivInverse", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		agei.AdditiveInverse(t, group, element)
	})
	t.Run("IsAdditiveInverse", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		agei.IsAdditiveInverse(t, group, element)
	})
	t.Run("IsTorsionElementUnderAddition", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		agei.IsTorsionElementUnderAddition(t, element, group)
	})
	t.Run("Neg", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		agei.Neg(t, element)
	})
	t.Run("Sub", func(t *testing.T) {
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
		agei.Sub(t, group, el1, el2)
	})
	t.Run("ApplySub", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}

		prng := fu.NewPrng().IntRange(0, 20)
		n := new(saferith.Nat).SetUint64(uint64(prng))
		agei.ApplySub(t, el1, n)
	})
}

func CheckMultiplicativeGroupInvariants[G algebra.MultiplicativeGroup[G, GE], GE algebra.MultiplicativeGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckMultiplicativeMonoidInvariants[G, GE](t, group, elementGenerator)
	CheckGroupInvariants[G, GE](t, group, elementGenerator)

	// mgi := &MultiplicativeGroupInvariants[G, GE]{}
	//Missing method DiscreteExponentiation
	//Div
	//MultiplicativeInverse
	// IsMultiplicativeInverse
	// IsTorsionElementUnderMultiplication
	// Div
	// ApplyDiv
}

func CheckCyclicGroupInvariants[G algebra.CyclicGroup[G, GE], GE algebra.CyclicGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	CheckCyclicMonoidInvariants[G, GE](t, group, elementGenerator)
	CheckGroupInvariants[G, GE](t, group, elementGenerator)

	cgi := &CyclicGroupInvariants[G, GE]{}
	cgi.DLog(t, group)
}
