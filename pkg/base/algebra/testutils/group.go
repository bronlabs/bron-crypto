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
	require.Equal(t, inverseOfIdentity, identityElement, "Inverse of identity element is itself")

	inverse, err := random.Inverse(under)
	require.NoError(t, err)
	inverseOfInverse, err1 := inverse.Inverse(under)
	require.NoError(t, err1)
	require.Equal(t, random, inverseOfInverse, "Inverse of inverse of X should be equal to X")

	// TODO: correct SYNTAX
	// var n *saferith.Nat
	// output, err := random.ApplyOp(under, inverse, n.SetUint64(uint64(1)))
	// require.Equal(t, identityElement, output, "Any element o inverse of the element should be equal to the identity element")
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

	var n *saferith.Nat
	output, err4 := random.ApplyOp(under, inverseOfRandom, n.SetUint64(uint64(1)))
	require.NoError(t, err4)
	IsInverse, err5 := output.IsInverse(output, under)
	require.NoError(t, err5)
	require.True(t, IsInverse, "identity element is Inverse of itself")
}
func (gei *GroupElementInvariants[G, GE]) IsTorsionElement(t *testing.T, random algebra.GroupElement[G, GE], order *saferith.Modulus, under algebra.BinaryOperator[GE]) {
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

func (agi *AdditiveGroupElementInvariants[G, GE]) AdditiveInverse(t *testing.T, group algebra.AdditiveGroup[G, GE], element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	identityElement := group.AdditiveIdentity()
	inverseOfIdentity := identityElement.AdditiveInverse()
	require.Equal(t, inverseOfIdentity, identityElement, "Inverse of identity element is itself")

	inverse := element.AdditiveInverse()
	inverseOfInverse := inverse.AdditiveInverse()
	require.Equal(t, element, inverseOfInverse, "Inverse of inverse of X should be equal to X")

	// var n *saferith.Nat
	// output := element.ApplyAdd(inverse, n.SetUint64(uint64(1))) // TODO: ERROR
	// require.Equal(t, identityElement, output, "Any element o inverse of the element should be equal to the identity element")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) IsAdditiveInverse(t *testing.T, group algebra.AdditiveGroup[G, GE], element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	identityElement := group.AdditiveIdentity()
	inverseOfIdentity := identityElement.IsAdditiveInverse(identityElement)
	require.True(t, inverseOfIdentity, "Inverse of identity element is itself")

	inverseOfElement := element.AdditiveInverse()
	IsInverseOfElement := element.IsAdditiveInverse(inverseOfElement)
	require.True(t, IsInverseOfElement, "Inverse of inverse of X should be equal to X")

	// var n *saferith.Nat
	n := new(saferith.Nat).SetUint64(1)
	output := element.ApplyAdd(inverseOfElement, n)
	IsInverse := output.IsAdditiveIdentity()
	require.True(t, IsInverse, "identity element is Inverse of itself")

}
func (agi *AdditiveGroupElementInvariants[G, GE]) IsTorsionElementUnderAddition(t *testing.T) {
	t.Helper()
	// TODO: Will add more invariants after the IsTorsionElement tests are implemented

}
func (agi *AdditiveGroupElementInvariants[G, GE]) Neg(t *testing.T, element algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	negElement := element.Neg()
	inverse := element.AdditiveInverse()
	require.Equal(t, inverse, negElement,
		"inverse of X should be the same as (-X)")
	require.Equal(t, inverse.Neg(), element,
		"-(-X) should be the same as negative of X")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) Sub(t *testing.T, group algebra.AdditiveGroup[G, GE], x algebra.AdditiveGroupElement[G, GE], ys ...algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	result := group.Add(x)
	for index := len(ys) - 1; index >= 0; index-- {
		result = group.Add(result, ys[index].Neg())
	}
	require.Equal(t, result, group.Sub(x, ys...),
		"Should get the same result for subtracting ys elements one by one from x")
}
func (agi *AdditiveGroupElementInvariants[G, GE]) ApplySub(t *testing.T, group algebra.AdditiveGroup[G, GE], x, y algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()
	//TODO: Help with the for loop, not Complete yet
	var n *saferith.Nat

	result := x.ApplySub(x, n)

	sub := x.Sub(x)
	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		sub = x.Sub(x)
	}
	require.Equal(t, sub, result)
}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) MultiplicativeInverse(t *testing.T, group algebra.MultiplicativeGroup[G, GE], element algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	identityElement := group.MultiplicativeIdentity()
	inverseOfIdentity, err := identityElement.MultiplicativeInverse()
	require.NoError(t, err)
	require.Equal(t, inverseOfIdentity, identityElement, "Inverse of identity element is itself")

	inverse, err1 := element.MultiplicativeInverse()
	require.NoError(t, err1)
	inverseOfInverse, err2 := inverse.MultiplicativeInverse()
	require.NoError(t, err2)
	require.Equal(t, element, inverseOfInverse, "Inverse of inverse of X should be equal to X")

	output := element.ApplyMul(inverse, n.SetUint64(uint64(1)))
	require.Equal(t, identityElement, output, "Any element o inverse of the element should be equal to the identity element")
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
	require.Equal(t, result, output,
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

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) IsTorsionElementUnderMultiplication(t *testing.T, group algebra.MultiplicativeGroup[G, GE], element algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()
	// TODO
}
func (mgei *MultiplicativeGroupElementInvariants[G, GE]) Div(t *testing.T, group algebra.MultiplicativeGroup[G, GE], x, y algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()

	output, err := x.Div(y)
	require.NoError(t, err)
	yInverse, err := y.MultiplicativeInverse()
	require.NoError(t, err)
	expected := x.Mul(yInverse)
	require.Equal(t, expected, output)

}

func (mgei *MultiplicativeGroupElementInvariants[G, GE]) ApplyDiv(t *testing.T, group algebra.MultiplicativeGroup[G, GE], x, y algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	output, err := x.ApplyDiv(y, n)
	require.NoError(t, err)

	expected, err1 := x.Div(y)
	require.NoError(t, err1)

	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		expected, _ = x.Div(y)
	}

	require.Equal(t, expected, output)
}
func (mgei *CyclicGroupInvariants[G, GE]) DLog(t *testing.T, group algebra.CyclicGroup[G, GE], x, y algebra.CyclicGroupElement[G, GE]) {
	t.Helper()
	// TODO:
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

// func CheckGroupElementInvariants[G algebra.Group[G, GE], GE algebra.GroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
// t.Helper()
// t.Helper()
// require.NotNil(t, group)
// require.NotNil(t, elementGenerator)
// invs := &GroupElementInvariants[G, GE]{}
//
//	t.Run("Inverse", func(t *testing.T) {
//		t.Parallel()
//		gen1 := elementGenerator.Clone()
//		isEmpty1 := gen1.Prng().IntRange(0, 16)
//		element := gen1.Empty()
//		if isEmpty1 != 0 {
//			element = gen1.GenerateNonZero()
//		}
//		invs.Inverse(t, group, element, algebra.Addition()) // TODO: how to pass Oprators ?
//	})
//
//	t.Run("IsInverse", func(t *testing.T) {
//		t.Parallel()
//		gen1 := elementGenerator.Clone()
//		isEmpty1 := gen1.Prng().IntRange(0, 16)
//		element := gen1.Empty()
//		if isEmpty1 != 0 {
//			element = gen1.GenerateNonZero()
//		}
//		var under algebra.BinaryOperator[GE]
//		invs.IsInverse(t, group, element, under)
//	})
//
//	t.Run("IsTorsionElement", func(t *testing.T) {
//		t.Parallel()
//		gen1 := elementGenerator.Clone()
//		isEmpty1 := gen1.Prng().IntRange(0, 16)
//		element := gen1.Empty()
//		if isEmpty1 != 0 {
//			element = gen1.GenerateNonZero()
//		}
//		var under algebra.BinaryOperator[GE]
//		// invs.IsTorsionElement(t, element, order, under)
//		invs.IsTorsionElement(t, element, group.Order(), under) // TODO: check if order is being used correctly.
//	})
//
// }

//	func CheckSubGroupInvariants[G algebra.SubGroup[G, GE], GE algebra.SubGroupElement[G, GE]](t *testing.T, group, subgroup G, elementGenerator fu.ObjectGenerator[GE]) {
//		// TODO: Tests are not implemented.
//		t.Helper()
//		require.NotNil(t, group)
//		require.NotNil(t, elementGenerator)
//		invs := &SubGroupInvariants[G, GE]{}
//		t.Run("CoFactor", func(t *testing.T) {
//			t.Parallel()
//			// TODO: Constant?
//			invs.CoFactor(t, group, subgroup)
//		})
//		t.Run("SuperGroupOrder", func(t *testing.T) {
//			t.Parallel()
//			invs.SuperGroupOrder(t, group)
//		})
//	}
//
//	func CheckSubGroupElementInvariants[G algebra.SubGroup[G, GE], GE algebra.SubGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
//		t.Helper()
//		//TODO: Need the correct Syntaxt for applyOp
//		require.NotNil(t, group)
//		require.NotNil(t, elementGenerator)
//		invs := &SubGroupElementInvariants[G, GE]{}
//		t.Run("IsSmallOrder", func(t *testing.T) {
//			t.Parallel()
//			gen1 := elementGenerator.Clone()
//			isEmpty1 := gen1.Prng().IntRange(0, 16)
//			element := gen1.Empty()
//			if isEmpty1 != 0 {
//				element = gen1.GenerateNonZero()
//			}
//			var under algebra.BinaryOperator[GE]
//			invs.IsSmallOrder(t, group, element, under)
//		})
//		t.Run("ClearCofactor", func(t *testing.T) {
//			t.Parallel()
//			gen1 := elementGenerator.Clone()
//			isEmpty1 := gen1.Prng().IntRange(0, 16)
//			element := gen1.Empty()
//			if isEmpty1 != 0 {
//				element = gen1.GenerateNonZero()
//			}
//			var under algebra.BinaryOperator[GE]
//			invs.ClearCofactor(t, group, element, under)
//		})
//	}

//	func CheckAdditiveGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
//		t.Helper()
//		require.NotNil(t, group)
//		require.NotNil(t, elementGenerator)
//		invs := &AdditiveGroupElementInvariants[G, GE]{}
//		t.Run("Sub", func(t *testing.T) {
//			t.Parallel()
//			// TODO: how to generate an array of elements
//			gen1 := elementGenerator.Clone()
//			gen2 := elementGenerator.Clone()
//			isEmpty1 := gen1.Prng().IntRange(0, 16)
//			isEmpty2 := gen2.Prng().IntRange(0, 16)
//			el1 := gen1.Empty()
//			el2 := gen2.Empty()
//			if isEmpty1 != 0 {
//				el1 = gen1.GenerateNonZero()
//			}
//			if isEmpty2 != 0 {
//				el2 = gen2.GenerateNonZero()
//			}
//			invs.Sub(t, group, el1, el2)
//		})
//	}
func CheckAdditiveGroupElementInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	// CheckAdditiveMonoidElementInvariants[G, GE]{}
	// TODO:....
	// func NewCollectionGenerator[C Collection[O], O Object](colAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng *Prng) (CollectionGenerator[C, O], error) {
	// fu.NewCollectionGenerator[](fu.SliceAdapter[G, GE])
	//TODOL ....
	invs := &AdditiveGroupElementInvariants[G, GE]{}
	t.Run("AdditivInverse", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		// this need to be abstracted away
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		invs.AdditiveInverse(t, group, element)
	})
	t.Run("IsAdditiveInverse", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		invs.IsAdditiveInverse(t, group, element)
	})
	// t.Run("IsTorsionElementUnderAddition", func(t *testing.T) {
	// 	t.Parallel()
	// 	// Need help for implementing the test
	// })
	t.Run("Neg", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		element := gen1.Empty()
		if isEmpty1 != 0 {
			element = gen1.GenerateNonZero()
		}
		invs.Neg(t, element)
	})
	t.Run("Sub", func(t *testing.T) {
		t.Parallel()
		// func NewCollectionGenerator[C Collection[O], O Object](colAdapter CollectionAdapter[C, O], elementGenerator ObjectGenerator[O], prng *Prng) (CollectionGenerator[C, O], error) {
		// fu.NewCollectionGenerator[](fu.SliceAdapter[G, GE])
		//TODO : How to generate an Array of elements ?
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
		invs.Sub(t, group, el1, el2)
	})
	// t.Run("ApplySub", func(t *testing.T) {
	// 	t.Parallel()
	// 	//TODO : How to generate an Array of elements ?
	// 	//TODO : FIX ApplySub
	// 	gen1 := elementGenerator.Clone()
	// 	gen2 := elementGenerator.Clone()
	// 	isEmpty1 := gen1.Prng().IntRange(0, 16)
	// 	isEmpty2 := gen2.Prng().IntRange(0, 16)
	// 	el1 := gen1.Empty()
	// 	el2 := gen2.Empty()
	// 	if isEmpty1 != 0 {
	// 		el1 = gen1.GenerateNonZero()
	// 	}
	// 	if isEmpty2 != 0 {
	// 		el2 = gen2.GenerateNonZero()
	// 	}
	// 	invs.ApplySub(t, group, el1, el2)
	// })
}

// func CheckMultiplicativeGroupInvariants[G algebra.MultiplicativeGroup[G, GE], GE algebra.MultiplicativeGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
// 	t.Helper()
// 	require.NotNil(t, group)
// 	require.NotNil(t, elementGenerator)
// 	invs := &MultiplicativeGroupInvariants[G, GE]{}
// 	t.Run("Div", func(t *testing.T) {
// 		t.Parallel()
// 		// TODO: how to generate an array of elements?
// 		gen1 := elementGenerator.Clone()
// 		gen2 := elementGenerator.Clone()
// 		isEmpty1 := gen1.Prng().IntRange(0, 16)
// 		isEmpty2 := gen2.Prng().IntRange(0, 16)
// 		el1 := gen1.Empty()
// 		el2 := gen2.Empty()
// 		if isEmpty1 != 0 {
// 			el1 = gen1.GenerateNonZero()
// 		}
// 		if isEmpty2 != 0 {
// 			el2 = gen2.GenerateNonZero()
// 		}
// 		invs.Div(t, group, el1, el2)
// 	})
// }
