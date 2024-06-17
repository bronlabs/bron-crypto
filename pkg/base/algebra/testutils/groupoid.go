package curves_testutils

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type GroupoidInvariants[G algebra.Groupoid[G, GE], GE algebra.GroupoidElement[G, GE]] struct{}

type GroupoidElementInvariants[G algebra.Groupoid[G, GE], GE algebra.GroupoidElement[G, GE]] struct{}

type AdditiveGroupoidInvariants[G algebra.AdditiveGroupoid[G, GE], GE algebra.AdditiveGroupoidElement[G, GE]] struct{}

type AdditiveGroupoidElementInvariants[G algebra.AdditiveGroupoid[G, GE], GE algebra.AdditiveGroupoidElement[G, GE]] struct{}

type MultiplicativeGroupoidInvariants[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]] struct{}

type MultiplicativeGroupoidElementInvariants[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]] struct{}

type CyclicGroupoidInvariants[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]] struct{}

type CyclicGroupoidElementInvariants[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]] struct{}

func (gi *GroupoidInvariants[G, GE]) IsDefinedUnder(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
	t.Helper()
	// TODO
}

func (gi *GroupoidInvariants[G, GE]) Op(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (gi *GroupoidInvariants[G, GE]) Order(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
	t.Helper()
	require.True(t, groupoid.Order().Nat().Eq(groupoid.Order().Nat()) == 1)
}
func (gei *GroupoidElementInvariants[G, GE]) Order(t *testing.T, element algebra.GroupoidElement[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()
	output1, err := element.Order(under)
	require.NoError(t, err)
	output2, err := element.Order(under)
	require.NoError(t, err)
	require.True(t, output1.Nat().Eq(output2.Nat()) == 1)
}
func (gei *GroupoidElementInvariants[G, GE]) ApplyOp(t *testing.T, groupoid algebra.Groupoid[G, GE], element algebra.GroupoidElement[G, GE], under algebra.BinaryOperator[GE], n *saferith.Nat) {
	t.Helper()
	if groupoid.IsDefinedUnder(under) {
		actual, err := element.ApplyOp(under, element, n)
		require.NoError(t, err)
		result := element

		for i := 0; int64(i) < n.Big().Int64(); i++ {
			result, _ = result.ApplyOp(under, element, n)
		}
		require.True(t, result.Equal(actual))
	}
}
func (agi *AdditiveGroupoidInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroupoid[G, GE], x algebra.AdditiveGroupoidElement[G, GE], ys ...algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	sum := groupoid.Add(x)
	for index := len(ys) - 1; index >= 0; index-- {
		sum = groupoid.Add(sum, ys[index])
	}
	require.True(t, sum.Equal(groupoid.Add(x, ys...)),
		"Should get the same result for adding ys elements one by one to x")
}

func (agi *AdditiveGroupoidInvariants[G, GE]) Addition(t *testing.T, groupoid algebra.AdditiveGroupoid[G, GE], x, y algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()
	// TODO: how to test an operator
}

func (agei *AdditiveGroupoidElementInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroupoid[G, GE], x, y algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	actual := x.Add(y)
	require.True(t, actual.Equal(groupoid.Add(x, y)),
		"Should get the same result for adding ys elements one by one to x")
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) ApplyAdd(t *testing.T, x algebra.AdditiveGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	actual := x.ApplyAdd(x, n)
	sum := x

	for i := 0; int64(i) < n.Big().Int64(); i++ {
		sum = sum.Add(x)
	}

	require.True(t, sum.Equal(actual))
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Double(t *testing.T, x algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()
	n := new(saferith.Nat).SetUint64(1)

	require.True(t, x.ApplyAdd(x, n).Equal(x.Double()),
		"2x should have the same return as ApplyAdd(GE, 2)")
	require.True(t, x.Add(x).Equal(x.Double()),
		"2x should have the same return as x + x")

}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Triple(t *testing.T, x algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	n := new(saferith.Nat).SetUint64(2)
	require.True(t, x.ApplyAdd(x, n).Equal(x.Triple()),
		"3x should have the same return as ApplyAdd(GE, 3)")
	require.True(t, x.Add(x).Add(x).Equal(x.Triple()),
		"3x should have the same return as x + x + x")
	require.True(t, x.Double().Add(x).Equal(x.Triple()),
		"3x should have the same return as 2x + x")
}

func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Mul(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], x algebra.MultiplicativeGroupoidElement[G, GE], ys ...algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()

	mul := groupoid.Mul(x)
	for index := len(ys) - 1; index >= 0; index-- {
		mul = groupoid.Mul(mul, ys[index])
	}
	require.Equal(t, mul, groupoid.Mul(x, ys...),
		"Should get the same result for multiplying ys elements one by one to x")
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Exp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], base, power GE) {
	t.Helper()
	actual := groupoid.Exp(base, power)

	powerNat := new(saferith.Nat).SetUint64(power.HashCode())
	expected := base.Exp(powerNat)

	require.True(t, expected.Equal(actual))
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) SimExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], bases []algebra.MultiplicativeGroupoidElement[G, GE], exponents []*saferith.Nat) {
	t.Helper()

	actual, err := groupoid.SimExp(bases, exponents)
	require.NoError(t, err)

	expected := bases[0].ApplyMul(bases[0], exponents[0])

	for index := 1; index < len(bases); index++ {
		temp := bases[index].ApplyMul(bases[index], exponents[index])
		expected = expected.Mul(temp)
	}

	require.True(t, expected.Equal(actual))
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiBaseExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], bases []algebra.MultiplicativeGroupoidElement[G, GE], exponents *saferith.Nat) {
	t.Helper()

	actual := groupoid.MultiBaseExp(bases, exponents)

	expected := bases[0].ApplyMul(bases[0], exponents)
	for index := 1; index < len(bases); index++ {
		temp := bases[index].ApplyMul(bases[index], exponents)
		expected = expected.Mul(temp)
	}

	require.True(t, expected.Equal(actual))
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiExponentExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], bases algebra.MultiplicativeGroupoidElement[G, GE], exponents []*saferith.Nat) {
	t.Helper()

	actual := groupoid.MultiExponentExp(bases, exponents)

	expected := bases.ApplyMul(bases, exponents[0])

	for index := 1; index < len(exponents); index++ {
		temp := bases.ApplyMul(bases, exponents[index])
		expected = expected.Mul(temp)
	}

	require.True(t, expected.Equal(actual))
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Multiplication(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}

func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Mul(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], x, y algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()

	expected := groupoid.Mul(x, y)

	require.True(t, expected.Equal(groupoid.Mul(x, y)),
		"Should get the same result for multiplying ys elements one by one to x")
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) ApplyMul(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	actual := x.ApplyMul(x, n)

	result := x

	for i := 0; int64(i) < n.Big().Int64(); i++ {
		result = result.Mul(x)
	}

	require.True(t, result.Equal(actual), fmt.Sprintf("res: %v, actual: %v", result, actual))
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Square(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()

	result := x.Square()

	expected := x.Mul(x)

	require.True(t, expected.Equal(result))
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Cube(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()

	result := x.Cube()

	expected := x.Mul(x).Mul(x)

	require.True(t, expected.Equal(result),
		"x * x * x should be the same as x.Cube()")

	expected = x.Square().Mul(x)
	require.True(t, expected.Equal(result),
		"(x^2 * x) should be the same as x.Cube()")
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Exp(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	actual := x.Exp(n)

	expected := x
	for i := 1; int64(i) < n.Big().Int64(); i++ {
		expected = expected.Mul(x)
	}

	require.True(t, expected.Equal(actual))
}

func (cgi *CyclicGroupoidInvariants[G, GE]) Generator(t *testing.T, groupoid algebra.CyclicGroupoid[G, GE], under algebra.BinaryOperator[GE]) {
	t.Helper()
	output1 := groupoid.Generator()
	output2 := groupoid.Generator()
	require.True(t, output1.Equal(output2))

	IsDefined := groupoid.IsDefinedUnder(under)

	if IsDefined == true {
		expectedGen, err := output1.ApplyOp(under, output1, groupoid.Order().Nat())
		require.NoError(t, err)
		require.True(t, output1.Equal(expectedGen),
			"Expected orignal value after operator being called Order of times.")
	}
}

func (cgei *CyclicGroupoidElementInvariants[G, GE]) CanGenerateAllElements(t *testing.T, groupoid algebra.CyclicGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (cgei *CyclicGroupoidElementInvariants[G, GE]) IsDesignatedGenerator(t *testing.T, element algebra.CyclicGroupoidElement[G, GE]) {
	t.Helper()
	require.Equal(t, element.IsDesignatedGenerator(), element.IsDesignatedGenerator())
}

func CheckGroupoidInvariants[G algebra.Groupoid[G, GE], GE algebra.GroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	CheckStructuredSetInvariants[G, GE](t, groupoid, elementGenerator)
	// IsDefinedUnder
	// OP
	// Order
	// ApplyOP
}

func CheckAdditiveGroupoidInvariants[G algebra.AdditiveGroupoid[G, GE], GE algebra.AdditiveGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	CheckGroupoidInvariants[G, GE](t, groupoid, elementGenerator)

	agi := &AdditiveGroupoidInvariants[G, GE]{}

	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		agi.Add(t, groupoid, elementGenerator.Generate(), elementGenerator.Generate())
	})
	t.Run("Additon", func(t *testing.T) {
		t.Parallel()
		agi.Addition(t, groupoid, elementGenerator.Generate(), elementGenerator.Generate())
	})

	agei := &AdditiveGroupoidElementInvariants[G, GE]{}
	t.Run("Add for element", func(t *testing.T) {
		t.Parallel()
		agei.Add(t, groupoid, elementGenerator.Generate(), elementGenerator.Generate())
	})
	t.Run("ApplyAdd", func(t *testing.T) {
		t.Parallel()
		prng := fu.NewPrng().IntRange(0, 20)
		n := new(saferith.Nat).SetUint64(uint64(prng))
		agei.ApplyAdd(t, elementGenerator.Generate(), n)
	})
	t.Run("Double", func(t *testing.T) {
		t.Parallel()
		agei.Double(t, elementGenerator.Generate())
	})
	t.Run("Tripple", func(t *testing.T) {
		t.Parallel()
		agei.Triple(t, elementGenerator.Generate())
	})
}

func CheckMultiplicativeGroupoidInvariants[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()

	CheckGroupoidInvariants[G, GE](t, groupoid, elementGenerator)

	mgi := &MultiplicativeGroupoidInvariants[G, GE]{}
	t.Run("Mul", func(t *testing.T) {
		t.Parallel()
		mgi.Mul(t, groupoid, elementGenerator.Generate(), elementGenerator.Generate())
	})

	mgei := &MultiplicativeGroupoidElementInvariants[G, GE]{}
	t.Run("Mul", func(t *testing.T) {
		t.Parallel()
		mgei.Mul(t, groupoid, elementGenerator.Generate(), elementGenerator.Generate())
	})
	t.Run("ApplyMul", func(t *testing.T) {
		t.Parallel()
		prng := fu.NewPrng().IntRange(0, 20)
		n := new(saferith.Nat).SetUint64(uint64(prng))
		mgei.ApplyMul(t, elementGenerator.Generate(), n)
	})
	t.Run("Square", func(t *testing.T) {
		t.Parallel()

		mgei.Square(t, elementGenerator.Generate())
	})
	t.Run("Cube", func(t *testing.T) {
		t.Parallel()

		mgei.Cube(t, elementGenerator.Generate())
	})
	t.Run("Exp", func(t *testing.T) {
		t.Parallel()
		prng := fu.NewPrng().IntRange(0, 20)
		n := new(saferith.Nat).SetUint64(uint64(prng))
		mgei.Exp(t, elementGenerator.Generate(), n)
	})
}

func CheckCyclicGroupoidInvariants[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()

	CheckGroupoidInvariants[G, GE](t, groupoid, elementGenerator)
	CheckPointedSetElementConstant[G, GE](t, groupoid, elementGenerator)

	// TODO: Operator
	// Generator
	// CanGenerateAllElements
	// IsDesignatedGenerator
}
