package curves_testutils

import (
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
	// TODO
}
func (gei *GroupoidElementInvariants[G, GE]) Order(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (gei *GroupoidElementInvariants[G, GE]) ApplyOp(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (agi *AdditiveGroupoidInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroupoid[G, GE], x algebra.AdditiveGroupoidElement[G, GE], ys ...algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	sum := groupoid.Add(x)
	for index := len(ys) - 1; index >= 0; index-- {
		sum = groupoid.Add(sum, ys[index])
	}
	require.Equal(t, sum, groupoid.Add(x, ys...),
		"Should get the same result for adding ys elements one by one to x")
}

func (agi *AdditiveGroupoidInvariants[G, GE]) Addition(t *testing.T, groupoid algebra.AdditiveGroupoid[G, GE], x, y algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}

func (agei *AdditiveGroupoidElementInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) ApplyAdd(t *testing.T, groupoid algebra.AdditiveGroupoidElement[G, GE], x algebra.AdditiveGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	sum := x.Add(x)

	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		sum = x.Add(x)
	}

	require.Equal(t, sum, x.ApplyAdd(x, n))
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Double(t *testing.T, x algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	doubleX := x.Double()
	// n := new(saferith.Nat).SetUint64(2)
	// expected := x.ApplyAdd(x, n)

	// require.Equal(t, expected, doubleX,
	// 	"2x should have the same return as ApplyAdd(GE, 2)") // TODO: why is this test wrong?
	require.Equal(t, x.Add(x), doubleX,
		"2x should have the same return as x + x")

}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Triple(t *testing.T, x algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	trippleX := x.Triple()

	// n := new(saferith.Nat).SetUint64(2)
	// expected := x.ApplyAdd(x, n)
	// require.Equal(t, expected, trippleX,
	// 	"3x should have the same return as x + x + x") // TODO: why is this wrong?

	expected := x.Double().Add(x)
	require.Equal(t, expected, trippleX,
		"3x should have the same return as 2x + x")
	expected = x.Add(x).Add(x)
	require.Equal(t, expected, trippleX,
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

func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Exp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE], x algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()

	// result := groupoid.Exp(x.Unwrap(), n.Unwrap())

	// ys := make(algebra.MultiplicativeGroupoidElement[G, GE], len(n)) // TODO: What's the correct syntax here?

}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) SimExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiBaseExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiExponentExp(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Multiplication(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) DiscreteExponentiation(t *testing.T, groupoid algebra.MultiplicativeGroupoid[G, GE]) {
	t.Helper()
	// TODO
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Mul(t *testing.T, x, y algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()
	//TODO
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) ApplyMul(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE]) {
	t.Helper()
	n := new(saferith.Nat).SetUint64(2)
	result := x.ApplyMul(x, n)

	mul := x.Mul(x)
	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		mul = x.Mul(x)
	}

	require.Equal(t, mul, result)
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Square(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.Square()

	expected := x.ApplyMul(x, n.SetUint64(uint64(2)))

	require.Equal(t, expected, result)
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Cube(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.Cube()

	expected := x.ApplyMul(x, n.SetUint64(uint64(3)))

	require.Equal(t, expected, result,
		"x * x * x should be the same as x.Cube()")

	expected = x.Square().Mul(x)
	require.Equal(t, expected, result,
		"(x^2 * x) should be the same as x.Cube()")
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Exp(t *testing.T, x algebra.MultiplicativeGroupoidElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.Exp(n)

	expected := x.ApplyMul(x, n)

	require.Equal(t, expected, result)

	mul := x.Mul(x)
	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		mul = x.Mul(x)
	}

	require.Equal(t, mul, result)
}

func (cgi *CyclicGroupoidInvariants[G, GE]) Generator(t *testing.T, groupoid algebra.CyclicGroupoid[G, GE]) {
	t.Helper()
	// TODO
}

func (cgei *CyclicGroupoidElementInvariants[G, GE]) CanGenerateAllElements(t *testing.T, gen algebra.CyclicGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}
func (cgei *CyclicGroupoidElementInvariants[G, GE]) IsDesignatedGenerator(t *testing.T, gen algebra.CyclicGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}

func CheckGroupoidInvariant[G algebra.Groupoid[G, GE], GE algebra.GroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	CheckStructuredSetInvariants[G, GE](t, groupoid, elementGenerator)

	gi := &GroupoidInvariants[G, GE]{}
	gi.IsDefinedUnder(t, groupoid)
	// gi.Op(t, groupoid, operator) // TODO: how to call operator

	gei := &GroupoidElementInvariants[G, GE]{}
	gei.Order(t, groupoid)
	gei.ApplyOp(t, groupoid)
}

func CheckAddiriveGroupoidInvariant[G algebra.AdditiveGroupoid[G, GE], GE algebra.AdditiveGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	CheckGroupoidInvariant[G, GE](t, groupoid, elementGenerator)

	agi := &AdditiveGroupoidInvariants[G, GE]{}

	t.Run("Add", func(t *testing.T) {
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
		agi.Add(t, groupoid, el1, el2)
	})
	t.Run("Additon", func(t *testing.T) {
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
		agi.Addition(t, groupoid, el1, el2)
	})

	agei := &AdditiveGroupoidElementInvariants[G, GE]{}
	t.Run("Add for element", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		agei.Add(t, el1)
	})
	// t.Run("ApplyAdd", func(t *testing.T) {
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
	// 	//TODO: how to properly pass n ?
	// 	agei.ApplyAdd(t, el1, el2, n)
	// })
	t.Run("Double", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		agei.Double(t, el1)
	})
	t.Run("Tripple", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		agei.Triple(t, el1)
	})
}

func CheckMultiplicativeGroupoidInvariant[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	// the fuzz function doesn't accept this checkFunction: "Missing DiscreteExponentiation"
	CheckGroupoidInvariant[G, GE](t, groupoid, elementGenerator)

	// mgi := &MultiplicativeGroupoidInvariants[G, GE]{}
	// t.Run("Mul", func(t *testing.T) {
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
	// 	mgi.Mul(t, groupoid, el1, el2)
	// })
	// t.Run("Exp", func(t *testing.T) {
	// 	gen1 := elementGenerator.Clone()
	// 	isEmpty1 := gen1.Prng().IntRange(0, 16)
	// 	el1 := gen1.Empty()
	// 	if isEmpty1 != 0 {
	// 		el1 = gen1.GenerateNonZero()
	// 	}
	// 	mgi.Exp(t, groupoid, el1)
	// })
	// t.Run("SimExp", func(t *testing.T) {
	// 	mgi.SimExp(t, groupoid)
	// })
	// t.Run("MultiBaseExp", func(t *testing.T) {
	// 	mgi.MultiBaseExp(t, groupoid)
	// })
	// t.Run("MultiExponentExp", func(t *testing.T) {
	// 	mgi.MultiExponentExp(t, groupoid)
	// })
	// t.Run("Multiplication", func(t *testing.T) {
	// 	mgi.Multiplication(t, groupoid)
	// })
	// t.Run("DiscreteExponentiation", func(t *testing.T) {
	// 	mgi.DiscreteExponentiation(t, groupoid)
	// })

	// mgei := &MultiplicativeGroupoidElementInvariants[G, GE]{}
	// t.Run("Mul", func(t *testing.T) {
		// gen1 := elementGenerator.Clone()
		// gen2 := elementGenerator.Clone()
		// isEmpty1 := gen1.Prng().IntRange(0, 16)
		// isEmpty2 := gen2.Prng().IntRange(0, 16)
		// el1 := gen1.Empty()
		// el2 := gen2.Empty()
		// if isEmpty1 != 0 {
		// 	el1 = gen1.GenerateNonZero()
		// }
		// if isEmpty2 != 0 {
		// 	el2 = gen2.GenerateNonZero()
		// }
		// mgei.Mul(t, el1, el2)
	// })
	// t.Run("ApplyMul", func(t *testing.T) {
	// 	gen1 := elementGenerator.Clone()
	// 	isEmpty1 := gen1.Prng().IntRange(0, 16)
	// 	el1 := gen1.Empty()
	// 	if isEmpty1 != 0 {
	// 		el1 = gen1.GenerateNonZero()
	// 	}
	// 	mgei.ApplyMul(t, groupoid, el1)
	// })
	// mgei.Square(t, el1)
	// mgei.Cube(t, el1)
	// mgei.Exp(t, el1)
}

func CheckCyclicGroupoidInvariant[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]](t *testing.T, groupoid G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	CheckGroupoidInvariant[G, GE](t, groupoid, elementGenerator)

	cgi := &CyclicGroupoidInvariants[G, GE]{}
	cgi.Generator(t, groupoid)

	cgei := &CyclicGroupoidElementInvariants[G, GE]{}
	t.Run("CanGenerateAllElements", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		cgei.CanGenerateAllElements(t, el1)
	})
	t.Run("IsDesignatedGenerator", func(t *testing.T) {
		gen1 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		cgei.IsDesignatedGenerator(t, el1)
	})
}
