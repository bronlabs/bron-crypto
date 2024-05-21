package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

type GroupoidInvariants[G algebra.Groupoid[G, GE], GE algebra.GroupElement[G, GE]] struct{}

type GroupoidElementInvariants[G algebra.Groupoid[G, GE], GE algebra.GroupElement[G, GE]] struct{}

type AdditiveGroupoidInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]] struct{}

type AdditiveGroupoidElementInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]] struct{}

type MultiplicativeGroupoidInvariants[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]] struct{}

type MultiplicativeGroupoidElementInvariants[G algebra.MultiplicativeGroupoid[G, GE], GE algebra.MultiplicativeGroupoidElement[G, GE]] struct{}

type CyclicGroupoidInvariants[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]] struct{}

type CyclicGroupoidElementInvariants[G algebra.CyclicGroupoid[G, GE], GE algebra.CyclicGroupoidElement[G, GE]] struct{}

func (gi *GroupoidInvariants[G, GE]) IsDefinedUnder(t *testing.T, groupoid algebra.Groupoid[G, GE]) {
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
func (agi *AdditiveGroupoidInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroup[G, GE], x algebra.AdditiveGroupElement[G, GE], ys ...algebra.AdditiveGroupoidElement[G, GE]) {
	t.Helper()

	sum := groupoid.Add(x)
	for index := len(ys) - 1; index >= 0; index-- {
		sum = groupoid.Add(sum, ys[index])
	}
	require.Equal(t, sum, groupoid.Add(x, ys...),
		"Should get the same result for adding ys elements one by one to x")
}

func (agi *AdditiveGroupoidInvariants[G, GE]) Addition(t *testing.T, groupoid algebra.AdditiveGroup[G, GE], x, y algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()
	// TODO
}

func (agei *AdditiveGroupoidElementInvariants[G, GE]) Add(t *testing.T, groupoid algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()
	// TODO
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) ApplyAdd(t *testing.T, groupoid algebra.AdditiveGroupElement[G, GE], x algebra.AdditiveGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	sum := x.Add(x)

	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		sum = x.Add(x)
	}

	require.Equal(t, sum, x.ApplyAdd(x, n))
}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Double(t *testing.T, x algebra.AdditiveGroupElement[G, GE]) {
	t.Helper()

	doubleX := x.Double()

	n := new(saferith.Nat)
	expected := x.ApplyAdd(x, n.SetUint64(uint64(2)))

	require.Equal(t, expected, doubleX,
		"2x should have the same return as ApplyAdd(GE, 2)")

}
func (agei *AdditiveGroupoidElementInvariants[G, GE]) Triple(t *testing.T, x algebra.AdditiveGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	trippleX := x.Triple()

	expected := x.ApplyAdd(x, n.SetUint64(uint64(3)))
	require.Equal(t, expected, trippleX,
		"3x should have the same return as x + x + x")

	expected = x.Double().Add(x)
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

func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Exp(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE], x, n algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()

	// result := groupoid.Exp(x.Unwrap(), n.Unwrap())

	// ys := make(algebra.MultiplicativeGroupoidElement[G, GE], len(n)) // TODO: What's the correct syntax here?

}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) SimExp(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiBaseExp(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) MultiExponentExp(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) Multiplication(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE]) {
	t.Helper()
	// TODO
}
func (mgi *MultiplicativeGroupoidInvariants[G, GE]) DiscreteExponentiation(t *testing.T, groupoid algebra.MultiplicativeGroup[G, GE]) {
	t.Helper()
	// TODO
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Mul(t *testing.T, x, y algebra.MultiplicativeGroupElement[G, GE]) {
	t.Helper()
	//TODO
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) ApplyMul(t *testing.T, x algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.ApplyMul(x, n)

	mul := x.Mul(x)
	for i := 2; int64(i) < n.Big().Int64(); i++ { // n-2 times
		mul = x.Mul(x)
	}

	require.Equal(t, mul, result)
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Square(t *testing.T, x algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.Square()

	expected := x.ApplyMul(x, n.SetUint64(uint64(2)))

	require.Equal(t, expected, result)
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Cube(t *testing.T, x algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
	t.Helper()

	result := x.Cube()

	expected := x.ApplyMul(x, n.SetUint64(uint64(3)))

	require.Equal(t, expected, result,
		"x * x * x should be the same as x.Cube()")

	expected = x.Square().Mul(x)
	require.Equal(t, expected, result,
		"(x^2 * x) should be the same as x.Cube()")
}
func (mgei *MultiplicativeGroupoidElementInvariants[G, GE]) Exp(t *testing.T, x algebra.MultiplicativeGroupElement[G, GE], n *saferith.Nat) {
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

func (cgi *CyclicGroupoidElementInvariants[G, GE]) CanGenerateAllElements(t *testing.T, gen algebra.CyclicGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}
func (cgi *CyclicGroupoidElementInvariants[G, GE]) IsDesignatedGenerator(t *testing.T, gen algebra.CyclicGroupoidElement[G, GE]) {
	t.Helper()
	// TODO
}
