package base_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// Test types for comparison

type simpleInt int

func (s simpleInt) IsLessThanOrEqual(rhs simpleInt) bool {
	return s <= rhs
}

type ctComparableInt int

func (c ctComparableInt) IsLessThanOrEqual(rhs ctComparableInt) bool {
	return c <= rhs
}

func (c ctComparableInt) Compare(rhs ctComparableInt) (lt, eq, gt ct.Choice) {
	lt = ct.Less(int(c), int(rhs))
	eq = ct.Equal(int(c), int(rhs))
	gt = ct.Greater(int(c), int(rhs))
	return
}

type withPartialCompareInt int

func (w withPartialCompareInt) IsLessThanOrEqual(rhs withPartialCompareInt) bool {
	return w <= rhs
}

func (w withPartialCompareInt) PartialCompare(rhs withPartialCompareInt) base.PartialOrdering {
	if w < rhs {
		return base.LessThan
	}
	if w > rhs {
		return base.GreaterThan
	}
	return base.Equal
}

type withCompareInt int

func (w withCompareInt) IsLessThanOrEqual(rhs withCompareInt) bool {
	return w <= rhs
}

func (w withCompareInt) Compare(rhs withCompareInt) base.Ordering {
	if w < rhs {
		return base.Ordering(base.LessThan)
	}
	if w > rhs {
		return base.Ordering(base.GreaterThan)
	}
	return base.Ordering(base.Equal)
}

func TestPartialOrdering_String(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Incomparable", base.Incomparable.String())
	require.Equal(t, "LessThan", base.LessThan.String())
	require.Equal(t, "Equal", base.Equal.String())
	require.Equal(t, "GreaterThan", base.GreaterThan.String())
}

func TestOrdering_String(t *testing.T) {
	t.Parallel()
	require.Equal(t, "LessThan", base.Ordering(base.LessThan).String())
	require.Equal(t, "Equal", base.Ordering(base.Equal).String())
	require.Equal(t, "GreaterThan", base.Ordering(base.GreaterThan).String())
}

func TestPartialOrdering_Is(t *testing.T) {
	t.Parallel()
	require.True(t, base.LessThan.Is(base.Ordering(base.LessThan)))
	require.True(t, base.Equal.Is(base.Ordering(base.Equal)))
	require.True(t, base.GreaterThan.Is(base.Ordering(base.GreaterThan)))
	require.False(t, base.LessThan.Is(base.Ordering(base.Equal)))
	require.False(t, base.Incomparable.Is(base.Ordering(base.LessThan)))
}

func TestOrdering_Is(t *testing.T) {
	t.Parallel()
	require.True(t, base.Ordering(base.LessThan).Is(base.LessThan))
	require.True(t, base.Ordering(base.Equal).Is(base.Equal))
	require.True(t, base.Ordering(base.GreaterThan).Is(base.GreaterThan))
	require.False(t, base.Ordering(base.LessThan).Is(base.Equal))
	require.False(t, base.Ordering(base.LessThan).Is(base.Incomparable))
}

func TestPartialOrdering_IsLessThan(t *testing.T) {
	t.Parallel()
	require.True(t, base.LessThan.IsLessThan())
	require.False(t, base.Equal.IsLessThan())
	require.False(t, base.GreaterThan.IsLessThan())
	require.False(t, base.Incomparable.IsLessThan())
}

func TestOrdering_IsLessThan(t *testing.T) {
	t.Parallel()
	require.True(t, base.Ordering(base.LessThan).IsLessThan())
	require.False(t, base.Ordering(base.Equal).IsLessThan())
	require.False(t, base.Ordering(base.GreaterThan).IsLessThan())
}

func TestPartialOrdering_IsGreaterThan(t *testing.T) {
	t.Parallel()
	require.True(t, base.GreaterThan.IsGreaterThan())
	require.False(t, base.Equal.IsGreaterThan())
	require.False(t, base.LessThan.IsGreaterThan())
	require.False(t, base.Incomparable.IsGreaterThan())
}

func TestOrdering_IsGreaterThan(t *testing.T) {
	t.Parallel()
	require.True(t, base.Ordering(base.GreaterThan).IsGreaterThan())
	require.False(t, base.Ordering(base.Equal).IsGreaterThan())
	require.False(t, base.Ordering(base.LessThan).IsGreaterThan())
}

func TestPartialOrdering_IsEqual(t *testing.T) {
	t.Parallel()
	require.True(t, base.Equal.IsEqual())
	require.False(t, base.LessThan.IsEqual())
	require.False(t, base.GreaterThan.IsEqual())
	require.False(t, base.Incomparable.IsEqual())
}

func TestOrdering_IsEqual(t *testing.T) {
	t.Parallel()
	require.True(t, base.Ordering(base.Equal).IsEqual())
	require.False(t, base.Ordering(base.LessThan).IsEqual())
	require.False(t, base.Ordering(base.GreaterThan).IsEqual())
}

func TestPartialOrdering_IsIncomparable(t *testing.T) {
	t.Parallel()
	require.True(t, base.Incomparable.IsIncomparable())
	require.False(t, base.LessThan.IsIncomparable())
	require.False(t, base.Equal.IsIncomparable())
	require.False(t, base.GreaterThan.IsIncomparable())
}

func TestPartialCompare(t *testing.T) {
	t.Parallel()

	// Test with simple type
	require.Equal(t, base.LessThan, base.PartialCompare(simpleInt(1), simpleInt(2)))
	require.Equal(t, base.Equal, base.PartialCompare(simpleInt(2), simpleInt(2)))
	require.Equal(t, base.GreaterThan, base.PartialCompare(simpleInt(3), simpleInt(2)))

	// Test with ct.Comparable type (constant-time comparison)
	require.Equal(t, base.LessThan, base.PartialCompare(ctComparableInt(1), ctComparableInt(2)))
	require.Equal(t, base.Equal, base.PartialCompare(ctComparableInt(2), ctComparableInt(2)))
	require.Equal(t, base.GreaterThan, base.PartialCompare(ctComparableInt(3), ctComparableInt(2)))

	// Test with WithInternalPartialCompareMethod
	require.Equal(t, base.LessThan, base.PartialCompare(withPartialCompareInt(1), withPartialCompareInt(2)))
	require.Equal(t, base.Equal, base.PartialCompare(withPartialCompareInt(2), withPartialCompareInt(2)))
	require.Equal(t, base.GreaterThan, base.PartialCompare(withPartialCompareInt(3), withPartialCompareInt(2)))
}

func TestCompare(t *testing.T) {
	t.Parallel()

	// Test with simple type
	require.Equal(t, base.Ordering(base.LessThan), base.Compare(simpleInt(1), simpleInt(2)))
	require.Equal(t, base.Ordering(base.Equal), base.Compare(simpleInt(2), simpleInt(2)))
	require.Equal(t, base.Ordering(base.GreaterThan), base.Compare(simpleInt(3), simpleInt(2)))

	// Test with ct.Comparable type (constant-time comparison)
	require.Equal(t, base.Ordering(base.LessThan), base.Compare(ctComparableInt(1), ctComparableInt(2)))
	require.Equal(t, base.Ordering(base.Equal), base.Compare(ctComparableInt(2), ctComparableInt(2)))
	require.Equal(t, base.Ordering(base.GreaterThan), base.Compare(ctComparableInt(3), ctComparableInt(2)))

	// Test with WithInternalCompareMethod
	require.Equal(t, base.Ordering(base.LessThan), base.Compare(withCompareInt(1), withCompareInt(2)))
	require.Equal(t, base.Ordering(base.Equal), base.Compare(withCompareInt(2), withCompareInt(2)))
	require.Equal(t, base.Ordering(base.GreaterThan), base.Compare(withCompareInt(3), withCompareInt(2)))
}

func TestParseOrderingFromMasks(t *testing.T) {
	t.Parallel()

	// Test GreaterThan (gt != 0)
	require.Equal(t, base.GreaterThan, base.ParseOrderingFromMasks(0, 0, 1))

	// Test Equal (eq != 0, gt == 0)
	require.Equal(t, base.Equal, base.ParseOrderingFromMasks(0, 1, 0))

	// Test LessThan (lt != 0, eq == 0, gt == 0)
	require.Equal(t, base.LessThan, base.ParseOrderingFromMasks(1, 0, 0))

	// Test Incomparable (all zero)
	require.Equal(t, base.Incomparable, base.ParseOrderingFromMasks(0, 0, 0))

	// Test with different integer types
	require.Equal(t, base.GreaterThan, base.ParseOrderingFromMasks(int8(0), int8(0), int8(1)))
	require.Equal(t, base.Equal, base.ParseOrderingFromMasks(uint64(0), uint64(1), uint64(0)))
}
