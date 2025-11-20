package ct_test

import (
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestSliceEachEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		slice := rapid.SliceOfN(rapid.Byte(), 1, sliceLength).Draw(t, "slice")
		element := rapid.SampledFrom(slice).Draw(t, "element")

		expected := ct.True
		for _, v := range slice {
			if v != element {
				expected = ct.False
				break
			}
		}

		actual := ct.SliceEachEqual(slice, element)
		require.Equal(t, expected, actual)
	})
}

func TestSliceEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		slice1 := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "slice1")
		slice2 := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "slice2")

		expected := slices.Equal(slice1, slice2)
		actual := ct.SliceEqual(slice1, slice2) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestSliceIsZero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		slice := rapid.SliceOf(rapid.Byte()).Draw(t, "slice")

		expected := ct.True
		for _, v := range slice {
			if v != 0 {
				expected = ct.False
				break
			}
		}

		actual := ct.SliceIsZero(slice)
		require.Equal(t, expected, actual)
	})
}

func TestCSelectInts_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		x0 := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "x0")
		x1 := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "x1")
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))

		var expected []byte
		if choice == ct.True {
			expected = x1
		} else {
			expected = x0
		}

		actual := ct.CSelectInts(choice, x0, x1)
		require.Equal(t, expected, actual)
	})
}

func TestCMOVInts_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		src := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "src")
		yes := ct.Choice(rapid.IntRange(0, 1).Draw(t, "yes"))

		actual := make([]byte, len(src))
		ct.CMOVInts(actual, src, yes)

		expected := make([]byte, len(src))
		if yes == ct.True {
			expected = src
		}
		require.Equal(t, expected, actual)
	})
}

func TestCSwapInts_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		sliceLength := rapid.IntRange(1, 100).Draw(t, "sliceLength")
		x := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "x")
		y := rapid.SliceOfN(rapid.Byte(), sliceLength, sliceLength).Draw(t, "y")
		yes := ct.Choice(rapid.IntRange(0, 1).Draw(t, "yes"))

		xCopy := make([]byte, len(x))
		copy(xCopy, x)
		yCopy := make([]byte, len(y))
		copy(yCopy, y)

		ct.CSwapInts(x, y, yes)

		var expectedX, expectedY []byte
		if yes == ct.True {
			expectedX = yCopy
			expectedY = xCopy
		} else {
			expectedX = xCopy
			expectedY = yCopy
		}

		require.Equal(t, expectedX, x)
		require.Equal(t, expectedY, y)
	})
}
