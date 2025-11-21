package sliceutils_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func TestMapOrError(t *testing.T) {
	t.Parallel()
	// Test successful mapping
	result, err := sliceutils.MapOrError([]int{1, 2, 3}, func(x int) (int, error) {
		return x * 2, nil
	})
	require.NoError(t, err)
	require.Equal(t, []int{2, 4, 6}, result)

	// Test with error
	_, err = sliceutils.MapOrError([]int{1, 2, 3}, func(x int) (int, error) {
		if x == 2 {
			return 0, errors.New("error at 2")
		}
		return x * 2, nil
	})
	require.Error(t, err)
}

func TestMapCast(t *testing.T) {
	t.Parallel()
	type MySlice []int
	result := sliceutils.MapCast[MySlice]([]int{1, 2, 3}, func(x int) int {
		return x * 2
	})
	require.Equal(t, MySlice{2, 4, 6}, result)
}

func TestMap(t *testing.T) {
	t.Parallel()
	result := sliceutils.Map([]int{1, 2, 3}, func(x int) int {
		return x * 2
	})
	require.Equal(t, []int{2, 4, 6}, result)
}

func TestFilter(t *testing.T) {
	t.Parallel()
	result := sliceutils.Filter([]int{1, 2, 3, 4, 5}, func(x int) bool {
		return x%2 == 0
	})
	require.Equal(t, []int{2, 4}, result)
}

func TestReduce(t *testing.T) {
	t.Parallel()
	result := sliceutils.Reduce([]int{1, 2, 3, 4}, 0, func(acc, x int) int {
		return acc + x
	})
	require.Equal(t, 10, result)
}

func TestRepeat(t *testing.T) {
	t.Parallel()
	result := sliceutils.Repeat[[]int](42, 3)
	require.Equal(t, []int{42, 42, 42}, result)
}

func TestReversed(t *testing.T) {
	t.Parallel()
	input := []int{1, 2, 3, 4}
	result := sliceutils.Reversed(input)
	require.Equal(t, []int{4, 3, 2, 1}, result)
	// Original should be unchanged
	require.Equal(t, []int{1, 2, 3, 4}, input)
}

func TestReverse(t *testing.T) {
	t.Parallel()
	input := []int{1, 2, 3, 4}
	result := sliceutils.Reverse(input)
	require.Equal(t, []int{4, 3, 2, 1}, result)
	// Original should be changed (in-place)
	require.Equal(t, []int{4, 3, 2, 1}, input)
}

func TestShuffle(t *testing.T) {
	t.Parallel()
	// Test with nil prng
	_, err := sliceutils.Shuffle([]int{1, 2, 3}, nil)
	require.Error(t, err)

	// Test with empty slice
	result, err := sliceutils.Shuffle([]int{}, bytes.NewReader([]byte{1, 2, 3}))
	require.NoError(t, err)
	require.Equal(t, []int{}, result)

	// Test with valid prng
	input := []int{1, 2, 3, 4, 5}
	// Provide enough random bytes for shuffle (8 bytes per random number, worst case 4*8=32 bytes needed)
	randomBytes := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	}
	prng := bytes.NewReader(randomBytes)
	result, err = sliceutils.Shuffle(input, prng)
	require.NoError(t, err)
	require.Len(t, result, 5)
}

func TestShuffled(t *testing.T) {
	t.Parallel()
	input := []int{1, 2, 3, 4, 5}
	// Provide enough random bytes for shuffle
	randomBytes := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	}
	prng := bytes.NewReader(randomBytes)
	result, err := sliceutils.Shuffled(input, prng)
	require.NoError(t, err)
	require.Len(t, result, 5)
	// Original should be unchanged
	require.Equal(t, []int{1, 2, 3, 4, 5}, input)
	require.NotEqual(t, input, result, "you're extremely unlucky if the shuffled result is the same as the input")
}

func TestPadToLeft(t *testing.T) {
	t.Parallel()
	result := sliceutils.PadToLeft([]int{1, 2, 3}, 2)
	require.Equal(t, []int{0, 0, 1, 2, 3}, result)

	// Test with negative padLength
	result = sliceutils.PadToLeft([]int{1, 2, 3}, -1)
	require.Equal(t, []int{1, 2, 3}, result)
}

func TestPadToLeftWith(t *testing.T) {
	t.Parallel()
	result := sliceutils.PadToLeftWith([]int{1, 2, 3}, 2, 9)
	require.Equal(t, []int{9, 9, 1, 2, 3}, result)
}

func TestPadToRight(t *testing.T) {
	t.Parallel()
	result := sliceutils.PadToRight([]int{1, 2, 3}, 2)
	require.Equal(t, []int{1, 2, 3, 0, 0}, result)

	// Test with negative padLength
	result = sliceutils.PadToRight([]int{1, 2, 3}, -1)
	require.Equal(t, []int{1, 2, 3}, result)
}

func TestPadToRightWith(t *testing.T) {
	t.Parallel()
	result := sliceutils.PadToRightWith([]int{1, 2, 3}, 2, 9)
	require.Equal(t, []int{1, 2, 3, 9, 9}, result)
}

func TestCount(t *testing.T) {
	t.Parallel()
	result := sliceutils.Count([]int{1, 2, 3, 4, 5}, func(x int) bool {
		return x%2 == 0
	})
	require.Equal(t, 2, result)
}

func TestCountUnique(t *testing.T) {
	t.Parallel()
	result := sliceutils.CountUnique([]int{1, 2, 2, 3, 3, 3})
	require.Equal(t, 3, result)
}

func TestCountUniqueFunc(t *testing.T) {
	t.Parallel()
	result := sliceutils.CountUniqueFunc([]int{1, 2, 2, 3, 3, 3}, func(a, b int) bool {
		return a == b
	})
	require.Equal(t, 3, result)
}

func TestAny(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.Any([]int{1, 2, 3}, func(x int) bool { return x == 2 }))
	require.False(t, sliceutils.Any([]int{1, 2, 3}, func(x int) bool { return x == 5 }))
}

func TestAll(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.All([]int{2, 4, 6}, func(x int) bool { return x%2 == 0 }))
	require.False(t, sliceutils.All([]int{1, 2, 3}, func(x int) bool { return x%2 == 0 }))
}

func TestIsAllUnique(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.IsAllUnique([]int{1, 2, 3}))
	require.False(t, sliceutils.IsAllUnique([]int{1, 2, 2, 3}))
}

func TestIsAllUniqueFunc(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.IsAllUniqueFunc([]int{1, 2, 3}, func(a, b int) bool { return a == b }))
	require.False(t, sliceutils.IsAllUniqueFunc([]int{1, 2, 2, 3}, func(a, b int) bool { return a == b }))
}

func TestIsSubList(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.IsSubList([]int{1, 2}, []int{1, 2, 3, 4}))
	require.False(t, sliceutils.IsSubList([]int{1, 5}, []int{1, 2, 3, 4}))
	require.False(t, sliceutils.IsSubList([]int{1, 2, 3, 4, 5}, []int{1, 2, 3}))
}

func TestIsSubListFunc(t *testing.T) {
	t.Parallel()
	eq := func(a, b int) bool { return a == b }
	require.True(t, sliceutils.IsSubListFunc([]int{1, 2}, []int{1, 2, 3, 4}, eq))
	require.False(t, sliceutils.IsSubListFunc([]int{1, 5}, []int{1, 2, 3, 4}, eq))
}

func TestIsSuperList(t *testing.T) {
	t.Parallel()
	require.True(t, sliceutils.IsSuperList([]int{1, 2, 3, 4}, []int{1, 2}))
	require.False(t, sliceutils.IsSuperList([]int{1, 2, 3, 4}, []int{1, 5}))
	require.True(t, sliceutils.IsSuperList([]int{1, 2, 3, 4, 5}, []int{1, 2, 3}))
	require.False(t, sliceutils.IsSuperList([]int{1, 2, 3}, []int{1, 2, 3, 4, 5}))
	require.True(t, sliceutils.IsSuperList([]int{1, 2, 3}, []int{1, 2, 3}))
}

func TestContainsFunc(t *testing.T) {
	t.Parallel()
	eq := func(a, b int) bool { return a == b }
	require.True(t, sliceutils.ContainsFunc([]int{1, 2, 3}, 2, eq))
	require.False(t, sliceutils.ContainsFunc([]int{1, 2, 3}, 5, eq))
}

func TestFold(t *testing.T) {
	t.Parallel()
	result := sliceutils.Fold(func(acc int, x int) int {
		return acc + x
	}, 0, 1, 2, 3, 4)
	require.Equal(t, 10, result)
}

func TestFoldOrError(t *testing.T) {
	t.Parallel()
	// Test successful fold
	result, err := sliceutils.FoldOrError(func(acc int, x int) (int, error) {
		return acc + x, nil
	}, 0, 1, 2, 3, 4)
	require.NoError(t, err)
	require.Equal(t, 10, result)

	// Test with error
	_, err = sliceutils.FoldOrError(func(acc int, x int) (int, error) {
		if x == 3 {
			return 0, errors.New("error at 3")
		}
		return acc + x, nil
	}, 0, 1, 2, 3, 4)
	require.Error(t, err)

	// Test with empty slice
	result, err = sliceutils.FoldOrError(func(acc int, x int) (int, error) {
		return acc + x, nil
	}, 42)
	require.NoError(t, err)
	require.Equal(t, 42, result)
}

func TestFill(t *testing.T) {
	t.Parallel()
	slice := make([]int, 5)
	sliceutils.Fill(slice, 42)
	require.Equal(t, []int{42, 42, 42, 42, 42}, slice)
}
