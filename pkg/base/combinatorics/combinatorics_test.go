package combinatorics_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/combinatorics"
)

func TestBinomial(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n, k, ans uint
	}{
		{0, 0, 1},
		{5, 0, 1},
		{5, 1, 5},
		{5, 2, 10},
		{5, 3, 10},
		{5, 4, 5},
		{5, 5, 1},

		{6, 0, 1},
		{6, 1, 6},
		{6, 2, 15},
		{6, 3, 20},
		{6, 4, 15},
		{6, 5, 6},
		{6, 6, 1},

		{20, 0, 1},
		{20, 1, 20},
		{20, 2, 190},
		{20, 3, 1140},
		{20, 4, 4845},
		{20, 5, 15504},
		{20, 6, 38760},
		{20, 7, 77520},
		{20, 8, 125970},
		{20, 9, 167960},
		{20, 10, 184756},
		{20, 11, 167960},
		{20, 12, 125970},
		{20, 13, 77520},
		{20, 14, 38760},
		{20, 15, 15504},
		{20, 16, 4845},
		{20, 17, 1140},
		{20, 18, 190},
		{20, 19, 20},
		{20, 20, 1},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("Binomial(%d, %d)", tc.n, tc.k), func(t *testing.T) {
			t.Parallel()
			actual, err := combinatorics.BinomialCoefficient(tc.n, tc.k)
			require.NoError(t, err)
			require.Equal(t, tc.ans, actual)
		})
	}
}

func TestCombinations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n, k uint
		data [][]uint
	}{
		{
			n:    1,
			k:    1,
			data: [][]uint{{0}},
		},
		{
			n:    2,
			k:    1,
			data: [][]uint{{0}, {1}},
		},
		{
			n:    2,
			k:    2,
			data: [][]uint{{0, 1}},
		},
		{
			n:    3,
			k:    1,
			data: [][]uint{{0}, {1}, {2}},
		},
		{
			n:    3,
			k:    2,
			data: [][]uint{{0, 1}, {0, 2}, {1, 2}},
		},
		{
			n:    3,
			k:    3,
			data: [][]uint{{0, 1, 2}},
		},
		{
			n:    4,
			k:    1,
			data: [][]uint{{0}, {1}, {2}, {3}},
		},
		{
			n:    4,
			k:    2,
			data: [][]uint{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}},
		},
		{
			n:    4,
			k:    3,
			data: [][]uint{{0, 1, 2}, {0, 1, 3}, {0, 2, 3}, {1, 2, 3}},
		},
		{
			n:    4,
			k:    4,
			data: [][]uint{{0, 1, 2, 3}},
		},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("combinations for n=%d k=%d", tc.n, tc.k), func(t *testing.T) {
			t.Parallel()
			input := make([]uint, tc.n)
			for i := range tc.n {
				input[i] = i
			}
			actual, err := combinatorics.Combinations(input, tc.k)
			require.NoError(t, err)
			require.EqualValues(t, tc.data, actual)
		})
	}
}

func TestPartialPermutations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n, k uint
		data [][]uint
	}{
		{
			n:    1,
			k:    1,
			data: [][]uint{{0}},
		},
		{
			n:    2,
			k:    1,
			data: [][]uint{{0}, {1}},
		},
		{
			n:    2,
			k:    2,
			data: [][]uint{{0, 1}, {1, 0}},
		},
		{
			n:    3,
			k:    1,
			data: [][]uint{{0}, {1}, {2}},
		},
		{
			n:    3,
			k:    2,
			data: [][]uint{{0, 1}, {0, 2}, {1, 0}, {1, 2}, {2, 0}, {2, 1}},
		},
		{
			n:    3,
			k:    3,
			data: [][]uint{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}},
		},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("partial permutations for n=%d k=%d", tc.n, tc.k), func(t *testing.T) {
			t.Parallel()
			input := make([]uint, tc.n)
			for i := range tc.n {
				input[i] = i
			}
			actual, err := combinatorics.PartialPermutations(input, tc.k)
			require.NoError(t, err)
			require.EqualValues(t, tc.data, actual)
		})
	}
}

func TestPermutations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n    uint
		data [][]uint
	}{
		{
			n:    2,
			data: [][]uint{{0, 1}, {1, 0}},
		},

		{
			n:    3,
			data: [][]uint{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}},
		},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("permutations for n=%d", tc.n), func(t *testing.T) {
			t.Parallel()
			input := make([]uint, tc.n)
			for i := range tc.n {
				input[i] = i
			}
			actual := combinatorics.Permutations(input)
			require.EqualValues(t, tc.data, actual)
		})
	}
}

func TestSubFactorial(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n        uint
		expected uint
	}{
		{
			n:        0,
			expected: 1,
		},
		{
			n:        1,
			expected: 0,
		},
		{
			n:        2,
			expected: 1,
		},
		{
			n:        3,
			expected: 2,
		},
		{
			n:        4,
			expected: 9,
		},
		{
			n:        5,
			expected: 44,
		},
		{
			n:        6,
			expected: 265,
		},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("!%d", tc.n), func(t *testing.T) {
			t.Parallel()
			actual := combinatorics.SubFactorial(tc.n)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestDerangements(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n    uint
		data [][]uint
	}{
		{
			n:    2,
			data: [][]uint{{1, 0}},
		},

		{
			n:    3,
			data: [][]uint{{1, 2, 0}, {2, 0, 1}},
		},
	} {
		tc := testCase
		t.Run(fmt.Sprintf("permutations for n=%d", tc.n), func(t *testing.T) {
			t.Parallel()
			input := make([]uint, tc.n)
			for i := range tc.n {
				input[i] = i
			}
			actual := combinatorics.Deragements(input, func(x, y uint) bool {
				return x == y
			})
			require.EqualValues(t, tc.data, actual)
		})
	}
}

func TestRandomPermutation(t *testing.T) {
	t.Parallel()
	n := 1000
	input := make([]int, n)
	for i := range n {
		input[i] = i
	}
	sampleSize := 5
	samples := make([][]int, sampleSize)
	var err error
	for i := range sampleSize {
		samples[i], err = combinatorics.Shuffle(input, crand.Reader)
		require.NoError(t, err)
	}
	for i, xi := range samples {
		for j, xj := range samples {
			if i == j {
				continue
			}
			require.NotEqualValues(t, xi, xj)
		}
	}
}
