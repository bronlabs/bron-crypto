package sliceutils_test

import (
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/stretchr/testify/require"
	"slices"
	"testing"
)

func TestCombinations(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		n, k uint
		data [][]uint
	}{
		{
			n:    1,
			k:    0,
			data: [][]uint{{}},
		},
		{
			n:    1,
			k:    2,
			data: [][]uint{{}},
		},
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
			actual := slices.Collect(sliceutils.Combinations(input, tc.k))
			require.EqualValues(t, tc.data, actual)
		})
	}
}
