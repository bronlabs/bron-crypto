package saferith_utils_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

func Test_NatJacobi(t *testing.T) {
	t.Parallel()
	// stolen from wikipedia
	data := [][]int{
		/*  1 */ {1},
		/*  3 */ {0, 1, -1},
		/*  5 */ {0, 1, -1, -1, 1},
		/*  7 */ {0, 1, 1, -1, 1, -1, -1},
		/*  9 */ {0, 1, 1, 0, 1, 1, 0, 1, 1},
		/* 11 */ {0, 1, -1, 1, 1, 1, -1, -1, -1, 1, -1},
		/* 13 */ {0, 1, -1, 1, 1, -1, -1, -1, -1, 1, 1, -1, 1},
		/* 15 */ {0, 1, 1, 0, 1, 0, 0, -1, 1, 0, 0, -1, 0, -1, -1},
		/* 17 */ {0, 1, 1, -1, 1, -1, -1, -1, 1, 1, -1, -1, -1, 1, -1, 1, 1},
	}

	for n := uint64(1); n < 18; n = n + 2 {
		for k := uint64(0); k <= 16 && k < n; k++ {
			a := new(saferith.Nat).SetUint64(k)
			b := new(saferith.Nat).SetUint64(n)
			j, err := saferithUtils.NatJacobi(a, b)
			require.NoError(t, err)

			expected := data[n/2][k]
			require.Equal(t, expected, j)
		}
	}
}
