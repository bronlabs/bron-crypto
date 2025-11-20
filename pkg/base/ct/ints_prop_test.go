package ct_test

import (
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestIsZero_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random integer value
		value := rapid.Int().Draw(t, "value")
		// Check if IsZero returns One for zero and Zero otherwise
		drewZero := value == 0
		actual := ct.IsZero(value) == ct.True
		require.Equal(t, drewZero, actual)
	})
}

func TestEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Equal returns One for equal values and Zero otherwise
		expected := x == y
		actual := ct.Equal(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestGreater_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Greater returns One for x > y and Zero otherwise
		expected := x > y
		actual := ct.Greater(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestLess_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if Less returns One for x < y and Zero otherwise
		expected := x < y
		actual := ct.Less(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestLessOrEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if LessOrEqual returns One for x <= y and Zero otherwise
		expected := x <= y
		actual := ct.LessOrEqual(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestGreaterOrEqual_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		// Check if GreaterOrEqual returns One for x >= y and Zero otherwise
		expected := x >= y
		actual := ct.GreaterOrEqual(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestCompareInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate two random integer values
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		agt, aeq, alt := ct.CompareInt(x, y)
		if x > y {
			require.Equal(t, ct.True, agt)
		} else if x == y {
			require.Equal(t, ct.True, aeq)
		} else {
			require.Equal(t, ct.True, alt)
		}
	})
}

func TestCSelectInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random choice and two integer values
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		x0 := rapid.Int().Draw(t, "x0")
		x1 := rapid.Int().Draw(t, "x1")
		// Check if CSelectInt returns x0 when choice is 0 and x1 when choice is 1
		expected := x0
		if choice == ct.True {
			expected = x1
		}
		actual := ct.CSelectInt(choice, x0, x1)
		require.Equal(t, expected, actual)
	})
}

func TestCMOVInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		src := rapid.Int().Draw(t, "src")

		var expected int
		if choice == ct.True {
			expected = src
		}
		var actual int
		ct.CMOVInt(&actual, choice, &src)
		require.Equal(t, expected, actual)
	})
}

func TestCSwapInt_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		choice := ct.Choice(rapid.IntRange(0, 1).Draw(t, "choice"))
		x := rapid.Int().Draw(t, "x")
		y := rapid.Int().Draw(t, "y")
		var expectedX, expectedY int
		if choice == ct.True {
			expectedX = y
			expectedY = x
		} else {
			expectedX = x
			expectedY = y
		}
		var actualX, actualY int = x, y
		ct.CSwapInt(&actualX, &actualY, choice)
		require.Equal(t, expectedX, actualX)
		require.Equal(t, expectedY, actualY)
	})
}

func TestMin_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Int().Draw(t, "a")
		b := rapid.Int().Draw(t, "b")
		expected := min(a, b)
		actual := ct.Min(a, b)
		require.Equal(t, expected, actual)
	})
}

func TestMax_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.Int().Draw(t, "a")
		b := rapid.Int().Draw(t, "b")
		expected := max(a, b)
		actual := ct.Max(a, b)
		require.Equal(t, expected, actual)
	})
}

func TestIsqrt64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.Uint64().Draw(t, "n")
		nBig := new(big.Int).SetUint64(n)
		expectedBig := new(big.Int).Sqrt(nBig)
		expected := expectedBig.Uint64()
		actual := ct.Isqrt64(n)
		require.Equal(t, expected, actual)
	})
}

func TestLessU64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.Uint64().Draw(t, "x")
		y := rapid.Uint64().Draw(t, "y")
		expected := x < y
		actual := ct.LessU64(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}

func TestLessI64_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.Int64().Draw(t, "x")
		y := rapid.Int64().Draw(t, "y")
		expected := x < y
		actual := ct.LessI64(x, y) == ct.True
		require.Equal(t, expected, actual)
	})
}
