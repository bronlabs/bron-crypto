package mat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

func newAlgebra(t *testing.T, n uint) *mat.MatrixAlgebra[S] {
	t.Helper()
	alg, err := mat.NewMatrixAlgebra(n, testRing())
	require.NoError(t, err)
	return alg
}

func newSquare(t *testing.T, rows [][]uint64) *mat.SquareMatrix[S] {
	t.Helper()
	sr := scalarRows(rows)
	alg := newAlgebra(t, uint(len(rows)))
	m, err := alg.New(sr)
	require.NoError(t, err)
	return m
}

func identity(t *testing.T, n uint) *mat.SquareMatrix[S] {
	t.Helper()
	return newAlgebra(t, n).Identity()
}

// --- Algebra constructor ---

func TestMatrixAlgebraConstructor(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		alg := newAlgebra(t, 3)
		require.Equal(t, 3, alg.N())
	})

	t.Run("zero_size", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewMatrixAlgebra(0, testRing())
		require.Error(t, err)
	})
}

// --- Identity ---

func TestSquareIdentity(t *testing.T) {
	t.Parallel()

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		id := identity(t, 3)
		for i := range 3 {
			for j := range 3 {
				v, err := id.Get(i, j)
				require.NoError(t, err)
				if i == j {
					require.True(t, v.Equal(scalar(1)), "diagonal (%d,%d)", i, j)
				} else {
					require.True(t, v.IsZero(), "off-diagonal (%d,%d)", i, j)
				}
			}
		}
	})

	t.Run("One_equals_Identity", func(t *testing.T) {
		t.Parallel()
		alg := newAlgebra(t, 2)
		require.True(t, alg.One().Equal(alg.Identity()))
	})
}

func TestSquareIsIdentity(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		t.Parallel()
		require.True(t, identity(t, 3).IsIdentity())
		require.True(t, identity(t, 2).IsOne())
	})

	t.Run("false_general", func(t *testing.T) {
		t.Parallel()
		require.False(t, newSquare(t, [][]uint64{{1, 2}, {3, 4}}).IsIdentity())
	})

	t.Run("false_first_column_ones", func(t *testing.T) {
		t.Parallel()
		// Catches the old i%n==0 bug that would select first column instead of diagonal.
		m := newSquare(t, [][]uint64{{1, 0, 0}, {1, 0, 0}, {1, 0, 0}})
		require.False(t, m.IsIdentity())
	})
}

// --- Arithmetic ---

func TestSquareAdd(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	b := newSquare(t, [][]uint64{{10, 20}, {30, 40}})
	require.True(t, a.Add(b).Equal(newSquare(t, [][]uint64{{11, 22}, {33, 44}})))
}

func TestSquareSub(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	b := newSquare(t, [][]uint64{{10, 20}, {30, 40}})
	require.True(t, a.Add(b).Sub(b).Equal(a))
}

func TestSquareNeg(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.Add(a.Neg()).IsZero())
}

func TestSquareDouble(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.Double().Equal(newSquare(t, [][]uint64{{2, 4}, {6, 8}})))
}

func TestSquareScalarMul(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.ScalarMul(scalar(5)).Equal(newSquare(t, [][]uint64{{5, 10}, {15, 20}})))
}

// --- Multiplication ---

func TestSquareMul(t *testing.T) {
	t.Parallel()

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		b := newSquare(t, [][]uint64{{5, 6}, {7, 8}})
		// [1*5+2*7, 1*6+2*8] = [19, 22]
		// [3*5+4*7, 3*6+4*8] = [43, 50]
		require.True(t, a.Mul(b).Equal(newSquare(t, [][]uint64{{19, 22}, {43, 50}})))
	})

	t.Run("identity_left", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{3, 4}, {5, 6}})
		require.True(t, identity(t, 2).Mul(a).Equal(a))
	})

	t.Run("identity_right", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{3, 4}, {5, 6}})
		require.True(t, a.Mul(identity(t, 2)).Equal(a))
	})

	t.Run("Square", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		require.True(t, a.Square().Equal(a.Mul(a)))
	})
}

// --- Trace ---

func TestSquareTrace(t *testing.T) {
	t.Parallel()

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		require.True(t, newSquare(t, [][]uint64{{1, 2}, {3, 4}}).Trace().Equal(scalar(5)))
	})

	t.Run("3x3_diagonal", func(t *testing.T) {
		t.Parallel()
		require.True(t, newSquare(t, [][]uint64{{10, 0, 0}, {0, 20, 0}, {0, 0, 30}}).Trace().Equal(scalar(60)))
	})

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		require.True(t, identity(t, 3).Trace().Equal(scalar(3)))
	})
}

// --- Determinant ---

func TestSquareDeterminant(t *testing.T) {
	t.Parallel()

	t.Run("1x1", func(t *testing.T) {
		t.Parallel()
		require.True(t, newSquare(t, [][]uint64{{7}}).Determinant().Equal(scalar(7)))
	})

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		// det = 1*4 - 2*3 = -2 mod q
		require.True(t, m.Determinant().Equal(scalar(4).Sub(scalar(6))))
	})

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2, 3}, {0, 4, 5}, {1, 0, 6}})
		require.True(t, m.Determinant().Equal(scalar(22)))
	})

	t.Run("needs_row_swap", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{0, 1}, {2, 3}})
		// det = 0*3 - 1*2 = -2 mod q
		require.True(t, m.Determinant().Equal(scalar(0).Sub(scalar(2))))
	})

	t.Run("singular", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2, 3}, {2, 4, 6}, {7, 8, 9}})
		require.True(t, m.Determinant().IsZero())
	})

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		require.True(t, identity(t, 3).Determinant().Equal(scalar(1)))
	})
}

// --- Inverse ---

func TestSquareTryInv(t *testing.T) {
	t.Parallel()

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.True(t, a.Mul(inv).IsIdentity())
		require.True(t, inv.Mul(a).IsIdentity())
	})

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2, 3}, {0, 4, 5}, {1, 0, 6}})
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.True(t, a.Mul(inv).IsIdentity())
		require.True(t, inv.Mul(a).IsIdentity())
	})

	t.Run("singular", func(t *testing.T) {
		t.Parallel()
		_, err := newSquare(t, [][]uint64{{1, 2, 3}, {2, 4, 6}, {7, 8, 9}}).TryInv()
		require.Error(t, err)
	})

	t.Run("needs_row_swap", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{0, 1}, {2, 3}})
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.True(t, a.Mul(inv).IsIdentity())
	})
}

// --- Division ---

func TestSquareTryDiv(t *testing.T) {
	t.Parallel()

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		b := newSquare(t, [][]uint64{{2, 1}, {1, 1}})
		got, err := a.TryDiv(b)
		require.NoError(t, err)
		// (a / b) * b = a
		require.True(t, got.Mul(b).Equal(a))
	})

	t.Run("singular_divisor", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		sing := newSquare(t, [][]uint64{{1, 2}, {2, 4}})
		_, err := a.TryDiv(sing)
		require.Error(t, err)
	})
}

// --- Transpose ---

func TestSquareTranspose(t *testing.T) {
	t.Parallel()
	m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, m.Transpose().Equal(newSquare(t, [][]uint64{{1, 3}, {2, 4}})))
	// (A^T)^T = A
	require.True(t, m.Transpose().Transpose().Equal(m))
}

// --- Row / column ops on square ---

func TestSquareSwapRow(t *testing.T) {
	t.Parallel()
	m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.SwapRow(0, 1)
	require.NoError(t, err)
	require.True(t, got.Equal(newSquare(t, [][]uint64{{3, 4}, {1, 2}})))
}

func TestSquareSwapColumn(t *testing.T) {
	t.Parallel()
	m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.SwapColumn(0, 1)
	require.NoError(t, err)
	require.True(t, got.Equal(newSquare(t, [][]uint64{{2, 1}, {4, 3}})))
}
