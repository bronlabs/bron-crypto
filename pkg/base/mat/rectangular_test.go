package mat_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

type S = *k256.Scalar

func testRing() *k256.ScalarField { return k256.NewScalarField() }

func scalar(v uint64) S { return testRing().FromUint64(v) }

func scalarRows(rows [][]uint64) [][]S {
	out := make([][]S, len(rows))
	for i, row := range rows {
		out[i] = make([]S, len(row))
		for j, v := range row {
			out[i][j] = scalar(v)
		}
	}
	return out
}

func newModule(t *testing.T, rows, cols uint) *mat.MatrixModule[S] {
	t.Helper()
	mod, err := mat.NewMatrixModule(rows, cols, testRing())
	require.NoError(t, err)
	return mod
}

func newMatrix(t *testing.T, rows [][]uint64) *mat.Matrix[S] {
	t.Helper()
	sr := scalarRows(rows)
	mod := newModule(t, uint(len(rows)), uint(len(rows[0])))
	m, err := mod.New(sr)
	require.NoError(t, err)
	return m
}

func columnVector(t *testing.T, vals ...uint64) *mat.Matrix[S] {
	t.Helper()
	rows := make([][]uint64, len(vals))
	for i, v := range vals {
		rows[i] = []uint64{v}
	}
	return newMatrix(t, rows)
}

func rowVector(t *testing.T, vals ...uint64) *mat.Matrix[S] {
	t.Helper()
	return newMatrix(t, [][]uint64{vals})
}

// --- Module / constructor tests ---

func TestMatrixModuleConstructor(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		mod := newModule(t, 2, 3)
		r, c := mod.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})

	t.Run("zero_rows", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewMatrixModule(0, 3, testRing())
		require.Error(t, err)
	})

	t.Run("nil_ring", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewMatrixModule[S](1, 1, nil)
		require.Error(t, err)
	})
}

func TestMatrixModuleProperties(t *testing.T) {
	t.Parallel()
	mod := newModule(t, 2, 3)

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		require.Contains(t, mod.Name(), "2x3")
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		require.False(t, mod.IsSquare())
		require.True(t, newModule(t, 3, 3).IsSquare())
	})

	t.Run("Zero_is_OpIdentity", func(t *testing.T) {
		t.Parallel()
		z := mod.Zero()
		require.True(t, z.IsZero())
		require.True(t, z.Equal(mod.OpIdentity()))
		r, c := z.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})
}

func TestMatrixRandom(t *testing.T) {
	t.Parallel()
	mod := newModule(t, 3, 3)
	m, err := mod.Random(crand.Reader)
	require.NoError(t, err)
	r, c := m.Dimensions()
	require.Equal(t, 3, r)
	require.Equal(t, 3, c)

	// Not all elements should be equal (overwhelmingly unlikely for a 256-bit field).
	first, _ := m.Get(0, 0)
	allSame := true
	for i := range 3 {
		for j := range 3 {
			if i == 0 && j == 0 {
				continue
			}
			v, _ := m.Get(i, j)
			if !v.Equal(first) {
				allSame = false
			}
		}
	}
	require.False(t, allSame, "all elements are identical — random generation is broken")
}

func TestMatrixHash(t *testing.T) {
	t.Parallel()
	mod := newModule(t, 2, 2)
	m, err := mod.Hash([]byte("test input"))
	require.NoError(t, err)
	r, c := m.Dimensions()
	require.Equal(t, 2, r)
	require.Equal(t, 2, c)

	// Each element should be different (each uses a different index in the hash).
	elems := make([]S, 4)
	for i := range 2 {
		for j := range 2 {
			elems[i*2+j], _ = m.Get(i, j)
		}
	}
	for i := range elems {
		for j := i + 1; j < len(elems); j++ {
			require.False(t, elems[i].Equal(elems[j]),
				"elements (%d) and (%d) are equal — hash domain separation is broken", i, j)
		}
	}

	// Deterministic: same input produces same output.
	m2, err := mod.Hash([]byte("test input"))
	require.NoError(t, err)
	require.True(t, m.Equal(m2))

	// Different input produces different output.
	m3, err := mod.Hash([]byte("different input"))
	require.NoError(t, err)
	require.False(t, m.Equal(m3))
}

func TestMatrixNewRowMajor(t *testing.T) {
	t.Parallel()
	mod := newModule(t, 2, 3)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		m, err := mod.NewRowMajor(scalar(1), scalar(2), scalar(3), scalar(4), scalar(5), scalar(6))
		require.NoError(t, err)
		require.True(t, m.Equal(newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})))
	})

	t.Run("wrong_count", func(t *testing.T) {
		t.Parallel()
		_, err := mod.NewRowMajor(scalar(1), scalar(2))
		require.Error(t, err)
	})
}

// --- Arithmetic ---

func TestMatrixAdd(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	b := newMatrix(t, [][]uint64{{10, 20, 30}, {40, 50, 60}})

	got := a.Add(b)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{11, 22, 33}, {44, 55, 66}})))
	// original unchanged
	require.True(t, a.Equal(newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})))
}

func TestMatrixSub(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{11, 22}, {33, 44}})
	b := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.Sub(b).Equal(newMatrix(t, [][]uint64{{10, 20}, {30, 40}})))
	// A + B - B = A
	require.True(t, a.Add(b).Sub(b).Equal(a))
}

func TestMatrixNeg(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.Add(a.Neg()).IsZero())
}

func TestMatrixDouble(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	require.True(t, a.Double().Equal(newMatrix(t, [][]uint64{{2, 4, 6}, {8, 10, 12}})))
}

func TestMatrixScalarMul(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	require.True(t, a.ScalarMul(scalar(3)).Equal(newMatrix(t, [][]uint64{{3, 6}, {9, 12}})))
}

// --- Predicates ---

func TestMatrixPredicates(t *testing.T) {
	t.Parallel()

	t.Run("IsZero", func(t *testing.T) {
		t.Parallel()
		require.True(t, newModule(t, 2, 2).Zero().IsZero())
		require.False(t, newMatrix(t, [][]uint64{{0, 1}, {0, 0}}).IsZero())
	})

	t.Run("IsDiagonal", func(t *testing.T) {
		t.Parallel()
		require.True(t, newMatrix(t, [][]uint64{{5, 0}, {0, 3}}).IsDiagonal())
		require.False(t, newMatrix(t, [][]uint64{{5, 1}, {0, 3}}).IsDiagonal())
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		require.True(t, newMatrix(t, [][]uint64{{1, 2}, {3, 4}}).IsSquare())
		require.False(t, newMatrix(t, [][]uint64{{1, 2, 3}}).IsSquare())
	})
}

// --- Vector predicates ---

func TestMatrixIsColumnVector(t *testing.T) {
	t.Parallel()
	require.True(t, newMatrix(t, [][]uint64{{1}, {2}, {3}}).IsColumnVector())
	require.True(t, newMatrix(t, [][]uint64{{7}}).IsColumnVector())
	require.False(t, newMatrix(t, [][]uint64{{1, 2}}).IsColumnVector())
	require.False(t, newMatrix(t, [][]uint64{{1, 2}, {3, 4}}).IsColumnVector())
}

func TestMatrixIsRowVector(t *testing.T) {
	t.Parallel()
	require.True(t, newMatrix(t, [][]uint64{{1, 2, 3}}).IsRowVector())
	require.True(t, newMatrix(t, [][]uint64{{7}}).IsRowVector())
	require.False(t, newMatrix(t, [][]uint64{{1}, {2}}).IsRowVector())
	require.False(t, newMatrix(t, [][]uint64{{1, 2}, {3, 4}}).IsRowVector())
}

// --- Dot product ---

func TestMatrixDotProduct(t *testing.T) {
	t.Parallel()

	t.Run("row_dot_column", func(t *testing.T) {
		t.Parallel()
		row := newMatrix(t, [][]uint64{{1, 2, 3}})
		col := newMatrix(t, [][]uint64{{4}, {5}, {6}})
		// 1*4 + 2*5 + 3*6 = 32
		got, err := row.DotProduct(col)
		require.NoError(t, err)
		require.True(t, got.Equal(scalar(32)))
	})

	t.Run("column_dot_column", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1}, {2}, {3}})
		b := newMatrix(t, [][]uint64{{4}, {5}, {6}})
		got, err := a.DotProduct(b)
		require.NoError(t, err)
		require.True(t, got.Equal(scalar(32)))
	})

	t.Run("row_dot_row", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2, 3}})
		b := newMatrix(t, [][]uint64{{4, 5, 6}})
		got, err := a.DotProduct(b)
		require.NoError(t, err)
		require.True(t, got.Equal(scalar(32)))
	})

	t.Run("column_dot_row", func(t *testing.T) {
		t.Parallel()
		col := newMatrix(t, [][]uint64{{1}, {2}, {3}})
		row := newMatrix(t, [][]uint64{{4, 5, 6}})
		got, err := col.DotProduct(row)
		require.NoError(t, err)
		require.True(t, got.Equal(scalar(32)))
	})

	t.Run("length_1", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{7}})
		b := newMatrix(t, [][]uint64{{3}})
		got, err := a.DotProduct(b)
		require.NoError(t, err)
		require.True(t, got.Equal(scalar(21)))
	})

	t.Run("orthogonal_is_zero", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 0}})
		b := newMatrix(t, [][]uint64{{0}, {1}})
		got, err := a.DotProduct(b)
		require.NoError(t, err)
		require.True(t, got.IsZero())
	})

	t.Run("incompatible_lengths", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2, 3}})
		b := newMatrix(t, [][]uint64{{4, 5}})
		_, err := a.DotProduct(b)
		require.Error(t, err)
	})

	t.Run("not_a_vector", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newMatrix(t, [][]uint64{{5}, {6}})
		_, err := a.DotProduct(b)
		require.Error(t, err)
	})

	t.Run("both_not_vectors", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newMatrix(t, [][]uint64{{5, 6}, {7, 8}})
		_, err := a.DotProduct(b)
		require.Error(t, err)
	})
}

// --- Element access ---

func TestMatrixGet(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	v, err := m.Get(1, 2)
	require.NoError(t, err)
	require.True(t, v.Equal(scalar(6)))

	_, err = m.Get(2, 0)
	require.Error(t, err)
}

func TestMatrixGetRowColumn(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("GetRow", func(t *testing.T) {
		t.Parallel()
		row, err := m.GetRow(0)
		require.NoError(t, err)
		r, c := row.Dimensions()
		require.Equal(t, 1, r)
		require.Equal(t, 3, c)
		require.True(t, row.Equal(newMatrix(t, [][]uint64{{1, 2, 3}})))
	})

	t.Run("GetColumn", func(t *testing.T) {
		t.Parallel()
		col, err := m.GetColumn(1)
		require.NoError(t, err)
		r, c := col.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 1, c)
		require.True(t, col.Equal(newMatrix(t, [][]uint64{{2}, {5}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.GetRow(-1)
		require.Error(t, err)
		_, err = m.GetColumn(3)
		require.Error(t, err)
	})
}

// --- Clone / Equal ---

func TestMatrixClone(t *testing.T) {
	t.Parallel()
	orig := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	clone := orig.Clone()
	clone.AddAssign(clone)
	// original unchanged
	require.True(t, orig.Equal(newMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
}

func TestMatrixEqual(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}})
	b := newMatrix(t, [][]uint64{{1}, {2}})
	require.False(t, a.Equal(b))
	require.True(t, a.Equal(newMatrix(t, [][]uint64{{1, 2}})))
}

// --- Transpose ---

func TestMatrixTranspose(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	got := m.Transpose()
	want := newMatrix(t, [][]uint64{{1, 4}, {2, 5}, {3, 6}})
	require.True(t, got.Equal(want))

	r, c := got.Dimensions()
	require.Equal(t, 3, r)
	require.Equal(t, 2, c)

	// double transpose is identity
	require.True(t, m.Transpose().Transpose().Equal(m))
}

// --- Row / column ops ---

func TestMatrixSwapRow(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})
	got, err := m.SwapRow(0, 2)
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{5, 6}, {3, 4}, {1, 2}})))
	// original unchanged
	require.True(t, m.Equal(newMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})))
}

func TestMatrixSwapColumn(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	got, err := m.SwapColumn(0, 2)
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{3, 2, 1}, {6, 5, 4}})))
}

func TestMatrixRowAdd(t *testing.T) {
	t.Parallel()
	// row0 += 2 * row1 (source=1, dest=0)
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.RowAdd(1, 0, scalar(2))
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{7, 10}, {3, 4}})))
}

func TestMatrixColumnAdd(t *testing.T) {
	t.Parallel()
	// col0 += 2 * col1 (source=1, dest=0)
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.ColumnAdd(1, 0, scalar(2))
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{5, 2}, {11, 4}})))
}

func TestMatrixRowScalarMul(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.RowScalarMul(1, scalar(3))
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2}, {9, 12}})))
}

func TestMatrixColumnScalarMul(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.ColumnScalarMul(0, scalar(5))
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{5, 2}, {15, 4}})))
}

func TestMatrixSwapRowOOB(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}})
	require.Panics(t, func() { _, _ = m.SwapRow(0, 1) })
}

// --- Minor ---

func TestMatrixMinor(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})

	t.Run("centre", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(1, 1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 3}, {7, 9}})))
	})

	t.Run("corner", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(0, 0)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{5, 6}, {8, 9}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.Minor(3, 0)
		require.Error(t, err)
	})
}

// --- Concatenation ---

func TestMatrixAugment(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMatrix(t, [][]uint64{{5}, {6}})
	got, err := a.Augment(b)
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2, 5}, {3, 4, 6}})))
}

func TestMatrixStack(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2, 3}})
	b := newMatrix(t, [][]uint64{{4, 5, 6}, {7, 8, 9}})
	got, err := a.Stack(b)
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})))
}

func TestMatrixAugmentDimensionMismatch(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}})
	b := newMatrix(t, [][]uint64{{3, 4}, {5, 6}})
	_, err := a.Augment(b)
	require.Error(t, err)
}

// --- Hadamard ---

func TestMatrixHadamardProduct(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMatrix(t, [][]uint64{{5, 6}, {7, 8}})
	got, err := a.HadamardProduct(b)
	require.NoError(t, err)
	require.True(t, got.Equal(newMatrix(t, [][]uint64{{5, 12}, {21, 32}})))
}

// --- Multiplication ---

func TestMatrixMultiply(t *testing.T) {
	t.Parallel()

	t.Run("2x3_times_3x2", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		b := newMatrix(t, [][]uint64{{7, 8}, {9, 10}, {11, 12}})
		got, err := a.TryMul(b)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{58, 64}, {139, 154}})))
	})

	t.Run("dimension_mismatch", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2}})
		b := newMatrix(t, [][]uint64{{3, 4}})
		_, err := a.TryMul(b)
		require.Error(t, err)
	})

	t.Run("identity_left", func(t *testing.T) {
		t.Parallel()
		id := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
		a := newMatrix(t, [][]uint64{{3, 4}, {5, 6}})
		got, err := id.TryMul(a)
		require.NoError(t, err)
		require.True(t, got.Equal(a))
	})

	t.Run("1x1", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{7}})
		b := newMatrix(t, [][]uint64{{3}})
		got, err := a.TryMul(b)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{21}})))
	})
}

// --- SolveRight / SolveLeft ---

func TestMatrixSolveRight(t *testing.T) {
	t.Parallel()

	t.Run("square_unique", func(t *testing.T) {
		t.Parallel()
		// M = [[1,2],[3,4]], b = [5,11] → x = [1,2] since 1*1+2*2=5, 1*3+2*4=11
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := columnVector(t, 5, 11)
		sol, err := mat.SolveRight(m, b)
		require.NoError(t, err)
		// Verify M*x = b
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		require.True(t, product.Equal(b))
	})

	t.Run("overdetermined_consistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[0,1],[1,1]], b = [3,4,7] → x = [3,4]
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
		b := columnVector(t, 3, 4, 7)
		sol, err := mat.SolveRight(m, b)
		require.NoError(t, err)
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		require.True(t, product.Equal(b))
	})

	t.Run("overdetermined_inconsistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[0,1],[1,1]], b = [3,4,8] → inconsistent (3+4 != 8)
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
		b := columnVector(t, 3, 4, 8)
		_, err := mat.SolveRight(m, b)
		require.Error(t, err)
	})

	t.Run("underdetermined", func(t *testing.T) {
		t.Parallel()
		// M = [[1,2,3]], b = [6] → many solutions, free vars set to 0 → x = [6,0,0]
		m := newMatrix(t, [][]uint64{{1, 2, 3}})
		b := columnVector(t, 6)
		sol, err := mat.SolveRight(m, b)
		require.NoError(t, err)
		// Verify M*x = b
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		require.True(t, product.Equal(b))
	})

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		// I*x = b → x = b
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
		b := columnVector(t, 7, 13)
		sol, err := mat.SolveRight(m, b)
		require.NoError(t, err)
		require.True(t, sol.Equal(b))
	})

	t.Run("wrong_column_length", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		_, err := mat.SolveRight(m, columnVector(t, 1))
		require.Error(t, err)
	})

	t.Run("needs_row_swap", func(t *testing.T) {
		t.Parallel()
		// M = [[0,1],[2,3]], b = [5,11] → needs pivot swap
		m := newMatrix(t, [][]uint64{{0, 1}, {2, 3}})
		b := columnVector(t, 5, 11)
		sol, err := mat.SolveRight(m, b)
		require.NoError(t, err)
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		require.True(t, product.Equal(b))
	})
}

func TestMatrixSolveLeft(t *testing.T) {
	t.Parallel()

	t.Run("square_unique", func(t *testing.T) {
		t.Parallel()
		// M = [[1,3],[2,4]], r = [5,11] → solve x*M = r
		m := newMatrix(t, [][]uint64{{1, 3}, {2, 4}})
		r := rowVector(t, 5, 11)
		sol, err := mat.SolveLeft(m, r)
		require.NoError(t, err)
		// Verify x*M = r: M^T * x = r^T
		mt := m.Transpose()
		product, err := mt.TryMul(sol)
		require.NoError(t, err)
		require.True(t, product.Equal(r.Transpose()))
	})

	t.Run("inconsistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[1,0]], row span = {[a,0]} → r = [0,1] not in row span
		m := newMatrix(t, [][]uint64{{1, 0}, {1, 0}})
		r := rowVector(t, 0, 1)
		_, err := mat.SolveLeft(m, r)
		require.Error(t, err)
	})

	t.Run("wrong_row_length", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		_, err := mat.SolveLeft(m, rowVector(t, 1))
		require.Error(t, err)
	})
}

// --- String / HashCode ---

func TestMatrixString(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	s := m.String()
	require.Contains(t, s, "[")
	require.Contains(t, s, "]")
}

func TestMatrixHashCode(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	c := newMatrix(t, [][]uint64{{5, 6}, {7, 8}})
	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

// --- SubMatrix / Slice ---

func TestMatrixSubMatrixGivenRows(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})

	t.Run("single_row", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{4, 5, 6}})))
	})

	t.Run("multiple_rows", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2, 3}, {7, 8, 9}})))
	})

	t.Run("reversed_order", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(2, 0)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{7, 8, 9}, {1, 2, 3}})))
	})

	t.Run("all_rows", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(0, 1, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(m))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenRows(3)
		require.Error(t, err)
	})

	t.Run("negative_index", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenRows(-1)
		require.Error(t, err)
	})
}

func TestMatrixSubMatrixGivenColumns(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("single_column", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{2}, {5}})))
	})

	t.Run("multiple_columns", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 3}, {4, 6}})))
	})

	t.Run("reversed_order", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(2, 0)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{3, 1}, {6, 4}})))
	})

	t.Run("all_columns", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(0, 1, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(m))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenColumns(3)
		require.Error(t, err)
	})

	t.Run("negative_index", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenColumns(-1)
		require.Error(t, err)
	})
}

func TestMatrixRowSlice(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}})

	t.Run("first_two", func(t *testing.T) {
		t.Parallel()
		got, err := m.RowSlice(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})))
	})

	t.Run("middle", func(t *testing.T) {
		t.Parallel()
		got, err := m.RowSlice(1, 3)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{4, 5, 6}, {7, 8, 9}})))
	})

	t.Run("last_row", func(t *testing.T) {
		t.Parallel()
		got, err := m.RowSlice(3, 4)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{10, 11, 12}})))
	})

	t.Run("all_rows", func(t *testing.T) {
		t.Parallel()
		got, err := m.RowSlice(0, 4)
		require.NoError(t, err)
		require.True(t, got.Equal(m))
	})

	t.Run("start_equals_end", func(t *testing.T) {
		t.Parallel()
		_, err := m.RowSlice(2, 2)
		require.Error(t, err)
	})

	t.Run("start_greater_than_end", func(t *testing.T) {
		t.Parallel()
		_, err := m.RowSlice(3, 1)
		require.Error(t, err)
	})

	t.Run("end_exceeds_rows", func(t *testing.T) {
		t.Parallel()
		_, err := m.RowSlice(0, 5)
		require.Error(t, err)
	})

	t.Run("negative_start", func(t *testing.T) {
		t.Parallel()
		_, err := m.RowSlice(-1, 2)
		require.Error(t, err)
	})
}

func TestMatrixColumnSlice(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3, 4}, {5, 6, 7, 8}})

	t.Run("first_two", func(t *testing.T) {
		t.Parallel()
		got, err := m.ColumnSlice(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{1, 2}, {5, 6}})))
	})

	t.Run("middle", func(t *testing.T) {
		t.Parallel()
		got, err := m.ColumnSlice(1, 3)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{2, 3}, {6, 7}})))
	})

	t.Run("last_column", func(t *testing.T) {
		t.Parallel()
		got, err := m.ColumnSlice(3, 4)
		require.NoError(t, err)
		require.True(t, got.Equal(newMatrix(t, [][]uint64{{4}, {8}})))
	})

	t.Run("all_columns", func(t *testing.T) {
		t.Parallel()
		got, err := m.ColumnSlice(0, 4)
		require.NoError(t, err)
		require.True(t, got.Equal(m))
	})

	t.Run("start_equals_end", func(t *testing.T) {
		t.Parallel()
		_, err := m.ColumnSlice(2, 2)
		require.Error(t, err)
	})

	t.Run("start_greater_than_end", func(t *testing.T) {
		t.Parallel()
		_, err := m.ColumnSlice(3, 1)
		require.Error(t, err)
	})

	t.Run("end_exceeds_cols", func(t *testing.T) {
		t.Parallel()
		_, err := m.ColumnSlice(0, 5)
		require.Error(t, err)
	})

	t.Run("negative_start", func(t *testing.T) {
		t.Parallel()
		_, err := m.ColumnSlice(-1, 2)
		require.Error(t, err)
	})
}

// --- Iterators ---

func TestMatrixIterRows(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("yields_all_rows", func(t *testing.T) {
		t.Parallel()
		var rows []*mat.Matrix[S]
		for row := range m.IterRows() {
			rows = append(rows, row)
		}
		require.Len(t, rows, 2)
		require.True(t, rows[0].Equal(newMatrix(t, [][]uint64{{1, 2, 3}})))
		require.True(t, rows[1].Equal(newMatrix(t, [][]uint64{{4, 5, 6}})))
	})

	t.Run("row_dimensions", func(t *testing.T) {
		t.Parallel()
		for row := range m.IterRows() {
			r, c := row.Dimensions()
			require.Equal(t, 1, r)
			require.Equal(t, 3, c)
		}
	})

	t.Run("rows_are_copies", func(t *testing.T) {
		t.Parallel()
		for row := range m.IterRows() {
			row.ScalarMulAssign(scalar(0))
		}
		// Original unchanged.
		v, _ := m.Get(0, 0)
		require.True(t, v.Equal(scalar(1)))
	})

	t.Run("break_early", func(t *testing.T) {
		t.Parallel()
		count := 0
		for range m.IterRows() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})

	t.Run("single_row", func(t *testing.T) {
		t.Parallel()
		m1 := newMatrix(t, [][]uint64{{7, 8, 9}})
		var rows []*mat.Matrix[S]
		for row := range m1.IterRows() {
			rows = append(rows, row)
		}
		require.Len(t, rows, 1)
		require.True(t, rows[0].Equal(m1))
	})
}

func TestMatrixIterColumns(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("yields_all_columns", func(t *testing.T) {
		t.Parallel()
		var cols []*mat.Matrix[S]
		for col := range m.IterColumns() {
			cols = append(cols, col)
		}
		require.Len(t, cols, 3)
		require.True(t, cols[0].Equal(newMatrix(t, [][]uint64{{1}, {4}})))
		require.True(t, cols[1].Equal(newMatrix(t, [][]uint64{{2}, {5}})))
		require.True(t, cols[2].Equal(newMatrix(t, [][]uint64{{3}, {6}})))
	})

	t.Run("column_dimensions", func(t *testing.T) {
		t.Parallel()
		for col := range m.IterColumns() {
			r, c := col.Dimensions()
			require.Equal(t, 2, r)
			require.Equal(t, 1, c)
		}
	})

	t.Run("columns_are_copies", func(t *testing.T) {
		t.Parallel()
		for col := range m.IterColumns() {
			col.ScalarMulAssign(scalar(0))
		}
		// Original unchanged.
		v, _ := m.Get(0, 0)
		require.True(t, v.Equal(scalar(1)))
	})

	t.Run("break_early", func(t *testing.T) {
		t.Parallel()
		count := 0
		for range m.IterColumns() {
			count++
			break
		}
		require.Equal(t, 1, count)
	})

	t.Run("single_column", func(t *testing.T) {
		t.Parallel()
		m1 := newMatrix(t, [][]uint64{{7}, {8}})
		var cols []*mat.Matrix[S]
		for col := range m1.IterColumns() {
			cols = append(cols, col)
		}
		require.Len(t, cols, 1)
		require.True(t, cols[0].Equal(m1))
	})
}

// --- Serialisation ---

func TestMatrixBytes(t *testing.T) {
	t.Parallel()

	t.Run("roundtrip_2x2", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := newModule(t, 2, 2).FromBytes(m.Bytes())
		require.NoError(t, err)
		require.True(t, m.Equal(got))
	})

	t.Run("roundtrip_1x1", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{42}})
		got, err := newModule(t, 1, 1).FromBytes(m.Bytes())
		require.NoError(t, err)
		require.True(t, m.Equal(got))
	})

	t.Run("wrong_length", func(t *testing.T) {
		t.Parallel()
		_, err := newModule(t, 2, 2).FromBytes([]byte{1, 2, 3})
		require.Error(t, err)
	})
}
