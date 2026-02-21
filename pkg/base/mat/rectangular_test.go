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
		require.Len(t, row, 3)
		for j, want := range []uint64{1, 2, 3} {
			require.True(t, row[j].Equal(scalar(want)))
		}
	})

	t.Run("GetColumn", func(t *testing.T) {
		t.Parallel()
		col, err := m.GetColumn(1)
		require.NoError(t, err)
		require.Len(t, col, 2)
		require.True(t, col[0].Equal(scalar(2)))
		require.True(t, col[1].Equal(scalar(5)))
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

// --- Spans / RowSpans ---

func TestMatrixSpans(t *testing.T) {
	t.Parallel()

	t.Run("square_unique", func(t *testing.T) {
		t.Parallel()
		// M = [[1,2],[3,4]], b = [5,11] → x = [1,2] since 1*1+2*2=5, 1*3+2*4=11
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := []S{scalar(5), scalar(11)}
		sol, err := m.Spans(b)
		require.NoError(t, err)
		// Verify M*x = b
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		for i, want := range b {
			v, _ := product.Get(i, 0)
			require.True(t, v.Equal(want), "row %d", i)
		}
	})

	t.Run("overdetermined_consistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[0,1],[1,1]], b = [3,4,7] → x = [3,4]
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
		b := []S{scalar(3), scalar(4), scalar(7)}
		sol, err := m.Spans(b)
		require.NoError(t, err)
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		for i, want := range b {
			v, _ := product.Get(i, 0)
			require.True(t, v.Equal(want), "row %d", i)
		}
	})

	t.Run("overdetermined_inconsistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[0,1],[1,1]], b = [3,4,8] → inconsistent (3+4 != 8)
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {1, 1}})
		b := []S{scalar(3), scalar(4), scalar(8)}
		_, err := m.Spans(b)
		require.Error(t, err)
	})

	t.Run("underdetermined", func(t *testing.T) {
		t.Parallel()
		// M = [[1,2,3]], b = [6] → many solutions, free vars set to 0 → x = [6,0,0]
		m := newMatrix(t, [][]uint64{{1, 2, 3}})
		b := []S{scalar(6)}
		sol, err := m.Spans(b)
		require.NoError(t, err)
		// Verify M*x = b
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		v, _ := product.Get(0, 0)
		require.True(t, v.Equal(scalar(6)))
	})

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		// I*x = b → x = b
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
		b := []S{scalar(7), scalar(13)}
		sol, err := m.Spans(b)
		require.NoError(t, err)
		v0, _ := sol.Get(0, 0)
		v1, _ := sol.Get(1, 0)
		require.True(t, v0.Equal(scalar(7)))
		require.True(t, v1.Equal(scalar(13)))
	})

	t.Run("wrong_column_length", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		_, err := m.Spans([]S{scalar(1)})
		require.Error(t, err)
	})

	t.Run("needs_row_swap", func(t *testing.T) {
		t.Parallel()
		// M = [[0,1],[2,3]], b = [5,11] → needs pivot swap
		m := newMatrix(t, [][]uint64{{0, 1}, {2, 3}})
		b := []S{scalar(5), scalar(11)}
		sol, err := m.Spans(b)
		require.NoError(t, err)
		product, err := m.TryMul(sol)
		require.NoError(t, err)
		for i, want := range b {
			v, _ := product.Get(i, 0)
			require.True(t, v.Equal(want), "row %d", i)
		}
	})
}

func TestMatrixRowSpans(t *testing.T) {
	t.Parallel()

	t.Run("square_unique", func(t *testing.T) {
		t.Parallel()
		// M = [[1,3],[2,4]], r = [5,11] → solve x*M = r
		m := newMatrix(t, [][]uint64{{1, 3}, {2, 4}})
		r := []S{scalar(5), scalar(11)}
		sol, err := m.RowSpans(r)
		require.NoError(t, err)
		// Verify x*M = r: sol^T * M should give r
		mt := m.Transpose()
		product, err := mt.TryMul(sol)
		require.NoError(t, err)
		for i, want := range r {
			v, _ := product.Get(i, 0)
			require.True(t, v.Equal(want), "col %d", i)
		}
	})

	t.Run("inconsistent", func(t *testing.T) {
		t.Parallel()
		// M = [[1,0],[0,1],[0,0]], r = [0,0,1] → row [0,0,1] not in row span
		m := newMatrix(t, [][]uint64{{1, 0}, {0, 1}, {0, 0}})
		r := []S{scalar(0), scalar(0), scalar(1)}
		_, err := m.RowSpans(r)
		require.Error(t, err)
	})

	t.Run("wrong_row_length", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		_, err := m.RowSpans([]S{scalar(1)})
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
