package mat_test

import (
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
	clone.AddMut(clone)
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

	t.Run("center", func(t *testing.T) {
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

// --- Serialization ---

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
