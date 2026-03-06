package mat_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

type P = *k256.Point

func testCurve() *k256.Curve { return k256.NewCurve() }

func generator() P { return testCurve().Generator() }

func point(v uint64) P { return generator().ScalarOp(scalar(v)) }

func pointRows(rows [][]uint64) [][]P {
	out := make([][]P, len(rows))
	for i, row := range rows {
		out[i] = make([]P, len(row))
		for j, v := range row {
			out[i][j] = point(v)
		}
	}
	return out
}

func newMVModule(t *testing.T, rows, cols uint) *mat.ModuleValuedMatrixModule[P, S] {
	t.Helper()
	mod, err := mat.NewModuleValuedMatrixModule(rows, cols, testCurve())
	require.NoError(t, err)
	return mod
}

func newMVMatrix(t *testing.T, rows [][]uint64) *mat.ModuleValuedMatrix[P, S] {
	t.Helper()
	pr := pointRows(rows)
	mod := newMVModule(t, uint(len(rows)), uint(len(rows[0])))
	m, err := mod.New(pr)
	require.NoError(t, err)
	return m
}

// --- Module constructor tests ---

func TestModuleValuedMatrixModuleConstructor(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		mod := newMVModule(t, 2, 3)
		r, c := mod.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})

	t.Run("zero_rows", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewModuleValuedMatrixModule(0, 3, testCurve())
		require.Error(t, err)
	})

	t.Run("zero_cols", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewModuleValuedMatrixModule(3, 0, testCurve())
		require.Error(t, err)
	})

	t.Run("nil_module", func(t *testing.T) {
		t.Parallel()
		_, err := mat.NewModuleValuedMatrixModule[P](1, 1, nil)
		require.Error(t, err)
	})
}

func TestModuleValuedMatrixModuleProperties(t *testing.T) {
	t.Parallel()
	mod := newMVModule(t, 2, 3)

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		require.Contains(t, mod.Name(), "2x3")
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		require.False(t, mod.IsSquare())
		require.True(t, newMVModule(t, 3, 3).IsSquare())
	})

	t.Run("Zero_is_OpIdentity", func(t *testing.T) {
		t.Parallel()
		z := mod.Zero()
		require.True(t, z.IsOpIdentity())
		require.True(t, z.Equal(mod.OpIdentity()))
		r, c := z.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})

	t.Run("ScalarStructure", func(t *testing.T) {
		t.Parallel()
		require.NotNil(t, mod.ScalarStructure())
	})
}

// --- Construction ---

func TestModuleValuedMatrixNewRowMajor(t *testing.T) {
	t.Parallel()
	mod := newMVModule(t, 2, 3)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		m, err := mod.NewRowMajor(point(1), point(2), point(3), point(4), point(5), point(6))
		require.NoError(t, err)
		require.True(t, m.Equal(newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})))
	})

	t.Run("wrong_count", func(t *testing.T) {
		t.Parallel()
		_, err := mod.NewRowMajor(point(1), point(2))
		require.Error(t, err)
	})
}

func TestModuleValuedMatrixNew(t *testing.T) {
	t.Parallel()
	mod := newMVModule(t, 2, 2)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		m, err := mod.New(pointRows([][]uint64{{1, 2}, {3, 4}}))
		require.NoError(t, err)
		require.True(t, m.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
	})

	t.Run("wrong_row_count", func(t *testing.T) {
		t.Parallel()
		_, err := mod.New(pointRows([][]uint64{{1, 2}}))
		require.Error(t, err)
	})

	t.Run("wrong_col_count", func(t *testing.T) {
		t.Parallel()
		_, err := mod.New(pointRows([][]uint64{{1}, {2}}))
		require.Error(t, err)
	})
}

// --- Random / Hash ---

func TestModuleValuedMatrixRandom(t *testing.T) {
	t.Parallel()
	mod := newMVModule(t, 2, 2)
	m, err := mod.Random(crand.Reader)
	require.NoError(t, err)
	r, c := m.Dimensions()
	require.Equal(t, 2, r)
	require.Equal(t, 2, c)
	require.False(t, m.IsOpIdentity(), "random matrix should not be zero")
}

func TestModuleValuedMatrixHash(t *testing.T) {
	t.Parallel()
	mod := newMVModule(t, 2, 2)

	m1, err := mod.Hash([]byte("test input"))
	require.NoError(t, err)
	r, c := m1.Dimensions()
	require.Equal(t, 2, r)
	require.Equal(t, 2, c)

	// Deterministic.
	m2, err := mod.Hash([]byte("test input"))
	require.NoError(t, err)
	require.True(t, m1.Equal(m2))

	// Different input produces different output.
	m3, err := mod.Hash([]byte("different input"))
	require.NoError(t, err)
	require.False(t, m1.Equal(m3))
}

// --- Arithmetic (group operations) ---

func TestModuleValuedMatrixOp(t *testing.T) {
	t.Parallel()
	// Op is point addition element-wise: point(a).Op(point(b)) == point(a+b)
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMVMatrix(t, [][]uint64{{10, 20}, {30, 40}})
	got := a.Op(b)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{11, 22}, {33, 44}})))
	// Original unchanged.
	require.True(t, a.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
}

func TestModuleValuedMatrixOpInv(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	// a + (-a) == zero
	sum := a.Op(a.OpInv())
	require.True(t, sum.IsOpIdentity())
}

func TestModuleValuedMatrixScalarOp(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got := a.ScalarOp(scalar(3))
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{3, 6}, {9, 12}})))
	// Original unchanged.
	require.True(t, a.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
}

func TestModuleValuedMatrixScalarOpAssign(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	a.ScalarOpAssign(scalar(2))
	require.True(t, a.Equal(newMVMatrix(t, [][]uint64{{2, 4}, {6, 8}})))
}

func TestModuleValuedMatrixScalarOpIdentity(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	// Scalar multiply by 1 is identity.
	require.True(t, a.ScalarOp(scalar(1)).Equal(a))
}

func TestModuleValuedMatrixScalarOpZero(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	// Scalar multiply by 0 gives zero matrix.
	require.True(t, a.ScalarOp(scalar(0)).IsOpIdentity())
}

// --- Element access ---

func TestModuleValuedMatrixGet(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	v, err := m.Get(1, 2)
	require.NoError(t, err)
	require.True(t, v.Equal(point(6)))

	_, err = m.Get(2, 0)
	require.Error(t, err)
}

func TestModuleValuedMatrixGetRowColumn(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("GetRow", func(t *testing.T) {
		t.Parallel()
		row, err := m.GetRow(0)
		require.NoError(t, err)
		r, c := row.Dimensions()
		require.Equal(t, 1, r)
		require.Equal(t, 3, c)
		require.True(t, row.Equal(newMVMatrix(t, [][]uint64{{1, 2, 3}})))
	})

	t.Run("GetColumn", func(t *testing.T) {
		t.Parallel()
		col, err := m.GetColumn(1)
		require.NoError(t, err)
		r, c := col.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 1, c)
		require.True(t, col.Equal(newMVMatrix(t, [][]uint64{{2}, {5}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.GetRow(-1)
		require.Error(t, err)
		_, err = m.GetColumn(3)
		require.Error(t, err)
	})
}

// --- Predicates ---

func TestModuleValuedMatrixPredicates(t *testing.T) {
	t.Parallel()

	t.Run("IsOpIdentity", func(t *testing.T) {
		t.Parallel()
		require.True(t, newMVModule(t, 2, 2).Zero().IsOpIdentity())
		require.False(t, newMVMatrix(t, [][]uint64{{0, 1}, {0, 0}}).IsOpIdentity())
	})

	t.Run("IsDiagonal", func(t *testing.T) {
		t.Parallel()
		require.True(t, newMVMatrix(t, [][]uint64{{5, 0}, {0, 3}}).IsDiagonal())
		require.False(t, newMVMatrix(t, [][]uint64{{5, 1}, {0, 3}}).IsDiagonal())
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		require.True(t, newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}}).IsSquare())
		require.False(t, newMVMatrix(t, [][]uint64{{1, 2, 3}}).IsSquare())
	})
}

// --- Clone / Equal ---

func TestModuleValuedMatrixClone(t *testing.T) {
	t.Parallel()
	orig := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	clone := orig.Clone()
	clone.OpAssign(clone)
	// Original unchanged.
	require.True(t, orig.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
}

func TestModuleValuedMatrixEqual(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}})
	b := newMVMatrix(t, [][]uint64{{1}, {2}})
	require.False(t, a.Equal(b))
	require.True(t, a.Equal(newMVMatrix(t, [][]uint64{{1, 2}})))
}

// --- Transpose ---

func TestModuleValuedMatrixTranspose(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	got := m.Transpose()
	want := newMVMatrix(t, [][]uint64{{1, 4}, {2, 5}, {3, 6}})
	require.True(t, got.Equal(want))

	r, c := got.Dimensions()
	require.Equal(t, 3, r)
	require.Equal(t, 2, c)

	// Double transpose is identity.
	require.True(t, m.Transpose().Transpose().Equal(m))
}

// --- Row / column ops ---

func TestModuleValuedMatrixSwapRow(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})
	got, err := m.SwapRow(0, 2)
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{5, 6}, {3, 4}, {1, 2}})))
	// Original unchanged.
	require.True(t, m.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})))
}

func TestModuleValuedMatrixSwapColumn(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	got, err := m.SwapColumn(0, 2)
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{3, 2, 1}, {6, 5, 4}})))
}

// --- Minor ---

func TestModuleValuedMatrixMinor(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})

	t.Run("centre", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(1, 1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 3}, {7, 9}})))
	})

	t.Run("corner", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(0, 0)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{5, 6}, {8, 9}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.Minor(3, 0)
		require.Error(t, err)
	})
}

// --- Concatenation ---

func TestModuleValuedMatrixAugment(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMVMatrix(t, [][]uint64{{5}, {6}})
	got, err := a.Augment(b)
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2, 5}, {3, 4, 6}})))
}

func TestModuleValuedMatrixStack(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2, 3}})
	b := newMVMatrix(t, [][]uint64{{4, 5, 6}, {7, 8, 9}})
	got, err := a.Stack(b)
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})))
}

func TestModuleValuedMatrixAugmentDimensionMismatch(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}})
	b := newMVMatrix(t, [][]uint64{{3, 4}, {5, 6}})
	_, err := a.Augment(b)
	require.Error(t, err)
}

// --- SubMatrix / Slice ---

func TestModuleValuedMatrixSubMatrixGivenRows(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})

	t.Run("single_row", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{4, 5, 6}})))
	})

	t.Run("multiple_rows", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenRows(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2, 3}, {7, 8, 9}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenRows(3)
		require.Error(t, err)
	})
}

func TestModuleValuedMatrixSubMatrixGivenColumns(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("single_column", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(1)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{2}, {5}})))
	})

	t.Run("multiple_columns", func(t *testing.T) {
		t.Parallel()
		got, err := m.SubMatrixGivenColumns(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 3}, {4, 6}})))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.SubMatrixGivenColumns(3)
		require.Error(t, err)
	})
}

func TestModuleValuedMatrixRowSlice(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}})

	t.Run("first_two", func(t *testing.T) {
		t.Parallel()
		got, err := m.RowSlice(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
	})

	t.Run("invalid_range", func(t *testing.T) {
		t.Parallel()
		_, err := m.RowSlice(3, 1)
		require.Error(t, err)
	})
}

func TestModuleValuedMatrixColumnSlice(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("first_two", func(t *testing.T) {
		t.Parallel()
		got, err := m.ColumnSlice(0, 2)
		require.NoError(t, err)
		require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {4, 5}})))
	})

	t.Run("invalid_range", func(t *testing.T) {
		t.Parallel()
		_, err := m.ColumnSlice(0, 4)
		require.Error(t, err)
	})
}

// --- Iterators ---

func TestModuleValuedMatrixIterRows(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("yields_all_rows", func(t *testing.T) {
		t.Parallel()
		var rows []*mat.ModuleValuedMatrix[P, S]
		for row := range m.IterRows() {
			rows = append(rows, row)
		}
		require.Len(t, rows, 2)
		require.True(t, rows[0].Equal(newMVMatrix(t, [][]uint64{{1, 2, 3}})))
		require.True(t, rows[1].Equal(newMVMatrix(t, [][]uint64{{4, 5, 6}})))
	})

	t.Run("rows_are_copies", func(t *testing.T) {
		t.Parallel()
		for row := range m.IterRows() {
			row.ScalarOpAssign(scalar(0))
		}
		v, _ := m.Get(0, 0)
		require.True(t, v.Equal(point(1)))
	})
}

func TestModuleValuedMatrixIterColumns(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})

	t.Run("yields_all_columns", func(t *testing.T) {
		t.Parallel()
		var cols []*mat.ModuleValuedMatrix[P, S]
		for col := range m.IterColumns() {
			cols = append(cols, col)
		}
		require.Len(t, cols, 2)
		require.True(t, cols[0].Equal(newMVMatrix(t, [][]uint64{{1}, {3}})))
		require.True(t, cols[1].Equal(newMVMatrix(t, [][]uint64{{2}, {4}})))
	})
}

// --- Serialisation ---

func TestModuleValuedMatrixBytes(t *testing.T) {
	t.Parallel()

	t.Run("roundtrip", func(t *testing.T) {
		t.Parallel()
		m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := newMVModule(t, 2, 2).FromBytes(m.Bytes())
		require.NoError(t, err)
		require.True(t, m.Equal(got))
	})

	t.Run("wrong_length", func(t *testing.T) {
		t.Parallel()
		_, err := newMVModule(t, 2, 2).FromBytes([]byte{1, 2, 3})
		require.Error(t, err)
	})
}

// --- String / HashCode ---

func TestModuleValuedMatrixString(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	s := m.String()
	require.Contains(t, s, "[")
	require.Contains(t, s, "]")
}

func TestModuleValuedMatrixHashCode(t *testing.T) {
	t.Parallel()
	a := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	c := newMVMatrix(t, [][]uint64{{5, 6}, {7, 8}})
	require.Equal(t, a.HashCode(), b.HashCode())
	require.NotEqual(t, a.HashCode(), c.HashCode())
}

// --- Module / Structure ---

func TestModuleValuedMatrixModule(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	mod := m.Module()
	r, c := mod.Dimensions()
	require.Equal(t, 2, r)
	require.Equal(t, 2, c)
}

func TestModuleValuedMatrixStructure(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	require.NotNil(t, m.Structure())
}

// --- LiftMatrix ---

func TestLiftMatrix(t *testing.T) {
	t.Parallel()

	t.Run("basic", func(t *testing.T) {
		t.Parallel()
		// Create a scalar matrix [[2, 3], [4, 5]] and lift with generator.
		scalarMat := newMatrix(t, [][]uint64{{2, 3}, {4, 5}})
		g := generator()
		lifted, err := mat.LiftMatrix[P](scalarMat, g)
		require.NoError(t, err)
		require.True(t, lifted.Equal(newMVMatrix(t, [][]uint64{{2, 3}, {4, 5}})))
	})

	t.Run("with_different_base_point", func(t *testing.T) {
		t.Parallel()
		// Lift with 2*G as base point: each scalar s maps to s*(2G) = (2s)*G.
		scalarMat := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		base := point(2)
		lifted, err := mat.LiftMatrix[P](scalarMat, base)
		require.NoError(t, err)
		require.True(t, lifted.Equal(newMVMatrix(t, [][]uint64{{2, 4}, {6, 8}})))
	})

	t.Run("nil_matrix", func(t *testing.T) {
		t.Parallel()
		_, err := mat.LiftMatrix[P](nil, generator())
		require.Error(t, err)
	})

	t.Run("identity_scalar_matrix", func(t *testing.T) {
		t.Parallel()
		scalarMat := newMatrix(t, [][]uint64{{1, 0}, {0, 1}})
		g := generator()
		lifted, err := mat.LiftMatrix[P](scalarMat, g)
		require.NoError(t, err)
		// Diagonal should be G, off-diagonal should be identity point.
		diag, _ := lifted.Get(0, 0)
		require.True(t, diag.Equal(g))
		off, _ := lifted.Get(0, 1)
		require.True(t, off.IsOpIdentity())
	})
}

// --- IsTorsionFree ---

func TestModuleValuedMatrixIsTorsionFree(t *testing.T) {
	t.Parallel()

	t.Run("1x1_torsion_free_point", func(t *testing.T) {
		t.Parallel()
		// k256 is a prime-order curve, so points are torsion-free.
		m := newMVMatrix(t, [][]uint64{{1}})
		require.True(t, m.IsTorsionFree())
	})

	t.Run("2x2_not_torsion_free", func(t *testing.T) {
		t.Parallel()
		m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		require.False(t, m.IsTorsionFree())
	})
}

// --- Set / SetRow / SetColumn ---

func TestModuleValuedMatrixSet(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.Set(0, 1, point(99))
	require.NoError(t, err)
	v, _ := got.Get(0, 1)
	require.True(t, v.Equal(point(99)))
	// Original unchanged.
	orig, _ := m.Get(0, 1)
	require.True(t, orig.Equal(point(2)))
}

func TestModuleValuedMatrixSetRow(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.SetRow(1, []P{point(10), point(20)})
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{1, 2}, {10, 20}})))
}

func TestModuleValuedMatrixSetColumn(t *testing.T) {
	t.Parallel()
	m := newMVMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	got, err := m.SetColumn(0, []P{point(10), point(30)})
	require.NoError(t, err)
	require.True(t, got.Equal(newMVMatrix(t, [][]uint64{{10, 2}, {30, 4}})))
}
