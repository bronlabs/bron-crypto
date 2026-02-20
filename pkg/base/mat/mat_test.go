package mat_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
)

type S = *k256.Scalar

func testRing() *k256.ScalarField {
	return k256.NewScalarField()
}

func scalar(v uint64) S {
	return testRing().FromUint64(v)
}

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

func newAlgebra(t *testing.T, n uint) *mat.MatrixAlgebra[S] {
	t.Helper()
	alg, err := mat.NewMatrixAlgebra(n, testRing())
	require.NoError(t, err)
	return alg
}

func newMatrix(t *testing.T, rows [][]uint64) *mat.Matrix[S] {
	t.Helper()
	sr := scalarRows(rows)
	mod := newModule(t, uint(len(rows)), uint(len(rows[0])))
	m, err := mod.New(sr)
	require.NoError(t, err)
	return m
}

func newSquare(t *testing.T, rows [][]uint64) *mat.SquareMatrix[S] {
	t.Helper()
	sr := scalarRows(rows)
	alg := newAlgebra(t, uint(len(rows)))
	m, err := alg.New(sr)
	require.NoError(t, err)
	return m
}

func identitySquare(t *testing.T, n uint) *mat.SquareMatrix[S] {
	t.Helper()
	return newAlgebra(t, n).Identity()
}

// --- Rectangular Matrix tests ---

func TestMatrixAddSubNeg(t *testing.T) {
	t.Parallel()

	a := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
	b := newMatrix(t, [][]uint64{{10, 20, 30}, {40, 50, 60}})

	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		got := a.Add(b)
		want := newMatrix(t, [][]uint64{{11, 22, 33}, {44, 55, 66}})
		require.True(t, got.Equal(want))
	})

	t.Run("Sub", func(t *testing.T) {
		t.Parallel()
		got := a.Add(b).Sub(b)
		require.True(t, got.Equal(a))
	})

	t.Run("Neg", func(t *testing.T) {
		t.Parallel()
		got := a.Add(a.Neg())
		require.True(t, got.IsZero())
	})

	t.Run("Double", func(t *testing.T) {
		t.Parallel()
		got := a.Double()
		want := newMatrix(t, [][]uint64{{2, 4, 6}, {8, 10, 12}})
		require.True(t, got.Equal(want))
	})

	t.Run("ScalarMul", func(t *testing.T) {
		t.Parallel()
		got := a.ScalarMul(scalar(3))
		want := newMatrix(t, [][]uint64{{3, 6, 9}, {12, 15, 18}})
		require.True(t, got.Equal(want))
	})

	t.Run("Clone_independent", func(t *testing.T) {
		t.Parallel()
		orig := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		clone := orig.Clone()
		clone.AddMut(clone)
		require.True(t, orig.Equal(newMatrix(t, [][]uint64{{1, 2}, {3, 4}})))
	})

	t.Run("Equal_different_dimensions", func(t *testing.T) {
		t.Parallel()
		m1 := newMatrix(t, [][]uint64{{1, 2}})
		m2 := newMatrix(t, [][]uint64{{1}, {2}})
		require.False(t, m1.Equal(m2))
	})
}

func TestMatrixTranspose(t *testing.T) {
	t.Parallel()

	t.Run("rectangular", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		got := m.Transpose()
		want := newMatrix(t, [][]uint64{{1, 4}, {2, 5}, {3, 6}})
		require.True(t, got.Equal(want))
		r, c := got.Dimensions()
		require.Equal(t, 3, r)
		require.Equal(t, 2, c)
	})

	t.Run("double_transpose_identity", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		require.True(t, m.Transpose().Transpose().Equal(m))
	})
}

func TestMatrixGetRowColumn(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})

	t.Run("GetRow", func(t *testing.T) {
		t.Parallel()
		row, err := m.GetRow(0)
		require.NoError(t, err)
		require.Len(t, row, 3)
		require.True(t, row[0].Equal(scalar(1)))
		require.True(t, row[1].Equal(scalar(2)))
		require.True(t, row[2].Equal(scalar(3)))
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
		_, err = m.Get(2, 0)
		require.Error(t, err)
	})
}

func TestMatrixRowColumnOps(t *testing.T) {
	t.Parallel()

	t.Run("SwapRow", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})
		got, err := m.SwapRow(0, 2)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{5, 6}, {3, 4}, {1, 2}})
		require.True(t, got.Equal(want))
		// original unchanged
		require.True(t, m.Equal(newMatrix(t, [][]uint64{{1, 2}, {3, 4}, {5, 6}})))
	})

	t.Run("SwapColumn", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		got, err := m.SwapColumn(0, 2)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{3, 2, 1}, {6, 5, 4}})
		require.True(t, got.Equal(want))
	})

	t.Run("RowAdd", func(t *testing.T) {
		t.Parallel()
		// row0 += 2 * row1
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.RowAdd(0, 1, scalar(2))
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{7, 10}, {3, 4}})
		require.True(t, got.Equal(want))
	})

	t.Run("ColumnAdd", func(t *testing.T) {
		t.Parallel()
		// col0 += 2 * col1
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.ColumnAdd(0, 1, scalar(2))
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{5, 2}, {11, 4}})
		require.True(t, got.Equal(want))
	})

	t.Run("RowScalarMul", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.RowScalarMul(1, scalar(3))
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{1, 2}, {9, 12}})
		require.True(t, got.Equal(want))
	})

	t.Run("ColumnScalarMul", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.ColumnScalarMul(0, scalar(5))
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{5, 2}, {15, 4}})
		require.True(t, got.Equal(want))
	})

	t.Run("SwapRow_OOB", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}})
		_, err := m.SwapRow(0, 1)
		require.Error(t, err)
	})
}

func TestMatrixMinor(t *testing.T) {
	t.Parallel()
	m := newMatrix(t, [][]uint64{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	})

	t.Run("remove_center", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(1, 1)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{1, 3}, {7, 9}})
		require.True(t, got.Equal(want))
	})

	t.Run("remove_corner", func(t *testing.T) {
		t.Parallel()
		got, err := m.Minor(0, 0)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{5, 6}, {8, 9}})
		require.True(t, got.Equal(want))
	})

	t.Run("OOB", func(t *testing.T) {
		t.Parallel()
		_, err := m.Minor(3, 0)
		require.Error(t, err)
	})
}

func TestMatrixConcat(t *testing.T) {
	t.Parallel()

	t.Run("ConcatColumns", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newMatrix(t, [][]uint64{{5}, {6}})
		got, err := a.ConcatColumns(b)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{1, 2, 5}, {3, 4, 6}})
		require.True(t, got.Equal(want))
	})

	t.Run("ConcatRows", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2, 3}})
		b := newMatrix(t, [][]uint64{{4, 5, 6}, {7, 8, 9}})
		got, err := a.ConcatRows(b)
		require.NoError(t, err)
		want := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}})
		require.True(t, got.Equal(want))
	})

	t.Run("ConcatColumns_dimension_mismatch", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2}})
		b := newMatrix(t, [][]uint64{{3, 4}, {5, 6}})
		_, err := a.ConcatColumns(b)
		require.Error(t, err)
	})
}

func TestMatrixHadamard(t *testing.T) {
	t.Parallel()
	a := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
	b := newMatrix(t, [][]uint64{{5, 6}, {7, 8}})
	got, err := a.HadamardProduct(b)
	require.NoError(t, err)
	want := newMatrix(t, [][]uint64{{5, 12}, {21, 32}})
	require.True(t, got.Equal(want))
}

func TestMatrixMultiply(t *testing.T) {
	t.Parallel()

	t.Run("2x3_times_3x2", func(t *testing.T) {
		t.Parallel()
		a := newMatrix(t, [][]uint64{{1, 2, 3}, {4, 5, 6}})
		b := newMatrix(t, [][]uint64{{7, 8}, {9, 10}, {11, 12}})
		got, err := a.TryMul(b)
		require.NoError(t, err)
		// [1*7+2*9+3*11, 1*8+2*10+3*12] = [58, 64]
		// [4*7+5*9+6*11, 4*8+5*10+6*12] = [139, 154]
		want := newMatrix(t, [][]uint64{{58, 64}, {139, 154}})
		require.True(t, got.Equal(want))
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
		want := newMatrix(t, [][]uint64{{21}})
		require.True(t, got.Equal(want))
	})
}

func TestMatrixBytes(t *testing.T) {
	t.Parallel()

	t.Run("roundtrip_2x2", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		bs := m.Bytes()
		mod := newModule(t, 2, 2)
		got, err := mod.FromBytes(bs)
		require.NoError(t, err)
		require.True(t, m.Equal(got))
	})

	t.Run("roundtrip_1x1", func(t *testing.T) {
		t.Parallel()
		m := newMatrix(t, [][]uint64{{42}})
		bs := m.Bytes()
		mod := newModule(t, 1, 1)
		got, err := mod.FromBytes(bs)
		require.NoError(t, err)
		require.True(t, m.Equal(got))
	})
}

func TestMatrixPredicates(t *testing.T) {
	t.Parallel()

	t.Run("IsZero", func(t *testing.T) {
		t.Parallel()
		z := newModule(t, 2, 3).Zero()
		require.True(t, z.IsZero())
		nz := newMatrix(t, [][]uint64{{0, 1}, {0, 0}})
		require.False(t, nz.IsZero())
	})

	t.Run("IsDiagonal", func(t *testing.T) {
		t.Parallel()
		d := newMatrix(t, [][]uint64{{5, 0}, {0, 3}})
		require.True(t, d.IsDiagonal())
		nd := newMatrix(t, [][]uint64{{5, 1}, {0, 3}})
		require.False(t, nd.IsDiagonal())
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		sq := newMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		require.True(t, sq.IsSquare())
		rect := newMatrix(t, [][]uint64{{1, 2, 3}})
		require.False(t, rect.IsSquare())
	})
}

func TestMatrixModuleAlgebra(t *testing.T) {
	t.Parallel()

	t.Run("OpIdentity_is_zero", func(t *testing.T) {
		t.Parallel()
		mod := newModule(t, 2, 3)
		z := mod.OpIdentity()
		require.True(t, z.IsZero())
		r, c := z.Dimensions()
		require.Equal(t, 2, r)
		require.Equal(t, 3, c)
	})

	t.Run("Zero_equals_OpIdentity", func(t *testing.T) {
		t.Parallel()
		mod := newModule(t, 2, 2)
		require.True(t, mod.Zero().Equal(mod.OpIdentity()))
	})

	t.Run("Name", func(t *testing.T) {
		t.Parallel()
		mod := newModule(t, 2, 3)
		require.Contains(t, mod.Name(), "2x3")
	})

	t.Run("IsSquare", func(t *testing.T) {
		t.Parallel()
		require.True(t, newModule(t, 3, 3).IsSquare())
		require.False(t, newModule(t, 2, 3).IsSquare())
	})
}

// --- Square Matrix tests ---

func TestSquareIdentityConstruction(t *testing.T) {
	t.Parallel()

	t.Run("Identity_3x3", func(t *testing.T) {
		t.Parallel()
		id := identitySquare(t, 3)
		// Verify diagonal is 1 and off-diagonal is 0.
		for i := range 3 {
			for j := range 3 {
				v, err := id.Get(i, j)
				require.NoError(t, err)
				if i == j {
					require.True(t, v.Equal(scalar(1)), "expected 1 at (%d,%d)", i, j)
				} else {
					require.True(t, v.IsZero(), "expected 0 at (%d,%d)", i, j)
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

	t.Run("true_for_identity", func(t *testing.T) {
		t.Parallel()
		id := identitySquare(t, 3)
		require.True(t, id.IsIdentity())
	})

	t.Run("false_for_nonidentity", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		require.False(t, m.IsIdentity())
	})

	t.Run("false_for_first_column_ones", func(t *testing.T) {
		t.Parallel()
		// With the i%n==0 bug, this would incorrectly return true.
		m := newSquare(t, [][]uint64{
			{1, 0, 0},
			{1, 0, 0},
			{1, 0, 0},
		})
		require.False(t, m.IsIdentity())
	})

	t.Run("2x2_identity", func(t *testing.T) {
		t.Parallel()
		id := identitySquare(t, 2)
		require.True(t, id.IsIdentity())
		require.True(t, id.IsOne())
	})
}

func TestSquareAddSubNeg(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	b := newSquare(t, [][]uint64{{10, 20}, {30, 40}})

	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		got := a.Add(b)
		want := newSquare(t, [][]uint64{{11, 22}, {33, 44}})
		require.True(t, got.Equal(want))
	})

	t.Run("Sub", func(t *testing.T) {
		t.Parallel()
		got := a.Add(b).Sub(b)
		require.True(t, got.Equal(a))
	})

	t.Run("Neg", func(t *testing.T) {
		t.Parallel()
		got := a.Add(a.Neg())
		require.True(t, got.IsZero())
	})

	t.Run("Double", func(t *testing.T) {
		t.Parallel()
		got := a.Double()
		want := newSquare(t, [][]uint64{{2, 4}, {6, 8}})
		require.True(t, got.Equal(want))
	})

	t.Run("ScalarMul", func(t *testing.T) {
		t.Parallel()
		got := a.ScalarMul(scalar(5))
		want := newSquare(t, [][]uint64{{5, 10}, {15, 20}})
		require.True(t, got.Equal(want))
	})
}

func TestSquareMul(t *testing.T) {
	t.Parallel()

	t.Run("basic_2x2", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		b := newSquare(t, [][]uint64{{5, 6}, {7, 8}})
		got := a.Mul(b)
		// [1*5+2*7, 1*6+2*8] = [19, 22]
		// [3*5+4*7, 3*6+4*8] = [43, 50]
		want := newSquare(t, [][]uint64{{19, 22}, {43, 50}})
		require.True(t, got.Equal(want))
	})

	t.Run("identity_left", func(t *testing.T) {
		t.Parallel()
		id := identitySquare(t, 2)
		a := newSquare(t, [][]uint64{{3, 4}, {5, 6}})
		require.True(t, id.Mul(a).Equal(a))
	})

	t.Run("identity_right", func(t *testing.T) {
		t.Parallel()
		id := identitySquare(t, 2)
		a := newSquare(t, [][]uint64{{3, 4}, {5, 6}})
		require.True(t, a.Mul(id).Equal(a))
	})

	t.Run("Square", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		require.True(t, a.Square().Equal(a.Mul(a)))
	})
}

func TestSquareTrace(t *testing.T) {
	t.Parallel()

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		require.True(t, m.Trace().Equal(scalar(5)))
	})

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{10, 0, 0}, {0, 20, 0}, {0, 0, 30}})
		require.True(t, m.Trace().Equal(scalar(60)))
	})
}

func TestSquareDeterminant(t *testing.T) {
	t.Parallel()

	t.Run("1x1", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{7}})
		require.True(t, m.Determinant().Equal(scalar(7)))
	})

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		// det = 1*4 - 2*3 = -2 mod q
		want := scalar(4).Sub(scalar(6))
		require.True(t, m.Determinant().Equal(want))
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
		want := scalar(0).Sub(scalar(2))
		require.True(t, m.Determinant().Equal(want))
	})

	t.Run("singular", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{
			{1, 2, 3},
			{2, 4, 6},
			{7, 8, 9},
		})
		require.True(t, m.Determinant().IsZero())
	})
}

func TestSquareTryInv(t *testing.T) {
	t.Parallel()

	t.Run("2x2_invertible", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		inv, err := a.TryInv()
		require.NoError(t, err)
		product := a.Mul(inv)
		require.True(t, product.IsIdentity())
	})

	t.Run("3x3_invertible", func(t *testing.T) {
		t.Parallel()
		a := newSquare(t, [][]uint64{
			{1, 2, 3},
			{0, 4, 5},
			{1, 0, 6},
		})
		inv, err := a.TryInv()
		require.NoError(t, err)
		require.True(t, a.Mul(inv).IsIdentity())
		require.True(t, inv.Mul(a).IsIdentity())
	})

	t.Run("singular", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{
			{1, 2, 3},
			{2, 4, 6},
			{7, 8, 9},
		})
		_, err := m.TryInv()
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

func TestSquareTryDiv(t *testing.T) {
	t.Parallel()
	a := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	b := newSquare(t, [][]uint64{{2, 1}, {1, 1}})

	got, err := a.TryDiv(b)
	require.NoError(t, err)
	// a / b * b = a
	require.True(t, got.Mul(b).Equal(a))
}

func TestSquareTranspose(t *testing.T) {
	t.Parallel()
	m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
	got := m.Transpose()
	want := newSquare(t, [][]uint64{{1, 3}, {2, 4}})
	require.True(t, got.Equal(want))
}

func TestSquareRowColumnOps(t *testing.T) {
	t.Parallel()

	t.Run("SwapRow", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.SwapRow(0, 1)
		require.NoError(t, err)
		want := newSquare(t, [][]uint64{{3, 4}, {1, 2}})
		require.True(t, got.Equal(want))
	})

	t.Run("SwapColumn", func(t *testing.T) {
		t.Parallel()
		m := newSquare(t, [][]uint64{{1, 2}, {3, 4}})
		got, err := m.SwapColumn(0, 1)
		require.NoError(t, err)
		want := newSquare(t, [][]uint64{{2, 1}, {4, 3}})
		require.True(t, got.Equal(want))
	})
}
