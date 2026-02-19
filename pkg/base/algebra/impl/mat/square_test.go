package mat

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	k256impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
)

func scalarFromU64(v uint64) *k256impl.Fq {
	var out k256impl.Fq
	out.SetUint64(v)
	return &out
}

func newScalarMatrix(t *testing.T, rows [][]uint64) *SquareMatrix[*k256impl.Fq, k256impl.Fq] {
	t.Helper()
	require.NotEmpty(t, rows)
	n := len(rows)
	for _, row := range rows {
		require.Len(t, row, n)
	}

	m := new(SquareMatrix[*k256impl.Fq, k256impl.Fq])
	require.Equal(t, ct.True, m.New(n))
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			m.data[m.idx(r, c)] = *scalarFromU64(rows[r][c])
		}
	}
	return m
}

func requireScalarEqU64(t *testing.T, got *k256impl.Fq, want uint64) {
	t.Helper()
	require.Equal(t, ct.True, got.Equal(scalarFromU64(want)))
}

func requireMatrixIsIdentity(t *testing.T, m *SquareMatrix[*k256impl.Fq, k256impl.Fq]) {
	t.Helper()
	require.Equal(t, ct.True, m.IsOne())
}

func requireMatrixEq(t *testing.T, got, want *SquareMatrix[*k256impl.Fq, k256impl.Fq]) {
	t.Helper()
	require.Equal(t, ct.True, got.Equal(want))
}

func TestSquareMatrixDeterminant_K256(t *testing.T) {
	t.Parallel()

	t.Run("1x1", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{
			{7},
		})
		var det k256impl.Fq
		ok := m.Determinant(&det)
		require.Equal(t, ct.True, ok)
		requireScalarEqU64(t, &det, 7)
	})

	t.Run("2x2", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{
			{1, 2},
			{3, 4},
		})
		var det k256impl.Fq
		ok := m.Determinant(&det)
		require.Equal(t, ct.True, ok)
		// det = 1*4 - 2*3 = -2 mod q
		var expected k256impl.Fq
		expected.Sub(scalarFromU64(4), scalarFromU64(6))
		require.Equal(t, ct.True, det.Equal(&expected))
	})

	t.Run("3x3", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{
			{1, 2, 3},
			{0, 4, 5},
			{1, 0, 6},
		})
		var det k256impl.Fq
		ok := m.Determinant(&det)
		require.Equal(t, ct.True, ok)
		// integer determinant = 22
		requireScalarEqU64(t, &det, 22)
	})

	t.Run("singular", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{
			{1, 2, 3},
			{2, 4, 6},
			{7, 8, 9},
		})
		var det k256impl.Fq
		ok := m.Determinant(&det)
		require.Equal(t, ct.False, ok)
	})

	t.Run("requires row swap on first pivot", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{
			{0, 1},
			{2, 3},
		})
		var det k256impl.Fq
		ok := m.Determinant(&det)
		require.Equal(t, ct.True, ok)
		// det = -2 mod q
		var expected k256impl.Fq
		expected.Sub(scalarFromU64(0), scalarFromU64(2))
		require.Equal(t, ct.True, det.Equal(&expected))
	})
}

func TestSquareMatrixInv_K256(t *testing.T) {
	t.Parallel()

	t.Run("2x2 invertible", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{
			{1, 2},
			{3, 4},
		})

		inv := new(SquareMatrix[*k256impl.Fq, k256impl.Fq])
		require.Equal(t, ct.True, inv.New(2))
		ok := inv.Inv(a)
		require.Equal(t, ct.True, ok)

		var left, right SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, left.New(2))
		require.Equal(t, ct.True, right.New(2))
		left.Mul(a, inv)
		right.Mul(inv, a)
		requireMatrixIsIdentity(t, &left)
		requireMatrixIsIdentity(t, &right)
	})

	t.Run("3x3 invertible", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{
			{1, 2, 3},
			{0, 4, 5},
			{1, 0, 6},
		})

		inv := new(SquareMatrix[*k256impl.Fq, k256impl.Fq])
		require.Equal(t, ct.True, inv.New(3))
		ok := inv.Inv(a)
		require.Equal(t, ct.True, ok)

		var left, right SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, left.New(3))
		require.Equal(t, ct.True, right.New(3))
		left.Mul(a, inv)
		right.Mul(inv, a)
		requireMatrixIsIdentity(t, &left)
		requireMatrixIsIdentity(t, &right)
	})

	t.Run("requires row swap", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{
			{0, 1},
			{2, 3},
		})

		inv := new(SquareMatrix[*k256impl.Fq, k256impl.Fq])
		require.Equal(t, ct.True, inv.New(2))
		ok := inv.Inv(a)
		require.Equal(t, ct.True, ok)

		var prod SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, prod.New(2))
		prod.Mul(a, inv)
		requireMatrixIsIdentity(t, &prod)
	})

	t.Run("singular returns false and leaves receiver unchanged", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{
			{1, 2, 3},
			{2, 4, 6},
			{7, 8, 9},
		})

		inv := newScalarMatrix(t, [][]uint64{
			{5, 0, 0},
			{0, 5, 0},
			{0, 0, 5},
		})
		before := new(SquareMatrix[*k256impl.Fq, k256impl.Fq])
		require.Equal(t, ct.True, before.New(3))
		before.Set(inv)

		ok := inv.Inv(a)
		require.Equal(t, ct.False, ok)
		require.Equal(t, ct.True, inv.Equal(before))
	})
}

func TestSquareMatrixOps_K256(t *testing.T) {
	t.Parallel()

	t.Run("init", func(t *testing.T) {
		t.Parallel()
		var m SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.False, m.New(0))
		require.Equal(t, ct.False, m.New(-1))
		require.Equal(t, ct.True, m.New(2))
	})

	t.Run("set and select", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newScalarMatrix(t, [][]uint64{{5, 6}, {7, 8}})

		var got SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, got.New(2))
		got.Set(a)
		requireMatrixEq(t, &got, a)

		var sel SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, sel.New(2))
		sel.Select(ct.True, a, b)
		requireMatrixEq(t, &sel, b)
		sel.Select(ct.False, a, b)
		requireMatrixEq(t, &sel, a)
	})

	t.Run("zero one and predicates", func(t *testing.T) {
		t.Parallel()
		m := newScalarMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		m.SetZero()
		require.Equal(t, ct.True, m.IsZero())
		require.Equal(t, ct.False, m.IsNonZero())
		require.Equal(t, ct.False, m.IsOne())

		m.SetOne()
		require.Equal(t, ct.True, m.IsOne())
		require.Equal(t, ct.False, m.IsZero())
		require.Equal(t, ct.True, m.IsNonZero())
	})

	t.Run("add sub neg double", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newScalarMatrix(t, [][]uint64{{5, 6}, {7, 8}})

		var add SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, add.New(2))
		add.Add(a, b)
		requireMatrixEq(t, &add, newScalarMatrix(t, [][]uint64{{6, 8}, {10, 12}}))

		var sub SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, sub.New(2))
		sub.Sub(&add, b)
		requireMatrixEq(t, &sub, a)

		var dbl SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, dbl.New(2))
		dbl.Double(a)
		requireMatrixEq(t, &dbl, newScalarMatrix(t, [][]uint64{{2, 4}, {6, 8}}))

		var neg SquareMatrix[*k256impl.Fq, k256impl.Fq]
		var zero SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, neg.New(2))
		require.Equal(t, ct.True, zero.New(2))
		neg.Neg(a)
		zero.Add(a, &neg)
		require.Equal(t, ct.True, zero.IsZero())
	})

	t.Run("mul and square", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newScalarMatrix(t, [][]uint64{{2, 0}, {1, 2}})

		var mul SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, mul.New(2))
		mul.Mul(a, b)
		requireMatrixEq(t, &mul, newScalarMatrix(t, [][]uint64{{4, 4}, {10, 8}}))

		var sq1, sq2 SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, sq1.New(2))
		require.Equal(t, ct.True, sq2.New(2))
		sq1.Square(a)
		sq2.Mul(a, a)
		requireMatrixEq(t, &sq1, &sq2)
	})

	t.Run("div", func(t *testing.T) {
		t.Parallel()
		a := newScalarMatrix(t, [][]uint64{{1, 2}, {3, 4}})
		b := newScalarMatrix(t, [][]uint64{{2, 1}, {1, 1}})

		var got SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, got.New(2))
		ok := got.Div(a, b)
		require.Equal(t, ct.True, ok)

		var back SquareMatrix[*k256impl.Fq, k256impl.Fq]
		require.Equal(t, ct.True, back.New(2))
		back.Mul(&got, b)
		requireMatrixEq(t, &back, a)

		sing := newScalarMatrix(t, [][]uint64{{1, 2}, {2, 4}})
		before := newScalarMatrix(t, [][]uint64{{9, 9}, {9, 9}})
		got.Set(before)
		ok = got.Div(a, sing)
		require.Equal(t, ct.False, ok)
		requireMatrixEq(t, &got, before)
	})
}
