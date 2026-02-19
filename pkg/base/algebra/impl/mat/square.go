package mat

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func _[RPtr impl.RingElementPtrLowLevel[RPtr, R], R any]() {
	var _ impl.RingElementLowLevel[*SquareMatrix[RPtr, R]] = (*SquareMatrix[RPtr, R])(nil)

	var _ impl.SquareMatrixLowLevel[*SquareMatrix[RPtr, R], RPtr, RPtr] = (*SquareMatrix[RPtr, R])(nil)
}

type SquareMatrix[RPtr impl.RingElementPtrLowLevel[RPtr, R], R any] struct {
	n    int
	data []R
}

func (m *SquareMatrix[RPtr, R]) New(n int) ct.Bool {
	if n <= 0 {
		return ct.False
	}
	m.n = n
	m.data = make([]R, n*n)
	m.SetZero()
	return ct.True
}

func (m *SquareMatrix[RPtr, R]) SetRandom(prng io.Reader) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Dimensions() (rows, cols int) {
	return m.n, m.n
}

func (m *SquareMatrix[RPtr, R]) IsSquare() ct.Bool {
	return ct.True
}

func (m *SquareMatrix[RPtr, R]) IsDiagonal() ct.Bool {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Minor(out, in *SquareMatrix[RPtr, R], row, col int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Get(out RPtr, row, col int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) GetRow(out []RPtr, row int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) GetColumn(out []RPtr, col int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Transpose(in *SquareMatrix[RPtr, R]) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SwapRow(i, j int) (ok ct.Bool) {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		return ct.False
	}
	m.swapRows(i, j)
	return ct.True
}

func (m *SquareMatrix[RPtr, R]) SwapColumn(i, j int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) RowAdd(row1, row2 int, scalar RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) ColumnAdd(col1, col2 int, scalar RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) RowMul(row int, scalar RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) ColumnMul(col int, scalar RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) KroneckerProduct(a, b *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) HadamardProduct(a, b *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) ScalarProduct(s RPtr, m2 *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) ConcatRows(a, b *SquareMatrix[RPtr, R]) {
	panic("not supported")
}

func (m *SquareMatrix[RPtr, R]) ConcatColumns(a, b *SquareMatrix[RPtr, R]) {
	panic("not supported")
}

func (m *SquareMatrix[RPtr, R]) SetElement(row, col int, value RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SetRow(row int, values *[]RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SetRowZero(row int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SetColumn(col int, values *[]RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SetColumnZero(col int) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Trace(out RPtr) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Set(v *SquareMatrix[RPtr, R]) {
	if m.n != v.n {
		panic("incompatible dimensions")
	}

	m.data = make([]R, len(v.data))
	for i := range v.data {
		RPtr(&m.data[i]).Set(&v.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) Select(choice ct.Choice, x0, x1 *SquareMatrix[RPtr, R]) {
	if m.n != x0.n || m.n != x1.n {
		panic("incompatible dimensions")
	}

	for i := range m.data {
		RPtr(&m.data[i]).Select(choice, &x0.data[i], &x1.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) Equal(rhs *SquareMatrix[RPtr, R]) ct.Bool {
	if m.n != rhs.n {
		panic("incompatible dimensions")
	}

	eq := ct.True
	for i := range m.data {
		eq &= RPtr(&m.data[i]).Equal(&rhs.data[i])
	}
	return eq
}

func (m *SquareMatrix[RPtr, R]) Add(lhs, rhs *SquareMatrix[RPtr, R]) {
	if m.n != rhs.n {
		panic("incompatible dimensions")
	}

	for i := range m.data {
		RPtr(&m.data[i]).Add(&lhs.data[i], &rhs.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) Double(e *SquareMatrix[RPtr, R]) {
	if m.n != e.n {
		panic("incompatible dimensions")
	}

	for i := range m.data {
		RPtr(&m.data[i]).Double(&e.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) SetBytes(bytes []byte) (ok ct.Bool) {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) SetZero() {
	for i := range m.data {
		RPtr(&m.data[i]).SetZero()
	}
}

func (m *SquareMatrix[RPtr, R]) IsZero() ct.Bool {
	return m.IsNonZero() ^ 1
}

func (m *SquareMatrix[RPtr, R]) IsNonZero() ct.Bool {
	z := ct.False
	for i := range m.data {
		z |= RPtr(&m.data[i]).IsNonZero()
	}
	return z
}

func (m *SquareMatrix[RPtr, R]) Sub(lhs, rhs *SquareMatrix[RPtr, R]) {
	if m.n != lhs.n || m.n != rhs.n {
		panic("incompatible dimensions")
	}

	for i := range m.data {
		RPtr(&m.data[i]).Sub(&lhs.data[i], &rhs.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) Neg(e *SquareMatrix[RPtr, R]) {
	if m.n != e.n {
		panic("incompatible dimensions")
	}

	for i := range m.data {
		RPtr(&m.data[i]).Neg(&e.data[i])
	}
}

func (m *SquareMatrix[RPtr, R]) SetOne() {
	m.SetZero()
	for i := range m.n {
		RPtr(&m.data[m.idx(i, i)]).SetOne()
	}
}

func (m *SquareMatrix[RPtr, R]) IsOne() ct.Bool {
	o := ct.True
	for r := range m.n {
		for c := range m.n {
			if r == c {
				o &= RPtr(&m.data[m.idx(r, c)]).IsOne()
			} else {
				o &= RPtr(&m.data[m.idx(r, c)]).IsZero()
			}
		}
	}

	return o
}

func (m *SquareMatrix[RPtr, R]) Mul(lhs, rhs *SquareMatrix[RPtr, R]) {
	if m.n != lhs.n || m.n != rhs.n {
		panic("incompatible dimensions")
	}

	var out SquareMatrix[RPtr, R]
	out.New(m.n)
	out.SetZero()
	for r := range m.n {
		for c := range m.n {
			for i := range m.n {
				var p R
				RPtr(&p).Mul(&lhs.data[m.idx(r, i)], &rhs.data[m.idx(i, c)])
				RPtr(&out.data[m.idx(r, c)]).Add(&out.data[m.idx(r, c)], &p)
			}
		}
	}
	m.Set(&out)
}

func (m *SquareMatrix[RPtr, R]) Square(e *SquareMatrix[RPtr, R]) {
	m.Mul(e, e)
}

func (m *SquareMatrix[RPtr, R]) Inv(e *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	if m.n != e.n {
		panic("incompatible dimensions")
	}

	var a, out SquareMatrix[RPtr, R]
	a.New(m.n)
	a.Set(e)
	out.New(m.n)
	out.SetOne()

	for k := 0; k < a.n; k++ {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			return ct.False
		}
		if pivot != k {
			a.swapRows(k, pivot)
			out.swapRows(k, pivot)
		}

		var pivotVal, invPivot R
		RPtr(&pivotVal).Set(&a.data[a.idx(k, k)])
		if RPtr(&invPivot).Inv(&pivotVal) == ct.False {
			return ct.False
		}

		// Normalize pivot row.
		for j := 0; j < a.n; j++ {
			RPtr(&a.data[a.idx(k, j)]).Mul(&a.data[a.idx(k, j)], &invPivot)
			RPtr(&out.data[out.idx(k, j)]).Mul(&out.data[out.idx(k, j)], &invPivot)
		}

		// Eliminate pivot column from all other rows.
		for i := 0; i < a.n; i++ {
			if i == k {
				continue
			}
			var factor R
			RPtr(&factor).Set(&a.data[a.idx(i, k)])
			if RPtr(&factor).IsZero() != ct.False {
				continue
			}

			for j := 0; j < a.n; j++ {
				var t R
				RPtr(&t).Mul(&factor, &a.data[a.idx(k, j)])
				RPtr(&a.data[a.idx(i, j)]).Sub(&a.data[a.idx(i, j)], &t)

				RPtr(&t).Mul(&factor, &out.data[out.idx(k, j)])
				RPtr(&out.data[out.idx(i, j)]).Sub(&out.data[out.idx(i, j)], &t)
			}
		}
	}

	m.Select(ct.True, m, &out)
	return ct.True
}

func (m *SquareMatrix[RPtr, R]) Div(lhs, rhs *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	var rhsInv, out SquareMatrix[RPtr, R]
	out.New(m.n)
	rhsInv.New(m.n)
	ok = rhsInv.Inv(rhs)
	out.Mul(lhs, &rhsInv)
	m.Select(ok, m, &out)
	return ok
}

func (m *SquareMatrix[RPtr, R]) Sqrt(e *SquareMatrix[RPtr, R]) (ok ct.Bool) {
	panic("implement me")
}

func (m *SquareMatrix[RPtr, R]) Determinant(out RPtr) ct.Bool {
	if m.n <= 0 {
		out.SetZero()
		return ct.False
	}

	var a SquareMatrix[RPtr, R]
	a.New(m.n)
	a.Set(m)

	var sign, det R
	RPtr(&sign).SetOne()
	RPtr(&det).SetOne()

	for k := 0; k < a.n; k++ {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			out.SetZero()
			return ct.False
		}
		if pivot != k {
			a.swapRows(k, pivot)
			RPtr(&sign).Neg(&sign)
		}

		var pivotVal R
		RPtr(&pivotVal).Set(&a.data[a.idx(k, k)])
		RPtr(&det).Mul(&det, &pivotVal)

		// Forward elimination only (determinant path).
		for i := k + 1; i < a.n; i++ {
			var factor R
			if RPtr(&factor).Div(&a.data[a.idx(i, k)], &pivotVal) == ct.False {
				out.SetZero()
				return ct.False
			}
			for j := k + 1; j < a.n; j++ {
				var t R
				RPtr(&t).Mul(&factor, &a.data[a.idx(k, j)])
				RPtr(&a.data[a.idx(i, j)]).Sub(&a.data[a.idx(i, j)], &t)
			}
			RPtr(&a.data[a.idx(i, k)]).SetZero()
		}
	}

	out.Mul(&sign, &det)
	return out.IsNonZero()
}

func (m *SquareMatrix[RPtr, R]) findPivotRow(col int) int {
	for r := col; r < m.n; r++ {
		if RPtr(&m.data[m.idx(r, col)]).IsZero() == ct.False {
			return r
		}
	}
	return -1
}

func (m *SquareMatrix[RPtr, R]) swapRows(i, j int) {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		panic("invalid row indices")
	}
	if i == j {
		return
	}

	rowI := i * m.n
	rowJ := j * m.n
	for c := 0; c < m.n; c++ {
		m.data[rowI+c], m.data[rowJ+c] = m.data[rowJ+c], m.data[rowI+c]
	}
}

func (m *SquareMatrix[RPtr, R]) idx(r, c int) int {
	return r*m.n + c
}
