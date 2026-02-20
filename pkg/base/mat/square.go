package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

func NewMatrixAlgebra[S algebra.RingElement[S]](n uint, ring algebra.Ring[S]) (*MatrixAlgebra[S], error) {
	if n == 0 {
		return nil, ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", n, n)
	}
	if ring == nil {
		return nil, ErrFailed.WithMessage("ring cannot be nil")
	}
	return &MatrixAlgebra[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *SquareMatrix[S], SquareMatrix[S]]{
			rows: int(n),
			cols: int(n),
			ring: ring,
		},
	}, nil
}

type MatrixAlgebra[S algebra.RingElement[S]] struct {
	MatrixModuleTrait[S, *SquareMatrix[S], SquareMatrix[S]]
}

func (a *MatrixAlgebra[S]) New(rows [][]S) (*SquareMatrix[S], error) {
	m, n := len(rows), len(rows[0])
	if m == 0 || n == 0 {
		return nil, ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", m, n)
	}
	matrix := &SquareMatrix[S]{}
	matrix.init(n, n)
	for i := range rows {
		if len(rows[i]) != matrix.n {
			return nil, ErrDimension.WithMessage("all rows must have the same number of columns: row 0 has %d columns but row %d has %d columns", matrix.cols(), i, len(rows[i]))
		}
		copy(matrix.v[i*matrix.n:(i+1)*matrix.n], rows[i])
	}
	return matrix, nil
}

func (a *MatrixAlgebra[S]) N() int {
	_, n := a.Dimensions()
	return n
}

func (a *MatrixAlgebra[S]) Characteristic() algebra.Cardinal {
	return a.ring.Characteristic()
}

func (a *MatrixAlgebra[S]) Identity() *SquareMatrix[S] {
	identity := a.OpIdentity()
	n := a.N()
	for i := range n {
		identity.v[identity.idx(i, i)] = a.ring.One()
	}
	return identity
}

func (a *MatrixAlgebra[S]) IsDomain() bool {
	return a.N() == 1 && a.ring.IsDomain()
}

func (a *MatrixAlgebra[S]) One() *SquareMatrix[S] {
	return a.Identity()
}

type SquareMatrix[S algebra.RingElement[S]] struct {
	MatrixTrait[S, *SquareMatrix[S], SquareMatrix[S]]
}

func (m *SquareMatrix[S]) init(rows, cols int) {
	if rows != cols {
		panic(ErrDimension.WithMessage("square matrix must have equal number of rows and columns"))
	}
	m.MatrixTrait = MatrixTrait[S, *SquareMatrix[S], SquareMatrix[S]]{
		self: m,
		m:    rows,
		n:    cols,
		v:    make([]S, rows*cols),
	}
}

func (m *SquareMatrix[S]) rows() int {
	return m.m
}

func (m *SquareMatrix[S]) cols() int {
	return m.n
}

func (m *SquareMatrix[S]) data() []S {
	return m.v
}

func (m *SquareMatrix[S]) N() int {
	return m.n
}

func (m *SquareMatrix[S]) Algebra() *MatrixAlgebra[S] {
	return &MatrixAlgebra[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *SquareMatrix[S], SquareMatrix[S]]{
			rows: m.rows(),
			cols: m.cols(),
			ring: m.scalarRing(),
		},
	}
}

func (m *SquareMatrix[S]) Structure() algebra.Structure[*SquareMatrix[S]] {
	return m.Algebra()
}

func (m *SquareMatrix[S]) OtherOp(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Mul(other)
}

func (m *SquareMatrix[S]) MulMut(other *SquareMatrix[S]) *SquareMatrix[S] {
	if m.n != other.N() {
		panic(ErrDimension.WithMessage("incompatible dimensions for multiplication: %dx%d and %dx%d", m.rows(), m.cols(), other.rows(), other.cols()))
	}
	n := m.n
	for i := range n {
		for j := range n {
			sum := m.Algebra().ring.Zero()
			for k := range n {
				t := m.v[m.idx(i, k)].Mul(other.v[other.idx(k, j)])
				sum = sum.Add(t)
			}
			m.v[m.idx(i, j)] = sum
		}
	}
	return m
}

func (m *SquareMatrix[S]) Mul(other *SquareMatrix[S]) *SquareMatrix[S] {
	out, err := m.TryMul(other)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to multiply matrices"))
	}
	return out
}

func (m *SquareMatrix[S]) SquareMut() *SquareMatrix[S] {
	return m.MulMut(m)
}

func (m *SquareMatrix[S]) Square() *SquareMatrix[S] {
	return m.Mul(m)
}

func (m *SquareMatrix[S]) IsIdentity() bool {
	n := m.Algebra().N()
	for i := range n {
		for j := range n {
			expected := m.Algebra().ring.Zero()
			if i == j {
				expected = m.Algebra().ring.One()
			}
			if !m.v[m.idx(i, j)].Equal(expected) {
				return false
			}
		}
	}
	return true
}

func (m *SquareMatrix[S]) IsOne() bool {
	return m.IsIdentity()
}

func (m *SquareMatrix[S]) Trace() S {
	alg := m.Algebra()
	trace := alg.ring.Zero()
	n := alg.N()
	for i := range n {
		trace = trace.Add(m.v[m.idx(i, i)])
	}
	return trace
}

func (m *SquareMatrix[S]) TryInv() (*SquareMatrix[S], error) {
	alg := m.Algebra()
	n := alg.N()
	a := m.Clone()
	out := alg.Identity()

	for k := range n {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}
		if pivot != k {
			a.SwapRowMut(k, pivot)
			out.SwapRowMut(k, pivot)
		}

		pivotVal := a.v[a.idx(k, k)]
		invPivot, err := alg.ring.One().TryDiv(pivotVal)
		if err != nil {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}

		// Normalize pivot row.
		for j := range n {
			a.v[a.idx(k, j)] = a.v[a.idx(k, j)].Mul(invPivot)
			out.v[out.idx(k, j)] = out.v[out.idx(k, j)].Mul(invPivot)
		}

		// Eliminate pivot column from all other rows.
		for i := range n {
			if i == k {
				continue
			}
			factor := a.v[a.idx(i, k)]
			if factor.IsZero() {
				continue
			}
			for j := range n {
				t := factor.Mul(a.v[a.idx(k, j)])
				a.v[a.idx(i, j)] = a.v[a.idx(i, j)].Sub(t)

				t = factor.Mul(out.v[out.idx(k, j)])
				out.v[out.idx(i, j)] = out.v[out.idx(i, j)].Sub(t)
			}
		}
	}
	return out, nil
}

func (m *SquareMatrix[S]) TryDiv(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	inv, err := other.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute inverse for division")
	}
	return m.Mul(inv), nil
}

func (m *SquareMatrix[S]) Determinant() S {
	a := m.Clone()
	n := m.Algebra().N()
	sign := m.Algebra().ring.One()
	det := m.Algebra().ring.One()

	for k := range n {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			return m.Algebra().ring.Zero()
		}
		if pivot != k {
			a.SwapRowMut(k, pivot)
			sign = sign.Neg()
		}

		pivotVal := a.v[a.idx(k, k)]
		det = det.Mul(pivotVal)

		// Forward elimination only (determinant path).
		for i := k + 1; i < n; i++ {
			factor, err := a.v[a.idx(i, k)].TryDiv(pivotVal)
			if err != nil {
				return m.Algebra().ring.Zero()
			}
			for j := k + 1; j < n; j++ {
				t := factor.Mul(a.v[a.idx(k, j)])
				a.v[a.idx(i, j)] = a.v[a.idx(i, j)].Sub(t)
			}
			a.v[a.idx(i, k)] = m.Algebra().ring.Zero()
		}
	}
	return det.Mul(sign)
}

func (m *SquareMatrix[S]) findPivotRow(col int) int {
	for r := col; r < m.Algebra().N(); r++ {
		if !m.v[m.idx(r, col)].IsZero() {
			return r
		}
	}
	return -1
}
