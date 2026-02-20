package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

func NewMatrixAlgebra[S algebra.RingElement[S]](n uint, ring algebra.Ring[S]) (*MatrixAlgebra[S], error) {
	matrixModule, err := NewMatrixModule(n, n, ring)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create matrix module")
	}
	return &MatrixAlgebra[S]{
		MatrixModule: *matrixModule,
	}, nil
}

type MatrixAlgebra[S algebra.RingElement[S]] struct {
	MatrixModule[S]
}

func (a *MatrixAlgebra[S]) New(rows [][]S) (*SquareMatrix[S], error) {
	matrix, err := a.MatrixModule.New(rows)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create matrix")
	}
	if matrix.rows != matrix.cols {
		return nil, errs.New("matrix must be square")
	}
	return &SquareMatrix[S]{
		Matrix: *matrix,
	}, nil
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
		identity.data[i*n+i] = a.ring.One()
	}
	return identity
}

func (a *MatrixAlgebra[S]) FromBytes(data []byte) (*SquareMatrix[S], error) {
	out, err := a.MatrixModule.FromBytes(data)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to parse matrix from bytes")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (a *MatrixAlgebra[S]) IsDomain() bool {
	return a.N() == 1 && a.ring.IsDomain()
}

func (a *MatrixAlgebra[S]) One() *SquareMatrix[S] {
	return a.Identity()
}

func (a *MatrixAlgebra[S]) OpIdentity() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *a.MatrixModule.OpIdentity(),
	}
}

func (a *MatrixAlgebra[S]) Zero() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *a.MatrixModule.Zero(),
	}
}

type SquareMatrix[S algebra.RingElement[S]] struct {
	Matrix[S]
}

func (m *SquareMatrix[S]) algebra() *MatrixAlgebra[S] {
	return &MatrixAlgebra[S]{
		MatrixModule: *m.module(),
	}
}

func (m *SquareMatrix[S]) Structure() algebra.Structure[*SquareMatrix[S]] {
	return m.algebra()
}

func (m *SquareMatrix[S]) OpMut(other *SquareMatrix[S]) *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.OpMut(&other.Matrix),
	}
}

func (m *SquareMatrix[S]) Op(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Clone().OpMut(other)
}

func (m *SquareMatrix[S]) AddMut(other *SquareMatrix[S]) *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.AddMut(&other.Matrix),
	}
}

func (m *SquareMatrix[S]) Add(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Clone().AddMut(other)
}

func (m *SquareMatrix[S]) SubMut(other *SquareMatrix[S]) *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.SubMut(&other.Matrix),
	}
}

func (m *SquareMatrix[S]) TrySub(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	return m.Sub(other), nil
}

func (m *SquareMatrix[S]) Sub(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Clone().SubMut(other)
}

func (m *SquareMatrix[S]) Double() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.Double(),
	}
}

func (m *SquareMatrix[S]) OpInvMut() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.OpInvMut(),
	}
}

func (m *SquareMatrix[S]) OpInv() *SquareMatrix[S] {
	return m.Clone().OpInvMut()
}

func (m *SquareMatrix[S]) NegMut() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.NegMut(),
	}
}

func (m *SquareMatrix[S]) TryNeg() (*SquareMatrix[S], error) {
	return m.Neg(), nil
}

func (m *SquareMatrix[S]) Neg() *SquareMatrix[S] {
	return m.Clone().NegMut()
}

func (m *SquareMatrix[S]) Transpose() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.Transpose(),
	}
}

func (m *SquareMatrix[S]) ColumnAddMut(i, j int, scalar S) (*SquareMatrix[S], error) {
	out, err := m.Matrix.ColumnAddMut(i, j, scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to add column")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) ColumnAdd(i, j int, scalar S) (*SquareMatrix[S], error) {
	return m.Clone().ColumnAddMut(i, j, scalar)
}

func (m *SquareMatrix[S]) RowAddMut(i, j int, scalar S) (*SquareMatrix[S], error) {
	out, err := m.Matrix.RowAddMut(i, j, scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to add row")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) RowAdd(i, j int, scalar S) (*SquareMatrix[S], error) {
	return m.Clone().RowAddMut(i, j, scalar)
}

func (m *SquareMatrix[S]) ColumnScalarMulMut(i int, scalar S) (*SquareMatrix[S], error) {
	out, err := m.Matrix.ColumnScalarMulMut(i, scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to multiply column by scalar")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) ColumnScalarMul(i int, scalar S) (*SquareMatrix[S], error) {
	return m.Clone().ColumnScalarMulMut(i, scalar)
}

func (m *SquareMatrix[S]) RowScalarMulMut(i int, scalar S) (*SquareMatrix[S], error) {
	out, err := m.Matrix.RowScalarMulMut(i, scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to multiply row by scalar")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) RowScalarMul(i int, scalar S) (*SquareMatrix[S], error) {
	return m.Clone().RowScalarMulMut(i, scalar)
}

func (m *SquareMatrix[S]) SwapColumnMut(i, j int) (*SquareMatrix[S], error) {
	out, err := m.Matrix.SwapColumnMut(i, j)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to swap columns")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) SwapColumn(i, j int) (*SquareMatrix[S], error) {
	return m.Clone().SwapColumnMut(i, j)
}

func (m *SquareMatrix[S]) SwapRowMut(i, j int) (*SquareMatrix[S], error) {
	out, err := m.Matrix.SwapRowMut(i, j)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to swap rows")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) SwapRow(i, j int) (*SquareMatrix[S], error) {
	return m.Clone().SwapRowMut(i, j)
}

func (m *SquareMatrix[S]) TryMul(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	return m.Mul(other), nil
}

func (m *SquareMatrix[S]) OtherOp(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Mul(other)
}

func (m *SquareMatrix[S]) MulMut(other *SquareMatrix[S]) *SquareMatrix[S] {
	ring := m.module().ring
	result := make([]S, len(m.data))
	for i := range m.rows {
		for j := range other.cols {
			sum := ring.Zero()
			for k := range m.cols {
				sum = sum.Add(m.data[i*m.cols+k].Mul(other.data[k*other.cols+j]))
			}
			result[i*other.cols+j] = sum
		}
	}
	copy(m.data, result)
	return m
}

func (m *SquareMatrix[S]) Mul(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Clone().MulMut(other)
}

func (m *SquareMatrix[S]) Square() *SquareMatrix[S] {
	return m.Mul(m)
}

func (m *SquareMatrix[S]) Minor(row, col int) (*SquareMatrix[S], error) {
	out, err := m.Matrix.Minor(row, col)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute minor")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) HadamardProductMut(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	out, err := m.Matrix.HadamardProductMut(&other.Matrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute Hadamard product")
	}
	return &SquareMatrix[S]{
		Matrix: *out,
	}, nil
}

func (m *SquareMatrix[S]) HadamardProduct(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	return m.Clone().HadamardProductMut(other)
}

func (m *SquareMatrix[S]) ScalarOpMut(scalar S) *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.ScalarOpMut(scalar),
	}
}

func (m *SquareMatrix[S]) ScalarOp(scalar S) *SquareMatrix[S] {
	return m.Clone().ScalarOpMut(scalar)
}

func (m *SquareMatrix[S]) ScalarMulMut(scalar S) *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.ScalarMulMut(scalar),
	}
}

func (m *SquareMatrix[S]) ScalarMul(scalar S) *SquareMatrix[S] {
	return m.Clone().ScalarMulMut(scalar)
}

func (m *SquareMatrix[S]) Equal(other *SquareMatrix[S]) bool {
	return other != nil && m.Matrix.Equal(&other.Matrix)
}

func (m *SquareMatrix[S]) IsIdentity() bool {
	n := m.algebra().N()
	one := m.algebra().ring.One()
	for i, v := range m.data {
		row, col := i/n, i%n
		if row == col {
			if !v.Equal(one) {
				return false
			}
		} else {
			if !v.IsZero() {
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
	alg := m.algebra()
	trace := alg.ring.Zero()
	n := alg.N()
	for i := range n {
		trace = trace.Add(m.data[m.idx(i, i)])
	}
	return trace
}

func (m *SquareMatrix[S]) TryInv() (*SquareMatrix[S], error) {
	alg := m.algebra()
	n := alg.N()
	a := m.Clone()
	out := alg.Identity()

	for k := range n {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}
		if pivot != k {
			a.Matrix.SwapRowMut(k, pivot)
			out.Matrix.SwapRowMut(k, pivot)
		}

		pivotVal := a.data[a.idx(k, k)]
		invPivot, err := alg.ring.One().TryDiv(pivotVal)
		if err != nil {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}

		// Normalize pivot row.
		for j := range n {
			a.data[a.idx(k, j)] = a.data[a.idx(k, j)].Mul(invPivot)
			out.data[out.idx(k, j)] = out.data[out.idx(k, j)].Mul(invPivot)
		}

		// Eliminate pivot column from all other rows.
		for i := range n {
			if i == k {
				continue
			}
			factor := a.data[a.idx(i, k)]
			if factor.IsZero() {
				continue
			}
			for j := range n {
				t := factor.Mul(a.data[a.idx(k, j)])
				a.data[a.idx(i, j)] = a.data[a.idx(i, j)].Sub(t)

				t = factor.Mul(out.data[out.idx(k, j)])
				out.data[out.idx(i, j)] = out.data[out.idx(i, j)].Sub(t)
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
	n := m.algebra().N()
	sign := m.algebra().ring.One()
	det := m.algebra().ring.One()

	for k := range n {
		pivot := a.findPivotRow(k)
		if pivot < 0 {
			return m.algebra().ring.Zero()
		}
		if pivot != k {
			a.Matrix.SwapRowMut(k, pivot)
			sign = sign.Neg()
		}

		pivotVal := a.data[a.idx(k, k)]
		det = det.Mul(pivotVal)

		// Forward elimination only (determinant path).
		for i := k + 1; i < n; i++ {
			factor, err := a.data[a.idx(i, k)].TryDiv(pivotVal)
			if err != nil {
				return m.algebra().ring.Zero()
			}
			for j := k + 1; j < n; j++ {
				t := factor.Mul(a.data[a.idx(k, j)])
				a.data[a.idx(i, j)] = a.data[a.idx(i, j)].Sub(t)
			}
			a.data[a.idx(i, k)] = m.algebra().ring.Zero()
		}
	}
	return det.Mul(sign)
}

func (m *SquareMatrix[S]) findPivotRow(col int) int {
	for r := col; r < m.algebra().N(); r++ {
		if !m.data[m.idx(r, col)].IsZero() {
			return r
		}
	}
	return -1
}

func (m *SquareMatrix[S]) idx(r, c int) int {
	n := m.algebra().N()
	return r*n + c
}

func (m *SquareMatrix[S]) Clone() *SquareMatrix[S] {
	return &SquareMatrix[S]{
		Matrix: *m.Matrix.Clone(),
	}
}
