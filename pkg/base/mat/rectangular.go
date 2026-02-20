package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

func NewMatrixModule[S algebra.RingElement[S]](rows, cols uint, ring algebra.Ring[S]) (*MatrixModule[S], error) {
	if rows == 0 || cols == 0 {
		return nil, ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", rows, cols)
	}
	if ring == nil {
		return nil, ErrFailed.WithMessage("ring cannot be nil")
	}
	return &MatrixModule[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *Matrix[S], Matrix[S]]{
			rows: int(rows),
			cols: int(cols),
			ring: ring,
		},
	}, nil
}

type MatrixModule[S algebra.RingElement[S]] struct {
	MatrixModuleTrait[S, *Matrix[S], Matrix[S]]
}

func (mm *MatrixModule[S]) New(rows [][]S) (*Matrix[S], error) {
	m, n := len(rows), len(rows[0])
	if m == 0 || n == 0 {
		return nil, ErrFailed.WithMessage("matrix dimensions must be positive: got %dx%d", m, n)
	}
	matrix := &Matrix[S]{}
	matrix.init(m, n)
	for i := range rows {
		if len(rows[i]) != matrix.n {
			return nil, ErrFailed.WithMessage("all rows must have the same number of columns: row 0 has %d columns but row %d has %d columns", matrix.cols, i, len(rows[i]))
		}
		copy(matrix.v[i*matrix.n:(i+1)*matrix.n], rows[i])
	}
	return matrix, nil
}

type Matrix[S algebra.RingElement[S]] struct {
	MatrixTrait[S, *Matrix[S], Matrix[S]]
}

func (m *Matrix[S]) init(rows, cols int) {
	m.MatrixTrait = MatrixTrait[S, *Matrix[S], Matrix[S]]{
		self: m,
		m:    rows,
		n:    cols,
		v:    make([]S, rows*cols),
	}
}

func (m *Matrix[S]) rows() int {
	return m.m
}

func (m *Matrix[S]) cols() int {
	return m.n
}

func (m *Matrix[S]) data() []S {
	return m.v
}

func (m *Matrix[S]) Module() *MatrixModule[S] {
	return &MatrixModule[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *Matrix[S], Matrix[S]]{
			rows: m.rows(),
			cols: m.cols(),
			ring: m.scalarRing(),
		},
	}
}

func (m *Matrix[S]) Structure() algebra.Structure[*Matrix[S]] {
	return m.Module()
}
