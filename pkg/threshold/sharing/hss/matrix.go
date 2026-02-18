package hss

import "github.com/bronlabs/krypton-primitives/pkg/base/curves"

type Matrix struct {
	Rows [][]curves.Scalar
}

func NewMatrix(rows [][]curves.Scalar) *Matrix {
	return &Matrix{Rows: rows}
}

func NewEmptyMatrix(rows, cols uint) *Matrix {
	r := make([][]curves.Scalar, rows)
	for ri := range rows {
		r[ri] = make([]curves.Scalar, cols)
	}

	return &Matrix{
		Rows: r,
	}
}

func (m *Matrix) Clone() *Matrix {
	clone := make([][]curves.Scalar, len(m.Rows))
	for ri, row := range m.Rows {
		clone[ri] = make([]curves.Scalar, len(m.Rows[ri]))
		copy(clone[ri], row)
	}

	return &Matrix{Rows: clone}
}

func (m *Matrix) Set(r, c int, value curves.Scalar) {
	m.Rows[r][c] = value
}

func (m *Matrix) SwapRows(r1, r2 int) {
	m.Rows[r1], m.Rows[r2] = m.Rows[r2], m.Rows[r1]
}

func (m *Matrix) Determinant() curves.Scalar {
	clone := m.Clone()
	det := clone.Rows[0][0].ScalarField().MultiplicativeIdentity()

	for d := range clone.Rows {
		r := -1
		for ri := d; ri < len(clone.Rows); ri++ {
			if !clone.Rows[d][d].IsAdditiveIdentity() {
				r = ri
				break
			}
		}
		if r == -1 {
			return clone.Rows[d][d].ScalarField().AdditiveIdentity()
		}
		if r != d {
			clone.SwapRows(d, r)
			det = det.Neg()
		}

		for ri := d + 1; ri < len(clone.Rows); ri++ {
			if clone.Rows[ri][d].IsAdditiveIdentity() {
				continue
			}

			f, _ := clone.Rows[d][d].Div(clone.Rows[ri][d])
			for ci := range clone.Rows {
				clone.Rows[ri][ci] = clone.Rows[ri][ci].Mul(f).Sub(clone.Rows[d][ci])
			}
			det, _ = det.Div(f)
		}
		det = det.Mul(clone.Rows[d][d])
	}

	return det
}
