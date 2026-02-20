package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// NewMatrixModule creates a MatrixModule for m×n matrices over the given finite ring.
func NewMatrixModule[S algebra.RingElement[S]](rows, cols uint, ring algebra.FiniteRing[S]) (*MatrixModule[S], error) {
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

// MatrixModule is the algebraic structure (module) for rectangular matrices over a finite ring.
// It serves as a factory for [Matrix] instances and provides module-level properties
// like dimensions, element size, and serialisation.
type MatrixModule[S algebra.RingElement[S]] struct {
	MatrixModuleTrait[S, *Matrix[S], Matrix[S]]
}

// Matrix is a generic rectangular matrix over a finite ring. Elements are stored in
// row-major order. Arithmetic operations are inherited from [MatrixTrait].
type Matrix[S algebra.RingElement[S]] struct {
	MatrixTrait[S, *Matrix[S], Matrix[S], *Matrix[S], Matrix[S]]
}

func (m *Matrix[S]) init(rows, cols int) {
	m.MatrixTrait = MatrixTrait[S, *Matrix[S], Matrix[S], *Matrix[S], Matrix[S]]{
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

func (m *Matrix[S]) data() []S { //nolint:unused // false positive: needed for the trait implementation.
	return m.v
}

// Module returns the MatrixModule that this matrix belongs to.
func (m *Matrix[S]) Module() *MatrixModule[S] {
	return &MatrixModule[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *Matrix[S], Matrix[S]]{
			rows: m.rows(),
			cols: m.cols(),
			ring: m.scalarRing(),
		},
	}
}

// Structure returns the algebraic structure for this matrix type.
func (m *Matrix[S]) Structure() algebra.Structure[*Matrix[S]] {
	return m.Module()
}
