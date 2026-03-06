package mat

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// NewModuleValuedMatrixModule creates a ModuleValuedMatrixModule for m×n matrices
// over the given finite module.
func NewModuleValuedMatrixModule[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](rows, cols uint, module algebra.FiniteModule[E, S]) (*ModuleValuedMatrixModule[E, S], error) {
	if rows == 0 || cols == 0 {
		return nil, ErrDimension.WithMessage("matrix dimensions must be positive: got %dx%d", rows, cols)
	}
	if module == nil {
		return nil, ErrFailed.WithMessage("module cannot be nil")
	}
	return &ModuleValuedMatrixModule[E, S]{
		MatrixGroupTrait: MatrixGroupTrait[algebra.FiniteModule[E, S], E, *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S]]{
			rows:      int(rows),
			cols:      int(cols),
			structure: module,
		},
	}, nil
}

// LiftMatrix lifts a scalar [Matrix] into a [ModuleValuedMatrix] by applying the
// scalar action of each entry on the given base point.
// Entry (i,j) of the result is basePoint.ScalarOp(m[i,j]).
func LiftMatrix[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](m *Matrix[S], basePoint E) (*ModuleValuedMatrix[E, S], error) {
	if m == nil {
		return nil, ErrFailed.WithMessage("matrix cannot be nil")
	}
	basePointModule := algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](basePoint.Structure())
	module, err := NewModuleValuedMatrixModule(uint(m.m), uint(m.n), basePointModule)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued matrix module")
	}
	elements := make([]E, m.m*m.n)
	for i, c := range m.data() {
		elements[i] = basePoint.ScalarOp(c)
	}
	out, err := module.NewRowMajor(elements...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued matrix")
	}
	return out, nil
}

// ModuleValuedMatrixModule is the algebraic structure (module) for rectangular matrices over a finite module.
// It serves as a factory for [ModuleValuedMatrix] instances and provides module-level properties
// like dimensions, element size, and serialisation.
type ModuleValuedMatrixModule[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	MatrixGroupTrait[algebra.FiniteModule[E, S], E, *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S]]
}

// ScalarStructure returns the algebraic structure of the scalar ring.
func (m *ModuleValuedMatrixModule[E, S]) ScalarStructure() algebra.Structure[S] {
	return m.structure.ScalarStructure()
}

// ModuleValuedMatrix is a generic rectangular matrix over a finite module. Elements are stored in
// row-major order. Arithmetic operations are inherited from [MatrixGroupElementTrait].
type ModuleValuedMatrix[E algebra.ModuleElement[E, S], S algebra.RingElement[S]] struct {
	MatrixGroupElementTrait[E, *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S], *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S]]
}

func (m *ModuleValuedMatrix[E, S]) init(rows, cols int) {
	m.MatrixGroupElementTrait = MatrixGroupElementTrait[E, *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S], *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S]]{
		self: m,
		m:    rows,
		n:    cols,
		v:    make([]E, rows*cols),
	}
}

func (m *ModuleValuedMatrix[E, S]) rows() int {
	return m.m
}

func (m *ModuleValuedMatrix[E, S]) cols() int {
	return m.n
}

func (m *ModuleValuedMatrix[E, S]) data() []E {
	return m.v
}

// Module returns the ModuleValuedMatrixModule that this matrix belongs to.
func (m *ModuleValuedMatrix[E, S]) Module() *ModuleValuedMatrixModule[E, S] {
	return &ModuleValuedMatrixModule[E, S]{
		MatrixGroupTrait: MatrixGroupTrait[algebra.FiniteModule[E, S], E, *ModuleValuedMatrix[E, S], ModuleValuedMatrix[E, S]]{
			rows:      m.rows(),
			cols:      m.cols(),
			structure: algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.scalarGroup()),
		},
	}
}

// Structure returns the algebraic structure for this matrix type.
func (m *ModuleValuedMatrix[E, S]) Structure() algebra.Structure[*ModuleValuedMatrix[E, S]] {
	return m.Module()
}

// IsTorsionFree reports whether this matrix is torsion-free.
// Only true for 1×1 matrices whose single element is torsion-free.
func (m *ModuleValuedMatrix[E, S]) IsTorsionFree() bool {
	return m.m == 1 && m.n == 1 && m.v[0].IsTorsionFree()
}

// ScalarOpAssign multiplies every element by scalar in place.
func (m *ModuleValuedMatrix[E, S]) ScalarOpAssign(scalar S) {
	for i := range m.v {
		m.v[i] = m.v[i].ScalarOp(scalar)
	}
}

// ScalarOp returns a new matrix with every element scaled by scalar.
func (m *ModuleValuedMatrix[E, S]) ScalarOp(scalar S) *ModuleValuedMatrix[E, S] {
	c := m.Clone()
	c.ScalarOpAssign(scalar)
	return c.self
}
