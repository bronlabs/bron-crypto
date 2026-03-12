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
			rows:          int(rows),
			cols:          int(cols),
			baseStructure: module,
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

// LeftAction computes the left module action of a scalar matrix on a module-valued matrix.
// Given actor ∈ M_{m×p}(R) and x ∈ M_{p×n}(M), the result is an m×n module-valued matrix
// where entry (i,j) = Σ_k x[k,j] · actor[i,k].
func LeftAction[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](actor *Matrix[S], x *ModuleValuedMatrix[E, S]) (*ModuleValuedMatrix[E, S], error) {
	if actor == nil || x == nil {
		return nil, ErrFailed.WithMessage("matrices cannot be nil")
	}
	if actor.n != x.rows() {
		return nil, ErrDimension.WithMessage("cannot multiply: number of columns in first matrix (%d) does not match number of rows in second matrix (%d)", actor.n, x.rows())
	}

	baseModule := x.Module().baseStructure
	module, err := NewModuleValuedMatrixModule(uint(actor.m), uint(x.cols()), baseModule)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued matrix module")
	}

	elements := make([]E, actor.m*x.cols())
	aData := actor.data()
	xData := x.data()
	for i := range actor.m {
		for j := range x.cols() {
			sum := baseModule.OpIdentity()
			for k := range actor.n {
				sum = sum.Op(xData[x.idx(k, j)].ScalarOp(aData[actor.idx(i, k)]))
			}
			elements[i*x.cols()+j] = sum
		}
	}

	out, err := module.NewRowMajor(elements...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued matrix")
	}
	return out, nil
}

// RightAction computes the right module action of a scalar matrix on a module-valued matrix.
// Given x ∈ M_{m×p}(M) and actor ∈ M_{p×n}(R), the result is an m×n module-valued matrix
// where entry (i,j) = Σ_k x[i,k] · actor[k,j].
func RightAction[E algebra.ModuleElement[E, S], S algebra.RingElement[S]](x *ModuleValuedMatrix[E, S], actor *Matrix[S]) (*ModuleValuedMatrix[E, S], error) {
	if x == nil || actor == nil {
		return nil, ErrFailed.WithMessage("matrices cannot be nil")
	}
	if x.cols() != actor.m {
		return nil, ErrDimension.WithMessage("cannot multiply: number of columns in first matrix (%d) does not match number of rows in second matrix (%d)", x.cols(), actor.m)
	}

	baseModule := x.Module().baseStructure
	module, err := NewModuleValuedMatrixModule(uint(x.rows()), uint(actor.n), baseModule)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create module-valued matrix module")
	}

	elements := make([]E, x.rows()*actor.n)
	xData := x.data()
	aData := actor.data()
	for i := range x.rows() {
		for j := range actor.n {
			sum := baseModule.OpIdentity()
			for k := range x.cols() {
				sum = sum.Op(xData[x.idx(i, k)].ScalarOp(aData[actor.idx(k, j)]))
			}
			elements[i*actor.n+j] = sum
		}
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
	return m.baseStructure.ScalarStructure()
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
			rows:          m.rows(),
			cols:          m.cols(),
			baseStructure: algebra.StructureMustBeAs[algebra.FiniteModule[E, S]](m.scalarGroup()),
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
