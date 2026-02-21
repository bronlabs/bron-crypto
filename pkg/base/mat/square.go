package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

// NewMatrixAlgebra creates a MatrixAlgebra for n×n square matrices over the given finite ring.
func NewMatrixAlgebra[S algebra.RingElement[S]](n uint, ring algebra.FiniteRing[S]) (*MatrixAlgebra[S], error) {
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

// MatrixAlgebra is the algebraic structure (algebra) for square matrices over a finite ring.
// It extends [MatrixModuleTrait] with multiplicative structure: identity element,
// characteristic, and domain detection. Use it as a factory for [SquareMatrix] instances.
type MatrixAlgebra[S algebra.RingElement[S]] struct {
	MatrixModuleTrait[S, *SquareMatrix[S], SquareMatrix[S]]
}

// N returns the dimension of the square matrices in this algebra.
func (a *MatrixAlgebra[S]) N() int {
	_, n := a.Dimensions()
	return n
}

// Characteristic returns the characteristic of the underlying scalar ring.
func (a *MatrixAlgebra[S]) Characteristic() algebra.Cardinal {
	return a.ring.Characteristic()
}

// Identity returns the n×n identity matrix.
func (a *MatrixAlgebra[S]) Identity() *SquareMatrix[S] {
	identity := a.OpIdentity()
	n := a.N()
	for i := range n {
		identity.v[identity.idx(i, i)] = a.ring.One()
	}
	return identity
}

// IsDomain reports whether the matrix algebra is an integral domain.
// This is only true for 1×1 matrices over a domain.
func (a *MatrixAlgebra[S]) IsDomain() bool {
	return a.N() == 1 && a.ring.IsDomain()
}

// One returns the multiplicative identity (alias for [MatrixAlgebra.Identity]).
func (a *MatrixAlgebra[S]) One() *SquareMatrix[S] {
	return a.Identity()
}

// SquareMatrix is an n×n matrix over a finite ring. It embeds [MatrixTrait] for shared
// operations and adds square-matrix-specific methods: multiplication, determinant,
// inverse, trace, and identity testing. The RectW type parameter is [*Matrix] so
// that operations like Augment return rectangular matrices.
type SquareMatrix[S algebra.RingElement[S]] struct {
	MatrixTrait[S, *SquareMatrix[S], SquareMatrix[S], *Matrix[S], Matrix[S]]
}

func (m *SquareMatrix[S]) init(rows, cols int) {
	if rows != cols {
		panic(ErrDimension.WithMessage("square matrix must have equal number of rows and columns"))
	}
	m.MatrixTrait = MatrixTrait[S, *SquareMatrix[S], SquareMatrix[S], *Matrix[S], Matrix[S]]{
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

// N returns the dimension of this square matrix.
func (m *SquareMatrix[S]) N() int {
	return m.n
}

// AsRectangular returns a rectangular [Matrix] view sharing the same data.
// Mutations to either matrix will be visible in both.
func (m *SquareMatrix[S]) AsRectangular() *Matrix[S] {
	rect := &Matrix[S]{}
	rect.init(m.m, m.n)
	rect.v = m.v // note that we are not copying
	return rect
}

// Algebra returns the MatrixAlgebra that this square matrix belongs to.
func (m *SquareMatrix[S]) Algebra() *MatrixAlgebra[S] {
	return &MatrixAlgebra[S]{
		MatrixModuleTrait: MatrixModuleTrait[S, *SquareMatrix[S], SquareMatrix[S]]{
			rows: m.rows(),
			cols: m.cols(),
			ring: m.scalarRing(),
		},
	}
}

// Structure returns the algebraic structure for this square matrix type.
func (m *SquareMatrix[S]) Structure() algebra.Structure[*SquareMatrix[S]] {
	return m.Algebra()
}

// OtherOp returns the ring's secondary operation (multiplication) applied to two matrices.
func (m *SquareMatrix[S]) OtherOp(other *SquareMatrix[S]) *SquareMatrix[S] {
	return m.Mul(other)
}

// MulAssign multiplies m by other in place: m = m * other.
func (m *SquareMatrix[S]) MulAssign(other *SquareMatrix[S]) {
	if m.n != other.N() {
		panic(ErrDimension.WithMessage("incompatible dimensions for multiplication: %dx%d and %dx%d", m.rows(), m.cols(), other.rows(), other.cols()))
	}
	ring := m.Algebra().ring
	n := m.n
	result := make([]S, n*n)
	for i := range n {
		for j := range n {
			sum := ring.Zero()
			for k := range n {
				sum = sum.Add(m.v[m.idx(i, k)].Mul(other.v[other.idx(k, j)]))
			}
			result[i*n+j] = sum
		}
	}
	copy(m.v, result)
}

// Mul returns the product m * other as a new matrix.
func (m *SquareMatrix[S]) Mul(other *SquareMatrix[S]) *SquareMatrix[S] {
	out, err := m.TryMul(other)
	if err != nil {
		panic(errs.Wrap(err).WithMessage("failed to multiply matrices"))
	}
	return out
}

// SquareAssign squares m in place: m = m * m.
func (m *SquareMatrix[S]) SquareAssign() {
	m.MulAssign(m)
}

// Square returns m * m as a new matrix.
func (m *SquareMatrix[S]) Square() *SquareMatrix[S] {
	return m.Mul(m)
}

// IsIdentity reports whether m is the identity matrix.
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

// IsOne is an alias for [SquareMatrix.IsIdentity].
func (m *SquareMatrix[S]) IsOne() bool {
	return m.IsIdentity()
}

// Trace returns the sum of the diagonal elements.
func (m *SquareMatrix[S]) Trace() S {
	alg := m.Algebra()
	trace := alg.ring.Zero()
	n := alg.N()
	for i := range n {
		trace = trace.Add(m.v[m.idx(i, i)])
	}
	return trace
}

// TryInv computes the inverse of m using Gauss-Jordan elimination.
// Returns an error if the matrix is singular.
func (m *SquareMatrix[S]) TryInv() (*SquareMatrix[S], error) {
	alg := m.Algebra()
	n := alg.N()
	a := m.Clone()
	out := alg.Identity()

	for k := range n {
		pivot := a.findPivotRow(k, k)
		if pivot < 0 {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}
		if pivot != k {
			a.SwapRowAssign(k, pivot)
			out.SwapRowAssign(k, pivot)
		}

		pivotVal := a.v[a.idx(k, k)]
		invPivot, err := alg.ring.One().TryDiv(pivotVal)
		if err != nil {
			return nil, ErrFailed.WithMessage("matrix is singular")
		}

		// Normalise pivot row.
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

// TryDiv computes m * other^(-1). Returns an error if other is singular.
func (m *SquareMatrix[S]) TryDiv(other *SquareMatrix[S]) (*SquareMatrix[S], error) {
	inv, err := other.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute inverse for division")
	}
	return m.Mul(inv), nil
}

// Determinant computes the determinant using Gaussian elimination with partial pivoting.
// Returns the ring's zero element for singular matrices.
func (m *SquareMatrix[S]) Determinant() S {
	a := m.Clone()
	n := m.Algebra().N()
	sign := m.Algebra().ring.One()
	det := m.Algebra().ring.One()

	for k := range n {
		pivot := a.findPivotRow(k, k)
		if pivot < 0 {
			return m.Algebra().ring.Zero()
		}
		if pivot != k {
			a.SwapRowAssign(k, pivot)
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
