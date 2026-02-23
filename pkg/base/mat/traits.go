package mat

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/errs-go/errs"
)

type matrixWrapper[S algebra.RingElement[S]] interface {
	init(rows, cols int)
	idx(row, col int) int
	data() []S
	rows() int
	cols() int
}

type matrixWrapperPtrConstraint[S algebra.RingElement[S], WT any] interface {
	*WT
	matrixWrapper[S]
	Clone() *WT
}

// MatrixModuleTrait provides shared implementation for matrix module structures.
// It is embedded by [MatrixModule] and [MatrixAlgebra] to provide common
// module-level operations: dimensions, serialisation, and zero/identity construction.
type MatrixModuleTrait[S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any] struct {
	ring algebra.FiniteRing[S]
	rows int
	cols int
}

// Name returns a human-readable name for the module, e.g. "M_2x3(fieldName)".
func (mm *MatrixModuleTrait[S, W, WT]) Name() string {
	return fmt.Sprintf("M_%dx%d(%s)", mm.rows, mm.cols, mm.ring.Name())
}

// Dimensions returns the number of rows and columns.
func (mm *MatrixModuleTrait[S, W, WT]) Dimensions() (m, n int) {
	return mm.rows, mm.cols
}

// Order returns the cardinality of the matrix module.
func (mm *MatrixModuleTrait[S, W, WT]) Order() algebra.Cardinal {
	return cardinal.New(uint64(mm.rows) * uint64(mm.cols)).Mul(mm.ring.Order())
}

// ElementSize returns the byte size of a single matrix (rows * cols * scalar size).
func (mm *MatrixModuleTrait[S, W, WT]) ElementSize() int {
	return mm.rows * mm.cols * mm.ring.ElementSize()
}

// IsSquare reports whether the module's matrices are square.
func (mm *MatrixModuleTrait[S, W, WT]) IsSquare() bool {
	return mm.rows == mm.cols
}

// FromBytes deserializes a matrix from a byte slice. The length must match ElementSize.
func (mm *MatrixModuleTrait[S, W, WT]) FromBytes(data []byte) (W, error) {
	if len(data) != mm.ElementSize() {
		return nil, ErrFailed.WithMessage("invalid data length: expected %d bytes, got %d", mm.ElementSize(), len(data))
	}
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	elementSize := mm.ring.ElementSize()
	d := W(&matrix).data()
	for i := range mm.rows * mm.cols {
		start := i * elementSize
		end := start + elementSize
		elementData := data[start:end]
		element, err := mm.ring.FromBytes(elementData)
		if err != nil {
			return nil, ErrFailed.WithMessage("failed to parse element at index %d: %v", i, err)
		}
		d[i] = element
	}
	return W(&matrix), nil
}

// OpIdentity returns the additive identity (zero matrix).
func (mm *MatrixModuleTrait[S, W, WT]) OpIdentity() W {
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	d := W(&matrix).data()
	for i := range d {
		d[i] = mm.ring.OpIdentity()
	}
	return W(&matrix)
}

// Zero returns the zero matrix (alias for [MatrixModuleTrait.OpIdentity]).
func (mm *MatrixModuleTrait[S, W, WT]) Zero() W {
	return mm.OpIdentity()
}

// New creates a matrix from a slice of row slices.
// The number of rows must match the module's row count, all rows must have
// length equal to the module's column count.
func (mm *MatrixModuleTrait[S, W, WT]) New(rows [][]S) (W, error) {
	if len(rows) != mm.rows {
		return nil, ErrDimension.WithMessage("row count mismatch: module expects %d rows, got %d", mm.rows, len(rows))
	}
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	d := W(&matrix).data()
	for i, row := range rows {
		if len(row) != mm.cols {
			return nil, ErrDimension.WithMessage("row %d has %d columns, expected %d", i, len(row), mm.cols)
		}
		copy(d[i*mm.cols:(i+1)*mm.cols], row)
	}
	return W(&matrix), nil
}

// NewRowMajor creates a matrix from elements in row-major order.
// The number of elements must equal rows * cols of the module.
func (mm *MatrixModuleTrait[S, W, WT]) NewRowMajor(elements ...S) (W, error) {
	total := mm.rows * mm.cols
	if len(elements) != total {
		return nil, ErrDimension.WithMessage("element count mismatch: expected %d, got %d", total, len(elements))
	}
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	copy(W(&matrix).data(), elements)
	return W(&matrix), nil
}

// Random generates a matrix with uniformly random elements from the scalar ring.
func (mm *MatrixModuleTrait[S, W, WT]) Random(prng io.Reader) (W, error) {
	values := make([]S, mm.rows*mm.cols)
	var err error
	for i := range values {
		values[i], err = mm.ring.Random(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to generate random element for matrix")
		}
	}
	out, err := mm.NewRowMajor(values...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create random matrix")
	}
	return out, nil
}

// Hash derives a matrix deterministically from the given data.
// Each element is hashed independently using an index-prefixed domain separation
// scheme (SHA3-256), ensuring distinct elements for the same input.
func (mm *MatrixModuleTrait[S, W, WT]) Hash(data []byte) (W, error) {
	values := make([]S, mm.rows*mm.cols)
	for i := range values {
		di, err := hashing.HashIndexLengthPrefixed(sha3.New256, binary.BigEndian.AppendUint64(nil, uint64(i)), data)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to hash data for matrix element %d", i)
		}
		values[i], err = mm.ring.Hash(di)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to hash element for matrix")
		}
	}
	out, err := mm.NewRowMajor(values...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create hashed matrix")
	}
	return out, nil
}

// ScalarStructure returns the algebraic structure of the scalar ring.
func (mm *MatrixModuleTrait[S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return mm.ring
}

// ScalarRing returns the underlying finite scalar ring.
func (mm *MatrixModuleTrait[S, W, WT]) ScalarRing() algebra.FiniteRing[S] {
	return mm.ring
}

// MatrixTrait provides shared implementation for matrix element types.
// It is embedded by [Matrix] and [SquareMatrix] to provide element access,
// arithmetic, row/column operations, and linear system solving.
//
// Type parameters:
//   - S: the scalar ring element type
//   - W/WT: the concrete matrix wrapper type (self-referential for CRTP)
//   - RectW/RectWT: the rectangular matrix type used by Augment and Stack
type MatrixTrait[S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any, RectW matrixWrapperPtrConstraint[S, RectWT], RectWT any] struct {
	self W
	m, n int
	v    []S
}

func (m *MatrixTrait[S, W, WT, RectW, RectWT]) scalarRing() algebra.FiniteRing[S] {
	return algebra.StructureMustBeAs[algebra.FiniteRing[S]](m.v[0].Structure())
}

func (m *MatrixTrait[S, W, WT, RectW, RectWT]) idx(row, col int) int {
	return row*m.n + col
}

// Dimensions returns the number of rows and columns.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Dimensions() (rows, cols int) {
	return m.m, m.n
}

// Get returns the element at (row, col), or an error if out of bounds.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Get(row, col int) (S, error) {
	if row < 0 || row >= m.m || col < 0 || col >= m.n {
		return *new(S), ErrDimension.WithMessage("index out of bounds: row %d, col %d for matrix of dimensions %dx%d", row, col, m.m, m.n)
	}
	return m.v[m.idx(row, col)], nil
}

// GetRow returns a copy of the i-th row.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) GetRow(i int) (RectW, error) {
	if i < 0 || i >= m.m {
		return nil, ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
	}
	var rowMatrix RectWT
	RectW(&rowMatrix).init(1, m.n)
	copy(RectW(&rowMatrix).data(), m.v[i*m.n:(i+1)*m.n])
	return RectW(&rowMatrix), nil
}

// IterRows yields each row as a RectW matrix in sequence. The yielded row is a copy and can be safely modified by the caller.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IterRows() iter.Seq[RectW] {
	return func(yield func(RectW) bool) {
		for i := range m.m {
			rowi, err := m.GetRow(i)
			if err != nil {
				panic(errs.Wrap(err).WithMessage("failed to get row %d during IterRows", i))
			}
			if !yield(rowi) {
				return
			}
		}
	}
}

// GetColumn returns a copy of the j-th column.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) GetColumn(j int) (RectW, error) {
	if j < 0 || j >= m.n {
		return nil, ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", j, m.n)
	}
	var colMatrix RectWT
	RectW(&colMatrix).init(m.m, 1)
	for i := range m.m {
		RectW(&colMatrix).data()[i] = m.v[m.idx(i, j)]
	}
	return RectW(&colMatrix), nil
}

// IterColumns yields each column as a RectW matrix in sequence. The yielded column is a copy and can be safely modified by the caller.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IterColumns() iter.Seq[RectW] {
	return func(yield func(RectW) bool) {
		for j := range m.n {
			colj, err := m.GetColumn(j)
			if err != nil {
				panic(errs.Wrap(err).WithMessage("failed to get column %d during IterColumns", j))
			}
			if !yield(colj) {
				return
			}
		}
	}
}

// Op returns the group operation result (addition). Alias for [MatrixTrait.Add].
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Op(other W) W {
	return m.Add(other)
}

// AddAssign adds other to m in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) AddAssign(other W) {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		panic(ErrDimension.WithMessage("cannot add: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols()))
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Add(otherData[i])
	}
}

// Add returns m + other as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Add(other W) W {
	c := m.clone()
	c.AddAssign(other)
	return c.self
}

// SubAssign subtracts other from m in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SubAssign(other W) {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		panic(ErrDimension.WithMessage("cannot subtract: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols()))
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Sub(otherData[i])
	}
}

// TrySub returns m - other. The error return exists for interface compatibility.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) TrySub(other W) (W, error) {
	return m.Sub(other), nil
}

// Sub returns m - other as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Sub(other W) W {
	c := m.clone()
	c.SubAssign(other)
	return c.self
}

// DoubleAssign doubles m in place: m = m + m.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) DoubleAssign() {
	m.AddAssign(m.self)
}

// Double returns 2*m as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Double() W {
	c := m.clone()
	c.DoubleAssign()
	return c.self
}

// OpInv returns the additive inverse (alias for [MatrixTrait.Neg]).
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) OpInv() W {
	return m.Neg()
}

// NegAssign negates m in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) NegAssign() {
	for i := range m.v {
		m.v[i] = m.v[i].Neg()
	}
}

// TryNeg returns -m. The error return exists for interface compatibility.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) TryNeg() (W, error) {
	return m.Neg(), nil
}

// Neg returns -m as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Neg() W {
	c := m.clone()
	c.NegAssign()
	return c.self
}

// IsOpIdentity reports whether m is the additive identity (alias for [MatrixTrait.IsZero]).
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IsOpIdentity() bool {
	return m.IsZero()
}

// IsZero reports whether all elements are zero.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IsZero() bool {
	for i := range m.v {
		if !m.v[i].IsZero() {
			return false
		}
	}
	return true
}

// IsDiagonal reports whether all off-diagonal elements are zero.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IsDiagonal() bool {
	for i := range m.m {
		for j := range m.n {
			if i != j && !m.v[m.idx(i, j)].IsZero() {
				return false
			}
		}
	}
	return true
}

// IsSquare reports whether the matrix has equal rows and columns.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IsSquare() bool {
	return m.m == m.n
}

// ColumnAddAssign adds scalar * column i to column j in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ColumnAddAssign(i, j int, scalar S) error {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		return ErrDimension.WithMessage("column index out of bounds: i=%d, j=%d for matrix with %d columns", i, j, m.n)
	}
	for row := range m.m {
		m.v[m.idx(row, j)] = m.v[m.idx(row, j)].Add(m.v[m.idx(row, i)].Mul(scalar))
	}
	return nil
}

// ColumnAdd returns a new matrix with scalar * column i added to column j.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ColumnAdd(i, j int, scalar S) (W, error) {
	c := m.clone()
	if err := c.ColumnAddAssign(i, j, scalar); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to add column %d to column %d with scalar %v", i, j, scalar)
	}
	return c.self, nil
}

// RowAddAssign adds scalar * row i to row j in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowAddAssign(i, j int, scalar S) error {
	if i < 0 || i >= m.m || j < 0 || j >= m.m {
		return ErrDimension.WithMessage("row index out of bounds: i=%d, j=%d for matrix with %d rows", i, j, m.m)
	}
	for col := range m.n {
		m.v[m.idx(j, col)] = m.v[m.idx(j, col)].Add(m.v[m.idx(i, col)].Mul(scalar))
	}
	return nil
}

// RowAdd returns a new matrix with scalar * row i added to row j.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowAdd(i, j int, scalar S) (W, error) {
	c := m.clone()
	if err := c.RowAddAssign(i, j, scalar); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to add row %d to row %d", i, j)
	}
	return c.self, nil
}

// ColumnScalarMulAssign multiplies column i by scalar in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ColumnScalarMulAssign(i int, scalar S) error {
	if i < 0 || i >= m.n {
		return ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", i, m.n)
	}
	for row := range m.m {
		m.v[m.idx(row, i)] = m.v[m.idx(row, i)].Mul(scalar)
	}
	return nil
}

// ColumnScalarMul returns a new matrix with column i multiplied by scalar.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ColumnScalarMul(i int, scalar S) (W, error) {
	c := m.clone()
	if err := c.ColumnScalarMulAssign(i, scalar); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to scale column %d", i)
	}
	return c.self, nil
}

// RowScalarMulAssign multiplies row i by scalar in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowScalarMulAssign(i int, scalar S) error {
	if i < 0 || i >= m.m {
		return ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
	}
	for col := range m.n {
		m.v[m.idx(i, col)] = m.v[m.idx(i, col)].Mul(scalar)
	}
	return nil
}

// RowScalarMul returns a new matrix with row i multiplied by scalar.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowScalarMul(i int, scalar S) (W, error) {
	c := m.clone()
	if err := c.RowScalarMulAssign(i, scalar); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to scale row %d", i)
	}
	return c.self, nil
}

// Augment concatenates other as additional columns: [m | other].
// The result is always a rectangular matrix (RectW), even when called on a square matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Augment(other RectW) (RectW, error) {
	if m.m != other.rows() {
		return nil, ErrDimension.WithMessage("cannot concatenate columns: number of rows in first matrix (%d) does not match number of rows in second matrix (%d)", m.m, other.rows())
	}
	var out RectWT
	RectW(&out).init(m.m, m.n+other.cols())
	d := RectW(&out).data()
	otherData := other.data()
	for i := range m.m {
		copy(d[i*(m.n+other.cols()):i*(m.n+other.cols())+m.n], m.v[i*m.n:(i+1)*m.n])
		copy(d[i*(m.n+other.cols())+m.n:(i+1)*(m.n+other.cols())], otherData[i*other.cols():(i+1)*other.cols()])
	}
	return RectW(&out), nil
}

// Stack concatenates other as additional rows: [m; other].
// The result is always a rectangular matrix (RectW), even when called on a square matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Stack(other RectW) (RectW, error) {
	if m.n != other.cols() {
		return nil, ErrDimension.WithMessage("cannot concatenate rows: number of columns in first matrix (%d) does not match number of columns in second matrix (%d)", m.n, other.cols())
	}
	var out RectWT
	RectW(&out).init(m.m+other.rows(), m.n)
	d := RectW(&out).data()
	otherData := other.data()
	copy(d[:m.m*m.n], m.v)
	copy(d[m.m*m.n:], otherData)
	return RectW(&out), nil
}

// SubMatrixGivenRows returns a submatrix containing the specified row indices and all columns.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SubMatrixGivenRows(indices ...int) (RectW, error) {
	if len(indices) == 0 {
		return nil, ErrDimension.WithMessage("must specify at least one row index")
	}
	for _, i := range indices {
		if i < 0 || i >= m.m {
			return nil, ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
		}
	}
	var out RectWT
	RectW(&out).init(len(indices), m.n)
	d := RectW(&out).data()
	for j, i := range indices {
		copy(d[j*m.n:(j+1)*m.n], m.v[i*m.n:(i+1)*m.n])
	}
	return RectW(&out), nil
}

// RowSlice returns a submatrix containing rows from start (inclusive) to end (exclusive) and all columns.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowSlice(start, end int) (RectW, error) {
	if start < 0 || end > m.m || start >= end {
		return nil, ErrDimension.WithMessage("invalid row slice: start=%d, end=%d for matrix with %d rows", start, end, m.m)
	}
	var out RectWT
	RectW(&out).init(end-start, m.n)
	d := RectW(&out).data()
	copy(d, m.v[start*m.n:end*m.n])
	return RectW(&out), nil
}

// SubMatrixGivenColumns returns a submatrix containing the specified column indices and all rows.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SubMatrixGivenColumns(indices ...int) (RectW, error) {
	if len(indices) == 0 {
		return nil, ErrDimension.WithMessage("must specify at least one column index")
	}
	for _, j := range indices {
		if j < 0 || j >= m.n {
			return nil, ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", j, m.n)
		}
	}
	var out RectWT
	RectW(&out).init(m.m, len(indices))
	d := RectW(&out).data()
	for i := range m.m {
		for j, col := range indices {
			d[i*len(indices)+j] = m.v[m.idx(i, col)]
		}
	}
	return RectW(&out), nil
}

// ColumnSlice returns a submatrix containing columns from start (inclusive) to end (exclusive) and all rows.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ColumnSlice(start, end int) (RectW, error) {
	if start < 0 || end > m.n || start >= end {
		return nil, ErrDimension.WithMessage("invalid column slice: start=%d, end=%d for matrix with %d columns", start, end, m.n)
	}
	var out RectWT
	RectW(&out).init(m.m, end-start)
	d := RectW(&out).data()
	for i := range m.m {
		copy(d[i*(end-start):i*(end-start)+(end-start)], m.v[i*m.n+start:i*m.n+end])
	}
	return RectW(&out), nil
}

// SwapColumnAssign swaps columns i and j in place. Panics if indices are out of bounds.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SwapColumnAssign(i, j int) {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		panic(ErrDimension.WithMessage("column index out of bounds: i=%d, j=%d for matrix with %d columns", i, j, m.n))
	}
	for row := range m.m {
		idx1 := m.idx(row, i)
		idx2 := m.idx(row, j)
		m.v[idx1], m.v[idx2] = m.v[idx2], m.v[idx1]
	}
}

// SwapColumn returns a new matrix with columns i and j swapped.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SwapColumn(i, j int) (W, error) {
	c := m.clone()
	c.SwapColumnAssign(i, j)
	return c.self, nil
}

// SwapRowAssign swaps rows i and j in place. Panics if indices are out of bounds.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SwapRowAssign(i, j int) {
	if i < 0 || i >= m.m || j < 0 || j >= m.m {
		panic(ErrDimension.WithMessage("row index out of bounds: i=%d, j=%d for matrix with %d rows", i, j, m.m))
	}
	for col := range m.n {
		idx1 := m.idx(i, col)
		idx2 := m.idx(j, col)
		m.v[idx1], m.v[idx2] = m.v[idx2], m.v[idx1]
	}
}

// SwapRow returns a new matrix with rows i and j swapped.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) SwapRow(i, j int) (W, error) {
	c := m.clone()
	c.SwapRowAssign(i, j)
	return c.self, nil
}

// TryMul returns the matrix product m * other, or an error if dimensions are incompatible.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) TryMul(other W) (W, error) {
	if m.n != other.rows() {
		return nil, ErrDimension.WithMessage("cannot multiply: number of columns in first matrix (%d) does not match number of rows in second matrix (%d)", m.n, other.rows())
	}
	var out WT
	W(&out).init(m.m, other.cols())
	outData := W(&out).data()
	otherData := other.data()
	ring := m.scalarRing()
	for i := range m.m {
		for j := range other.cols() {
			sum := ring.Zero()
			for k := range m.n {
				sum = sum.Add(m.v[m.idx(i, k)].Mul(otherData[other.idx(k, j)]))
			}
			outData[W(&out).idx(i, j)] = sum
		}
	}
	return W(&out), nil
}

// Transpose returns the transpose of m.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Transpose() W {
	var out WT
	W(&out).init(m.n, m.m)
	outData := W(&out).data()
	for i := range m.m {
		for j := range m.n {
			outData[W(&out).idx(j, i)] = m.v[m.idx(i, j)]
		}
	}
	return W(&out)
}

// Minor returns the (m-1)x(n-1) matrix with the given row and column removed.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Minor(row, col int) (W, error) {
	if row < 0 || row >= m.m || col < 0 || col >= m.n {
		return nil, ErrDimension.WithMessage("index out of bounds: row %d, col %d for matrix of dimensions %dx%d", row, col, m.m, m.n)
	}
	var minor WT
	W(&minor).init(m.m-1, m.n-1)
	minorData := W(&minor).data()
	for i := range W(&minor).rows() {
		for j := range W(&minor).cols() {
			srcRow := i
			if srcRow >= row {
				srcRow++
			}
			srcCol := j
			if srcCol >= col {
				srcCol++
			}
			minorData[W(&minor).idx(i, j)] = m.v[m.idx(srcRow, srcCol)]
		}
	}
	return W(&minor), nil
}

// HadamardProductAssign computes the element-wise (Hadamard) product in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) HadamardProductAssign(other W) error {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		return ErrDimension.WithMessage("cannot compute Hadamard product: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols())
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Mul(otherData[i])
	}
	return nil
}

// Spans solves M*x = b where M is this m×n matrix and b is column (length m).
// Returns x as an n×1 rectangular matrix, or an error if b is not in the column span of M.
// Free variables (in underdetermined systems) are set to zero.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Spans(column []S) (RectW, error) {
	if len(column) != m.m {
		return nil, ErrDimension.WithMessage("column length %d does not match matrix row count %d", len(column), m.m)
	}

	// Build column vector as an m×1 rectangular matrix and augment [M | b].
	var bCol RectWT
	RectW(&bCol).init(m.m, 1)
	copy(RectW(&bCol).data(), column)

	aug, err := m.Augment(RectW(&bCol))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to build augmented matrix for Spans")
	}

	sol, err := solveAugmented(m.scalarRing(), aug)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("column is not in the span of the matrix")
	}

	var out RectWT
	RectW(&out).init(m.n, 1)
	copy(RectW(&out).data(), sol)
	return RectW(&out), nil
}

// RowSpans solves x*M = r where M is this m×n matrix and r is row (length n).
// This is equivalent to solving M^T * x^T = r^T.
// Returns x as an m×1 rectangular matrix, or an error if r is not in the row span of M.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) RowSpans(row []S) (RectW, error) {
	if len(row) != m.n {
		return nil, ErrDimension.WithMessage("row length %d does not match matrix column count %d", len(row), m.n)
	}

	// Build augmented matrix [M^T | r] as a rectangular matrix.
	// M^T is n×m, augmented is n × (m+1).
	var aug RectWT
	RectW(&aug).init(m.n, m.m+1)
	augData := RectW(&aug).data()
	augCols := m.m + 1
	for i := range m.n {
		for j := range m.m {
			augData[i*augCols+j] = m.v[j*m.n+i] // M^T[i][j] = M[j][i]
		}
		augData[i*augCols+m.m] = row[i]
	}

	sol, err := solveAugmented(m.scalarRing(), RectW(&aug))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("row is not in the row span of the matrix")
	}

	var out RectWT
	RectW(&out).init(m.m, 1)
	copy(RectW(&out).data(), sol)
	return RectW(&out), nil
}

// HadamardProduct returns the element-wise (Hadamard) product as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) HadamardProduct(other W) (W, error) {
	c := m.clone()
	if err := c.HadamardProductAssign(other); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute Hadamard product")
	}
	return c.self, nil
}

// ScalarOp returns the scalar module operation (alias for [MatrixTrait.ScalarMul]).
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ScalarOp(scalar S) W {
	return m.ScalarMul(scalar)
}

// ScalarMulAssign multiplies every element by scalar in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ScalarMulAssign(scalar S) {
	for i := range m.v {
		m.v[i] = m.v[i].Mul(scalar)
	}
}

// ScalarMul returns a new matrix with every element multiplied by scalar.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) ScalarMul(scalar S) W {
	c := m.clone()
	c.ScalarMulAssign(scalar)
	return c.self
}

// IsTorsionFree reports whether the matrix module is torsion-free.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) IsTorsionFree() bool {
	return m.m == 1 && m.n == 1 && m.scalarRing().IsDomain()
}

// Equal reports whether m and other have the same dimensions and equal elements.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Equal(other W) bool {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		return false
	}
	otherData := other.data()
	for i := range m.v {
		if !m.v[i].Equal(otherData[i]) {
			return false
		}
	}
	return true
}

// Bytes serialises the matrix to bytes by concatenating each scalar's byte representation.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Bytes() []byte {
	scalarSize := m.scalarRing().ElementSize()
	data := make([]byte, len(m.v)*scalarSize)
	for i, element := range m.v {
		copy(data[i*scalarSize:(i+1)*scalarSize], element.Bytes())
	}
	return data
}

// HashCode returns a combined hash of all elements.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) HashCode() base.HashCode {
	acc := base.HashCode(1)
	for _, element := range m.v {
		acc = acc.Combine(element.HashCode())
	}
	return acc
}

// String returns a human-readable representation of the matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) String() string {
	var b strings.Builder
	b.Grow(4 + m.m*(6+m.n*8))

	b.WriteString("[\n")
	for i := range m.m {
		b.WriteString("  [")
		rowOff := i * m.n
		for j := range m.n {
			fmt.Fprint(&b, m.v[rowOff+j])
			if j < m.n-1 {
				b.WriteString(", ")
			}
		}
		b.WriteString("]\n")
	}
	b.WriteByte(']')
	return b.String()
}

// Clone returns a deep copy of the matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Clone() W {
	var cloned WT
	W(&cloned).init(m.m, m.n)
	copy(W(&cloned).data(), m.v)
	return W(&cloned)
}

// findPivotRow returns the first row at or below startRow with a non-zero entry
// in the given column, or -1 if none exists.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) findPivotRow(col, startRow int) int {
	for r := startRow; r < m.m; r++ {
		if !m.v[m.idx(r, col)].IsZero() {
			return r
		}
	}
	return -1
}

func (m *MatrixTrait[S, W, WT, RectW, RectWT]) clone() MatrixTrait[S, W, WT, RectW, RectWT] {
	clonedSelf := m.self.Clone()
	return MatrixTrait[S, W, WT, RectW, RectWT]{
		self: clonedSelf,
		m:    m.m,
		n:    m.n,
		v:    W(clonedSelf).data(),
	}
}

// solveAugmented performs Gauss-Jordan elimination in place on aug, treating
// the last column as the augmented vector b in [A | b]. It returns the solution
// as a slice of length (cols-1), or an error if the system is inconsistent.
// Free variables are set to zero. aug is modified in place.
func solveAugmented[S algebra.RingElement[S]](ring algebra.Ring[S], aug matrixWrapper[S]) ([]S, error) {
	rows, cols := aug.rows(), aug.cols()
	numVars := cols - 1
	d := aug.data()

	pivotCols := make([]int, 0, min(rows, numVars))
	pivotRow := 0

	for pc := 0; pc < numVars && pivotRow < rows; pc++ {
		// Find pivot.
		pr := -1
		for r := pivotRow; r < rows; r++ {
			if !d[aug.idx(r, pc)].IsZero() {
				pr = r
				break
			}
		}
		if pr < 0 {
			continue // free variable
		}

		// Swap rows.
		if pr != pivotRow {
			for j := range cols {
				pi, ri := aug.idx(pivotRow, j), aug.idx(pr, j)
				d[pi], d[ri] = d[ri], d[pi]
			}
		}

		// Scale pivot row so the leading entry becomes 1.
		invPivot, err := ring.One().TryDiv(d[aug.idx(pivotRow, pc)])
		if err != nil {
			return nil, ErrFailed.WithMessage("pivot element is not invertible")
		}
		for j := range cols {
			idx := aug.idx(pivotRow, j)
			d[idx] = d[idx].Mul(invPivot)
		}

		// Eliminate this column from all other rows.
		for i := range rows {
			if i == pivotRow {
				continue
			}
			factor := d[aug.idx(i, pc)]
			if factor.IsZero() {
				continue
			}
			for j := range cols {
				ii, pi := aug.idx(i, j), aug.idx(pivotRow, j)
				d[ii] = d[ii].Sub(factor.Mul(d[pi]))
			}
		}

		pivotCols = append(pivotCols, pc)
		pivotRow++
	}

	// Consistency: any non-pivot row with a non-zero entry in the b column.
	for i := pivotRow; i < rows; i++ {
		if !d[aug.idx(i, numVars)].IsZero() {
			return nil, ErrFailed.WithMessage("system is inconsistent: no solution exists")
		}
	}

	// Extract solution.
	sol := make([]S, numVars)
	for i := range numVars {
		sol[i] = ring.Zero()
	}
	for i, pc := range pivotCols {
		sol[pc] = d[aug.idx(i, numVars)]
	}
	return sol, nil
}
