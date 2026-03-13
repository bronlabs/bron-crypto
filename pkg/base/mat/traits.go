package mat

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"strings"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

type matrixWrapper[S algebra.GroupElement[S]] interface {
	init(rows, cols int)
	idx(row, col int) int
	data() []S
	rows() int
	cols() int
}

type matrixWrapperPtrConstraint[S algebra.GroupElement[S], WT any] interface {
	*WT
	matrixWrapper[S]
	Clone() *WT
}

// MatrixGroupTrait provides shared implementation for matrix structure types.
// It is embedded by [MatrixModuleTrait] (for ring-valued matrices) and
// [ModuleValuedMatrixModule] (for module-valued matrices) to provide common
// operations: dimensions, serialisation, and zero/identity construction.
type MatrixGroupTrait[G algebra.FiniteGroup[S], S algebra.GroupElement[S], W matrixWrapperPtrConstraint[S, WT], WT any] struct {
	baseStructure G
	rows          int
	cols          int
}

// Name returns a human-readable name for the module, e.g. "M_2x3(groupName)".
func (mm *MatrixGroupTrait[G, S, W, WT]) Name() string {
	return fmt.Sprintf("M_%dx%d(%s)", mm.rows, mm.cols, mm.baseStructure.Name())
}

// Dimensions returns the number of rows and columns.
func (mm *MatrixGroupTrait[G, S, W, WT]) Dimensions() (m, n int) {
	return mm.rows, mm.cols
}

// Order returns the cardinality of the matrix module.
func (mm *MatrixGroupTrait[G, S, W, WT]) Order() algebra.Cardinal {
	return cardinal.New(uint64(mm.rows) * uint64(mm.cols)).Mul(mm.baseStructure.Order())
}

// ElementSize returns the byte size of a single matrix (rows * cols * scalar size).
func (mm *MatrixGroupTrait[G, S, W, WT]) ElementSize() int {
	return mm.rows * mm.cols * mm.baseStructure.ElementSize()
}

// IsSquare reports whether the module's matrices are square.
func (mm *MatrixGroupTrait[G, S, W, WT]) IsSquare() bool {
	return mm.rows == mm.cols
}

// FromBytes deserializes a matrix from a byte slice. The length must match ElementSize.
func (mm *MatrixGroupTrait[G, S, W, WT]) FromBytes(data []byte) (W, error) {
	if len(data) != mm.ElementSize() {
		return nil, ErrFailed.WithMessage("invalid data length: expected %d bytes, got %d", mm.ElementSize(), len(data))
	}
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	elementSize := mm.baseStructure.ElementSize()
	d := W(&matrix).data()
	for i := range mm.rows * mm.cols {
		start := i * elementSize
		end := start + elementSize
		elementData := data[start:end]
		element, err := mm.baseStructure.FromBytes(elementData)
		if err != nil {
			return nil, ErrFailed.WithMessage("failed to parse element at index %d: %v", i, err)
		}
		d[i] = element
	}
	return W(&matrix), nil
}

// OpIdentity returns the additive identity (zero matrix).
func (mm *MatrixGroupTrait[G, S, W, WT]) OpIdentity() W {
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	d := W(&matrix).data()
	for i := range d {
		d[i] = mm.baseStructure.OpIdentity()
	}
	return W(&matrix)
}

// Zero returns the zero matrix (alias for [MatrixGroupTrait.OpIdentity]).
func (mm *MatrixGroupTrait[G, S, W, WT]) Zero() W {
	return mm.OpIdentity()
}

// New creates a matrix from a slice of row slices.
// The number of rows must match the module's row count, all rows must have
// length equal to the module's column count.
func (mm *MatrixGroupTrait[G, S, W, WT]) New(rows [][]S) (W, error) {
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
func (mm *MatrixGroupTrait[G, S, W, WT]) NewRowMajor(elements ...S) (W, error) {
	total := mm.rows * mm.cols
	if len(elements) != total {
		return nil, ErrDimension.WithMessage("element count mismatch: expected %d, got %d", total, len(elements))
	}
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	copy(W(&matrix).data(), elements)
	return W(&matrix), nil
}

// Random generates a matrix with uniformly random elements from the underlying structure.
func (mm *MatrixGroupTrait[G, S, W, WT]) Random(prng io.Reader) (W, error) {
	values := make([]S, mm.rows*mm.cols)
	var err error
	for i := range values {
		values[i], err = mm.baseStructure.Random(prng)
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
func (mm *MatrixGroupTrait[G, S, W, WT]) Hash(data []byte) (W, error) {
	values := make([]S, mm.rows*mm.cols)
	for i := range values {
		di, err := hashing.HashIndexLengthPrefixed(sha3.New256, binary.BigEndian.AppendUint64(nil, uint64(i)), data)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to hash data for matrix element %d", i)
		}
		values[i], err = mm.baseStructure.Hash(di)
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

// ScalarStructure returns the algebraic structure of the element group.
func (mm *MatrixGroupTrait[G, S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return mm.baseStructure
}

// MatrixModuleTrait extends [MatrixGroupTrait] with ring-specific structure operations.
// It is embedded by [MatrixModule] and [MatrixAlgebra] to provide access to the
// scalar ring and standard basis vector construction.
type MatrixModuleTrait[R algebra.FiniteRing[S], S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any, RectW matrixWrapperPtrConstraint[S, RectWT], RectWT any] struct {
	MatrixGroupTrait[R, S, W, WT]
}

// ScalarRing returns the underlying ring of scalars.
func (mm *MatrixModuleTrait[R, S, W, WT, RectW, RectWT]) ScalarRing() algebra.Ring[S] {
	return mm.baseStructure
}

// NewStandardUnit returns the i-th standard basis row vector: a 1×cols matrix
// with one in column i and zero elsewhere.
func (mm *MatrixModuleTrait[R, S, W, WT, RectW, RectWT]) NewStandardUnit(i int) (RectW, error) {
	if i < 0 || i >= mm.cols {
		return nil, ErrDimension.WithMessage("standard unit index out of bounds: %d for module with %d columns", i, mm.cols)
	}
	var matrix RectWT
	RectW(&matrix).init(1, mm.cols)
	d := RectW(&matrix).data()
	for j := range d {
		d[j] = mm.baseStructure.Zero()
	}
	d[i] = mm.baseStructure.One()
	return RectW(&matrix), nil
}

// MatrixGroupElementTrait provides shared implementation for matrix element types.
// It is embedded by [Matrix], [SquareMatrix], and [ModuleValuedMatrix] to provide
// element access, group arithmetic, row/column operations, and structural queries.
//
// Type parameters:
//   - S: the element type (group element)
//   - W/WT: the concrete matrix wrapper type (self-referential for CRTP)
//   - RectW/RectWT: the rectangular matrix type used by Augment and Stack
type MatrixGroupElementTrait[S algebra.GroupElement[S], W matrixWrapperPtrConstraint[S, WT], WT any, RectW matrixWrapperPtrConstraint[S, RectWT], RectWT any] struct {
	self W
	m, n int
	v    []S
}

func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) scalarGroup() algebra.FiniteGroup[S] {
	return algebra.StructureMustBeAs[algebra.FiniteGroup[S]](m.v[0].Structure())
}

func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) idx(row, col int) int {
	return row*m.n + col
}

// Dimensions returns the number of rows and columns.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Dimensions() (rows, cols int) {
	return m.m, m.n
}

// Get returns the element at (row, col), or an error if out of bounds.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Get(row, col int) (S, error) {
	if row < 0 || row >= m.m || col < 0 || col >= m.n {
		return *new(S), ErrDimension.WithMessage("index out of bounds: row %d, col %d for matrix of dimensions %dx%d", row, col, m.m, m.n)
	}
	return m.v[m.idx(row, col)], nil
}

// GetRow returns a copy of the i-th row.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) GetRow(i int) (RectW, error) {
	if i < 0 || i >= m.m {
		return nil, ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
	}
	var rowMatrix RectWT
	RectW(&rowMatrix).init(1, m.n)
	copy(RectW(&rowMatrix).data(), m.v[i*m.n:(i+1)*m.n])
	return RectW(&rowMatrix), nil
}

// IterRows yields each row as a RectW matrix in sequence. The yielded row is a copy and can be safely modified by the caller.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IterRows() iter.Seq[RectW] {
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

// IterInRow yields each element in the i-th row in sequence. The yielded elements are copies and can be safely modified by the caller.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IterInRow(i int) iter.Seq[S] {
	return func(yield func(S) bool) {
		row, err := m.GetRow(i)
		if err != nil {
			return
		}
		for _, ri := range row.data() {
			if !yield(ri.Clone()) {
				return
			}
		}
	}
}

// GetColumn returns a copy of the j-th column.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) GetColumn(j int) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IterColumns() iter.Seq[RectW] {
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

// IterInColumn yields each element in the j-th column in sequence. The yielded elements are copies and can be safely modified by the caller.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IterInColumn(j int) iter.Seq[S] {
	return func(yield func(S) bool) {
		column, err := m.GetColumn(j)
		if err != nil {
			return
		}
		for _, ci := range column.data() {
			if !yield(ci.Clone()) {
				return
			}
		}
	}
}

// Iter yields each element in the matrix in row-major order. The yielded elements are copies and can be safely modified by the caller.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Iter() iter.Seq[S] {
	return func(yield func(S) bool) {
		for i := range m.v {
			if !yield(m.v[i].Clone()) {
				return
			}
		}
	}
}

// OpAssign adds other to m element-wise in place using the group operation.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) OpAssign(other W) {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		panic(ErrDimension.WithMessage("cannot add: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols()))
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Op(otherData[i])
	}
}

// Op returns the element-wise group operation of m and other as a new matrix.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Op(other W) W {
	c := m.clone()
	c.OpAssign(other)
	return c.self
}

// OpInvAssign inverts every element under the group operation in place.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) OpInvAssign() {
	for i := range m.v {
		m.v[i] = m.v[i].OpInv()
	}
}

// OpInv returns the element-wise group inverse as a new matrix.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) OpInv() W {
	c := m.clone()
	c.OpInvAssign()
	return c.self
}

// IsOpIdentity reports whether every element is the group identity.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsOpIdentity() bool {
	for i := range m.v {
		if !m.v[i].IsOpIdentity() {
			return false
		}
	}
	return true
}

// IsDiagonal reports whether all off-diagonal elements are the group identity.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsDiagonal() bool {
	for i := range m.m {
		for j := range m.n {
			if i != j && !m.v[m.idx(i, j)].IsOpIdentity() {
				return false
			}
		}
	}
	return true
}

// IsSquare reports whether the matrix has equal rows and columns.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsSquare() bool {
	return m.m == m.n
}

// Augment concatenates other as additional columns: [m | other].
// The result is always a rectangular matrix (RectW), even when called on a square matrix.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Augment(other RectW) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Stack(other RectW) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SubMatrixGivenRows(indices ...int) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) RowSlice(start, end int) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SubMatrixGivenColumns(indices ...int) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) ColumnSlice(start, end int) (RectW, error) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SwapColumnAssign(i, j int) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SwapColumn(i, j int) (W, error) {
	c := m.clone()
	c.SwapColumnAssign(i, j)
	return c.self, nil
}

// SwapRowAssign swaps rows i and j in place. Panics if indices are out of bounds.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SwapRowAssign(i, j int) {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SwapRow(i, j int) (W, error) {
	c := m.clone()
	c.SwapRowAssign(i, j)
	return c.self, nil
}

// Transpose returns the transpose of m.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Transpose() W {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Minor(row, col int) (W, error) {
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

// Equal reports whether m and other have the same dimensions and equal elements.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Equal(other W) bool {
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

// Bytes serialises the matrix to bytes by concatenating each element's byte representation.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Bytes() []byte {
	scalarSize := m.scalarGroup().ElementSize()
	data := make([]byte, len(m.v)*scalarSize)
	for i, element := range m.v {
		copy(data[i*scalarSize:(i+1)*scalarSize], element.Bytes())
	}
	return data
}

// HashCode returns a combined hash of all elements.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) HashCode() base.HashCode {
	acc := base.HashCode(1)
	for _, element := range m.v {
		acc = acc.Combine(element.HashCode())
	}
	return acc
}

// String returns a human-readable representation of the matrix.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) String() string {
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
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Clone() W {
	var cloned WT
	W(&cloned).init(m.m, m.n)
	copy(W(&cloned).data(), m.v)
	return W(&cloned)
}

// SetColumnAssign sets column c to the given data in place.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SetColumnAssign(c int, data []S) error {
	if c < 0 || c >= m.n {
		return ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", c, m.n)
	}
	if len(data) != m.m {
		return ErrDimension.WithMessage("column length %d does not match matrix row count %d", len(data), m.m)
	}
	for r, d := range data {
		m.v[m.idx(r, c)] = d.Clone()
	}
	return nil
}

// SetColumn returns a new matrix with column c set to data.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SetColumn(c int, data []S) (W, error) {
	out := m.clone()
	if err := out.SetColumnAssign(c, data); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set column %d", c)
	}
	return out.self, nil
}

// SetRowAssign sets row r to the given data in place.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SetRowAssign(r int, data []S) error {
	if r < 0 || r >= m.m {
		return ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", r, m.m)
	}
	if len(data) != m.n {
		return ErrDimension.WithMessage("row length %d does not match matrix column count %d", len(data), m.n)
	}
	for c, d := range data {
		m.v[m.idx(r, c)] = d.Clone()
	}
	return nil
}

// SetRow returns a new matrix with row r set to data.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SetRow(r int, data []S) (W, error) {
	out := m.clone()
	if err := out.SetRowAssign(r, data); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set row %d", r)
	}
	return out.self, nil
}

// SetAssign sets the element at (r, c) to data in place.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) SetAssign(r, c int, data S) error {
	if r < 0 || r >= m.m {
		return ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", r, m.m)
	}
	if c < 0 || c >= m.n {
		return ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", c, m.n)
	}
	m.v[m.idx(r, c)] = data.Clone()
	return nil
}

// Set returns a new matrix with an element at (r, c) set to data.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) Set(r, c int, data S) (W, error) {
	out := m.clone()
	if err := out.SetAssign(r, c, data); err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to set element at row %d, column %d", r, c)
	}
	return out.self, nil
}

// IsColumnVector returns true if this matrix has exactly one column.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsColumnVector() bool {
	return m.n == 1
}

// IsRowVector returns true if this matrix has exactly one row.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsRowVector() bool {
	return m.m == 1
}

// IsNumber reports whether this matrix is 1×1.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) IsNumber() bool {
	return m.n == 1 && m.m == 1
}

// vectorLength returns the length of a row or column vector, or -1 if the matrix is not a vector.
func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) vectorLength() int {
	if m.IsRowVector() {
		return m.n
	}
	if m.IsColumnVector() {
		return m.m
	}
	return -1
}

func (m *MatrixGroupElementTrait[S, W, WT, RectW, RectWT]) clone() MatrixGroupElementTrait[S, W, WT, RectW, RectWT] {
	clonedSelf := m.self.Clone()
	return MatrixGroupElementTrait[S, W, WT, RectW, RectWT]{
		self: clonedSelf,
		m:    m.m,
		n:    m.n,
		v:    W(clonedSelf).data(),
	}
}

// MatrixTrait extends [MatrixGroupElementTrait] with ring-specific operations
// (Add, Sub, Neg, ScalarMul, Mul, Hadamard product) for matrices over a finite ring.
// It is embedded by [Matrix] and [SquareMatrix].
type MatrixTrait[S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any, RectW matrixWrapperPtrConstraint[S, RectWT], RectWT any] struct {
	MatrixGroupElementTrait[S, W, WT, RectW, RectWT]
}

func (m *MatrixTrait[S, W, WT, RectW, RectWT]) scalarRing() algebra.FiniteRing[S] {
	return algebra.StructureMustBeAs[algebra.FiniteRing[S]](m.v[0].Structure())
}

// AddAssign adds other to m in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) AddAssign(other W) {
	m.OpAssign(other)
}

// Add returns m + other as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Add(other W) W {
	return m.Op(other)
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

// NegAssign negates m in place.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) NegAssign() {
	m.OpInvAssign()
}

// TryNeg returns -m. The error return exists for interface compatibility.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) TryNeg() (W, error) {
	return m.Neg(), nil
}

// Neg returns -m as a new matrix.
func (m *MatrixTrait[S, W, WT, RectW, RectWT]) Neg() W {
	return m.OpInv()
}

func (m *MatrixTrait[S, W, WT, RectW, RectWT]) clone() MatrixTrait[S, W, WT, RectW, RectWT] {
	clonedSelf := m.self.Clone()
	return MatrixTrait[S, W, WT, RectW, RectWT]{
		MatrixGroupElementTrait: MatrixGroupElementTrait[S, W, WT, RectW, RectWT]{
			self: clonedSelf,
			m:    m.m,
			n:    m.n,
			v:    W(clonedSelf).data(),
		},
	}
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
