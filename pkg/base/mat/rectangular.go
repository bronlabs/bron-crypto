package mat

import (
	"fmt"
	"slices"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/errs-go/errs"
)

func NewMatrixModule[S algebra.RingElement[S]](rows, cols uint, ring algebra.Ring[S]) (*MatrixModule[S], error) {
	if rows == 0 || cols == 0 {
		return nil, ErrFailed.WithMessage("matrix dimensions must be positive: got %dx%d", rows, cols)
	}
	if ring == nil {
		return nil, ErrFailed.WithMessage("ring cannot be nil")
	}
	return &MatrixModule[S]{
		rows: int(rows),
		cols: int(cols),
		ring: ring,
	}, nil
}

type MatrixModule[S algebra.RingElement[S]] struct {
	rows, cols int
	ring       algebra.Ring[S]
}

func (mm *MatrixModule[S]) New(rows [][]S) (*Matrix[S], error) {
	if len(rows) == 0 || len(rows[0]) == 0 {
		return nil, ErrFailed.WithMessage("matrix dimensions must be positive: got %dx%d", len(rows), len(rows[0]))
	}
	matrix := &Matrix[S]{
		rows: len(rows),
		cols: len(rows[0]),
		data: make([]S, len(rows)*len(rows[0])),
	}
	for i := range rows {
		if len(rows[i]) != matrix.cols {
			return nil, ErrFailed.WithMessage("all rows must have the same number of columns: row 0 has %d columns but row %d has %d columns", matrix.cols, i, len(rows[i]))
		}
		copy(matrix.data[i*matrix.cols:(i+1)*matrix.cols], rows[i])
	}
	return matrix, nil
}

func (mm *MatrixModule[S]) Name() string {
	return fmt.Sprintf("M_%dx%d(%s)", mm.rows, mm.cols, mm.ring.Name())
}

func (mm *MatrixModule[S]) Dimensions() (m, n int) {
	return mm.rows, mm.cols
}

func (mm *MatrixModule[S]) Order() algebra.Cardinal {
	return cardinal.New(uint64(mm.rows) * uint64(mm.cols)).Mul(mm.ring.Order())
}

func (mm *MatrixModule[S]) IsSquare() bool {
	return mm.rows == mm.cols
}

func (mm *MatrixModule[S]) ElementSize() int {
	return mm.rows * mm.cols * mm.ring.ElementSize()
}

func (mm *MatrixModule[S]) FromBytes(data []byte) (*Matrix[S], error) {
	expectedSize := mm.ElementSize()
	if len(data) != expectedSize {
		return nil, ErrFailed.WithMessage("invalid data length: expected %d bytes, got %d", expectedSize, len(data))
	}
	matrix := &Matrix[S]{
		rows: mm.rows,
		cols: mm.cols,
		data: make([]S, mm.rows*mm.cols),
	}
	elementSize := mm.ring.ElementSize()
	for i := range mm.rows * mm.cols {
		start := i * elementSize
		end := start + elementSize
		elementData := data[start:end]
		element, err := mm.ring.FromBytes(elementData)
		if err != nil {
			return nil, ErrFailed.WithMessage("failed to parse element at index %d: %v", i, err)
		}
		matrix.data[i] = element
	}
	return matrix, nil
}

func (mm *MatrixModule[S]) OpIdentity() *Matrix[S] {
	matrix := &Matrix[S]{
		rows: mm.rows,
		cols: mm.cols,
		data: make([]S, mm.rows*mm.cols),
	}
	for i := range matrix.data {
		matrix.data[i] = mm.ring.OpIdentity()
	}
	return matrix
}

func (mm *MatrixModule[S]) Zero() *Matrix[S] {
	return mm.OpIdentity()
}

func (mm *MatrixModule[S]) ScalarStructure() algebra.Structure[S] {
	return mm.ring
}

type Matrix[S algebra.RingElement[S]] struct {
	rows, cols int
	data       []S
}

func (m *Matrix[S]) module() *MatrixModule[S] {
	return &MatrixModule[S]{
		rows: m.rows,
		cols: m.cols,
		ring: m.data[0].Structure().(algebra.Ring[S]),
	}
}

func (m *Matrix[S]) Structure() algebra.Structure[*Matrix[S]] {
	return m.module()
}

func (m *Matrix[S]) Dimensions() (rows, cols int) {
	return m.rows, m.cols
}

func (m *Matrix[S]) Get(row, col int) (S, error) {
	if row < 0 || row >= m.rows || col < 0 || col >= m.cols {
		return *new(S), ErrOutOfBounds
	}
	return m.data[row*m.cols+col], nil
}

func (m *Matrix[S]) GetRowMut(row int) ([]S, error) {
	if row < 0 || row >= m.rows {
		return nil, ErrOutOfBounds
	}
	start := row * m.cols
	end := start + m.cols
	return m.data[start:end], nil
}

func (m *Matrix[S]) GetRow(i int) ([]S, error) {
	rowi, err := m.GetRowMut(i)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to get row %d", i)
	}
	rowValues := make([]S, m.cols)
	copy(rowValues, rowi)
	return rowValues, nil
}

func (m *Matrix[S]) GetColumn(j int) ([]S, error) {
	if j < 0 || j >= m.cols {
		return nil, ErrOutOfBounds
	}
	colValues := make([]S, m.rows)
	for i := 0; i < m.rows; i++ {
		colValues[i] = m.data[i*m.cols+j]
	}
	return colValues, nil
}

func (m *Matrix[S]) OpMut(other *Matrix[S]) *Matrix[S] {
	return m.AddMut(other)
}

func (m *Matrix[S]) Op(other *Matrix[S]) *Matrix[S] {
	return m.Add(other)
}

func (m *Matrix[S]) AddMut(other *Matrix[S]) *Matrix[S] {
	if m.rows != other.rows || m.cols != other.cols {
		panic(ErrDimensionMismatch)
	}
	for i := range m.data {
		m.data[i] = m.data[i].Add(other.data[i])
	}
	return m
}

func (m *Matrix[S]) Add(other *Matrix[S]) *Matrix[S] {
	return m.Clone().AddMut(other)
}

func (m *Matrix[S]) SubMut(other *Matrix[S]) *Matrix[S] {
	if m.rows != other.rows || m.cols != other.cols {
		panic(ErrDimensionMismatch)
	}
	for i := range m.data {
		m.data[i] = m.data[i].Sub(other.data[i])
	}
	return m
}

func (m *Matrix[S]) TrySub(other *Matrix[S]) (*Matrix[S], error) {
	return m.Sub(other), nil
}

func (m *Matrix[S]) Sub(other *Matrix[S]) *Matrix[S] {
	return m.Clone().SubMut(other)
}

func (m *Matrix[S]) Double() *Matrix[S] {
	return m.Add(m)
}

func (m *Matrix[S]) OpInvMut() *Matrix[S] {
	return m.NegMut()
}

func (m *Matrix[S]) OpInv() *Matrix[S] {
	return m.Neg()
}

func (m *Matrix[S]) NegMut() *Matrix[S] {
	for i := range m.data {
		m.data[i] = m.data[i].Neg()
	}
	return m
}

func (m *Matrix[S]) TryNeg() (*Matrix[S], error) {
	return m.Neg(), nil
}

func (m *Matrix[S]) Neg() *Matrix[S] {
	return m.Clone().NegMut()
}

func (m *Matrix[S]) IsOpIdentity() bool {
	for _, v := range m.data {
		if !v.IsOpIdentity() {
			return false
		}
	}
	return true
}

func (m *Matrix[S]) IsZero() bool {
	return m.IsOpIdentity()
}

func (m *Matrix[S]) IsDiagonal() bool {
	for i := range m.rows {
		for j := range m.cols {
			if i != j && !m.data[i*m.cols+j].IsOpIdentity() {
				return false
			}
		}
	}
	return true
}

func (m *Matrix[S]) IsSquare() bool {
	return m.rows == m.cols
}

func (m *Matrix[S]) Transpose() *Matrix[S] {
	transposed := &Matrix[S]{
		rows: m.cols,
		cols: m.rows,
		data: make([]S, len(m.data)),
	}
	for i := range m.rows {
		for j := range m.cols {
			transposed.data[j*m.rows+i] = m.data[i*m.cols+j]
		}
	}
	return transposed
}

func (m *Matrix[S]) ColumnAddMut(i, j int, scalar S) (*Matrix[S], error) {
	if i < 0 || i >= m.cols || j < 0 || j >= m.cols {
		return nil, ErrOutOfBounds
	}
	for row := range m.rows {
		m.data[row*m.cols+i] = m.data[row*m.cols+i].Op(m.data[row*m.cols+j].Mul(scalar))
	}
	return m, nil
}

func (m *Matrix[S]) ColumnAdd(i, j int, scalar S) (*Matrix[S], error) {
	return m.Clone().ColumnAddMut(i, j, scalar)
}

func (m *Matrix[S]) RowAddMut(i, j int, scalar S) (*Matrix[S], error) {
	if i < 0 || i >= m.rows || j < 0 || j >= m.rows {
		return nil, ErrOutOfBounds
	}
	for col := range m.cols {
		m.data[i*m.cols+col] = m.data[i*m.cols+col].Op(m.data[j*m.cols+col].Mul(scalar))
	}
	return m, nil
}

func (m *Matrix[S]) RowAdd(i, j int, scalar S) (*Matrix[S], error) {
	return m.Clone().RowAddMut(i, j, scalar)
}

func (m *Matrix[S]) ColumnScalarMulMut(i int, scalar S) (*Matrix[S], error) {
	if i < 0 || i >= m.cols {
		return nil, ErrOutOfBounds
	}
	for row := range m.rows {
		m.data[row*m.cols+i] = m.data[row*m.cols+i].Mul(scalar)
	}
	return m, nil
}

func (m *Matrix[S]) ColumnScalarMul(i int, scalar S) (*Matrix[S], error) {
	return m.Clone().ColumnScalarMulMut(i, scalar)
}

func (m *Matrix[S]) RowScalarMulMut(i int, scalar S) (*Matrix[S], error) {
	if i < 0 || i >= m.rows {
		return nil, ErrOutOfBounds
	}
	for col := range m.cols {
		m.data[i*m.cols+col] = m.data[i*m.cols+col].Mul(scalar)
	}
	return m, nil
}

func (m *Matrix[S]) RowScalarMul(i int, scalar S) (*Matrix[S], error) {
	return m.Clone().RowScalarMulMut(i, scalar)
}

func (m *Matrix[S]) ConcatColumns(other *Matrix[S]) (*Matrix[S], error) {
	if m.rows != other.rows {
		return nil, ErrDimensionMismatch.WithMessage("cannot concatenate columns: row counts do not match")
	}
	concat := &Matrix[S]{
		rows: m.rows,
		cols: m.cols + other.cols,
		data: make([]S, (m.cols+other.cols)*m.rows),
	}
	for i := range m.rows {
		copy(concat.data[i*(m.cols+other.cols):i*(m.cols+other.cols)+m.cols], m.data[i*m.cols:(i+1)*m.cols])
		copy(concat.data[i*(m.cols+other.cols)+m.cols:(i+1)*(m.cols+other.cols)], other.data[i*other.cols:(i+1)*other.cols])
	}
	return concat, nil
}

func (m *Matrix[S]) ConcatRows(other *Matrix[S]) (*Matrix[S], error) {
	if m.cols != other.cols {
		return nil, ErrDimensionMismatch.WithMessage("cannot concatenate rows: column counts do not match")
	}
	concat := &Matrix[S]{
		rows: m.rows + other.rows,
		cols: m.cols,
		data: make([]S, (m.rows+other.rows)*m.cols),
	}
	copy(concat.data[:m.rows*m.cols], m.data)
	copy(concat.data[m.rows*m.cols:], other.data)
	return concat, nil
}

func (m *Matrix[S]) SwapColumnMut(i, j int) (*Matrix[S], error) {
	if i < 0 || i >= m.cols || j < 0 || j >= m.cols {
		return nil, ErrOutOfBounds
	}
	for row := range m.rows {
		m.data[row*m.cols+i], m.data[row*m.cols+j] = m.data[row*m.cols+j], m.data[row*m.cols+i]
	}
	return m, nil
}

func (m *Matrix[S]) SwapColumn(i, j int) (*Matrix[S], error) {
	return m.Clone().SwapColumnMut(i, j)
}

func (m *Matrix[S]) SwapRowMut(i, j int) (*Matrix[S], error) {
	if i < 0 || i >= m.rows || j < 0 || j >= m.rows {
		return nil, ErrOutOfBounds
	}
	rowSize := m.cols
	for col := range m.cols {
		m.data[i*rowSize+col], m.data[j*rowSize+col] = m.data[j*rowSize+col], m.data[i*rowSize+col]
	}
	return m, nil
}

func (m *Matrix[S]) SwapRow(i, j int) (*Matrix[S], error) {
	return m.Clone().SwapRowMut(i, j)
}

func (m *Matrix[S]) TryMul(other *Matrix[S]) (*Matrix[S], error) {
	if m.cols != other.rows {
		return nil, ErrDimensionMismatch.WithMessage("cannot multiply: column count of first matrix (%d) does not match row count of second matrix (%d)", m.cols, other.rows)
	}
	ring := m.module().ring
	product := &Matrix[S]{
		rows: m.rows,
		cols: other.cols,
		data: make([]S, m.rows*other.cols),
	}
	for i := range m.rows {
		for j := range other.cols {
			sum := ring.Zero()
			for k := range m.cols {
				sum = sum.Add(m.data[i*m.cols+k].Mul(other.data[k*other.cols+j]))
			}
			product.data[i*other.cols+j] = sum
		}
	}
	return product, nil
}

func (m *Matrix[S]) Minor(row, col int) (*Matrix[S], error) {
	if row < 0 || row >= m.rows || col < 0 || col >= m.cols {
		return nil, ErrOutOfBounds
	}
	minor := &Matrix[S]{
		rows: m.rows - 1,
		cols: m.cols - 1,
		data: make([]S, (m.rows-1)*(m.cols-1)),
	}
	for i := range minor.rows {
		for j := range minor.cols {
			srcRow := i
			if srcRow >= row {
				srcRow++
			}
			srcCol := j
			if srcCol >= col {
				srcCol++
			}
			minor.data[i*minor.cols+j] = m.data[srcRow*m.cols+srcCol]
		}
	}
	return minor, nil
}

func (m *Matrix[S]) HadamardProductMut(other *Matrix[S]) (*Matrix[S], error) {
	if m.rows != other.rows || m.cols != other.cols {
		return nil, ErrDimensionMismatch.WithMessage("cannot compute Hadamard product: dimensions do not match")
	}
	for i := range m.data {
		m.data[i] = m.data[i].OtherOp(other.data[i])
	}
	return m, nil
}

func (m *Matrix[S]) HadamardProduct(other *Matrix[S]) (*Matrix[S], error) {
	return m.Clone().HadamardProductMut(other)
}

func (m *Matrix[S]) ScalarOpMut(scalar S) *Matrix[S] {
	return m.ScalarMulMut(scalar)
}

func (m *Matrix[S]) ScalarOp(scalar S) *Matrix[S] {
	return m.ScalarMul(scalar)
}

func (m *Matrix[S]) ScalarMulMut(scalar S) *Matrix[S] {
	for i := range m.data {
		m.data[i] = m.data[i].Mul(scalar)
	}
	return m
}

func (m *Matrix[S]) ScalarMul(scalar S) *Matrix[S] {
	return m.Clone().ScalarMulMut(scalar)
}

func (m *Matrix[S]) IsTorsionFree() bool {
	return m.module().ring.IsDomain()
}

func (m *Matrix[S]) Equal(other *Matrix[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	if m.rows != other.rows || m.cols != other.cols {
		return false
	}
	for i := range m.data {
		if !m.data[i].Equal(other.data[i]) {
			return false
		}
	}
	return true
}

func (m *Matrix[S]) Bytes() []byte {
	scalarSize := m.module().ring.ElementSize()
	data := make([]byte, len(m.data)*scalarSize)
	for i, element := range m.data {
		copy(data[i*scalarSize:(i+1)*scalarSize], element.Bytes())
	}
	return data
}

func (m *Matrix[S]) Clone() *Matrix[S] {
	return &Matrix[S]{
		rows: m.rows,
		cols: m.cols,
		data: slices.Clone(m.data),
	}
}

func (m *Matrix[S]) HashCode() base.HashCode {
	acc := base.HashCode(1)
	for _, e := range m.data {
		acc = acc.Combine(e.HashCode())
	}
	return acc
}

func (m *Matrix[S]) String() string {
	var b strings.Builder
	// Rough preallocation: brackets/newlines plus per-element formatting. This is only a hint.
	b.Grow(4 + m.rows*(6+m.cols*8))

	b.WriteString("[\n")
	for i := 0; i < m.rows; i++ {
		b.WriteString("  [")
		rowOff := i * m.cols
		for j := 0; j < m.cols; j++ {
			fmt.Fprint(&b, m.data[rowOff+j])
			if j < m.cols-1 {
				b.WriteString(", ")
			}
		}
		b.WriteString("]\n")
	}
	b.WriteByte(']')
	return b.String()
}
