package mat

import (
	"fmt"
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
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

type MatrixModuleTrait[S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any] struct {
	ring algebra.Ring[S]
	rows int
	cols int
}

func (mm *MatrixModuleTrait[S, W, WT]) Name() string {
	return fmt.Sprintf("M_%dx%d(%s)", mm.rows, mm.cols, mm.ring.Name())
}

func (mm *MatrixModuleTrait[S, W, WT]) Dimensions() (m, n int) {
	return mm.rows, mm.cols
}

func (mm *MatrixModuleTrait[S, W, WT]) Order() algebra.Cardinal {
	return cardinal.New(uint64(mm.rows) * uint64(mm.cols)).Mul(mm.ring.Order())
}

func (mm *MatrixModuleTrait[S, W, WT]) ElementSize() int {
	return mm.rows * mm.cols * mm.ring.ElementSize()
}

func (mm *MatrixModuleTrait[S, W, WT]) IsSquare() bool {
	return mm.rows == mm.cols
}

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

func (mm *MatrixModuleTrait[S, W, WT]) OpIdentity() W {
	var matrix WT
	W(&matrix).init(mm.rows, mm.cols)
	d := W(&matrix).data()
	for i := range d {
		d[i] = mm.ring.OpIdentity()
	}
	return W(&matrix)
}

func (mm *MatrixModuleTrait[S, W, WT]) Zero() W {
	return mm.OpIdentity()
}

func (mm *MatrixModuleTrait[S, W, WT]) ScalarStructure() algebra.Structure[S] {
	return mm.ring
}

func (mm *MatrixModuleTrait[S, W, WT]) ScalarRing() algebra.Ring[S] {
	return mm.ring
}

type MatrixTrait[S algebra.RingElement[S], W matrixWrapperPtrConstraint[S, WT], WT any] struct {
	self W
	m, n int
	v    []S
}

func (m *MatrixTrait[S, W, WT]) scalarRing() algebra.Ring[S] {
	return algebra.StructureMustBeAs[algebra.Ring[S]](m.v[0].Structure())
}

func (m *MatrixTrait[S, W, WT]) idx(row, col int) int {
	return row*m.n + col
}

func (m *MatrixTrait[S, W, WT]) Dimensions() (rows, cols int) {
	return m.m, m.n
}

func (m *MatrixTrait[S, W, WT]) Get(row, col int) (S, error) {
	if row < 0 || row >= m.m || col < 0 || col >= m.n {
		return *new(S), ErrDimension.WithMessage("index out of bounds: row %d, col %d for matrix of dimensions %dx%d", row, col, m.m, m.n)
	}
	return m.v[m.idx(row, col)], nil
}

func (m *MatrixTrait[S, W, WT]) GetRow(i int) ([]S, error) {
	if i < 0 || i >= m.m {
		return nil, ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
	}
	row := make([]S, m.n)
	copy(row, m.v[i*m.n:(i+1)*m.n])
	return row, nil
}

func (m *MatrixTrait[S, W, WT]) GetColumn(j int) ([]S, error) {
	if j < 0 || j >= m.n {
		return nil, ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", j, m.n)
	}
	column := make([]S, m.m)
	for i := range m.m {
		column[i] = m.v[m.idx(i, j)]
	}
	return column, nil
}

func (m *MatrixTrait[S, W, WT]) Op(other W) W {
	return m.Add(other)
}

func (m *MatrixTrait[S, W, WT]) AddMut(other W) W {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		panic(ErrDimension.WithMessage("cannot add: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols()))
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Add(otherData[i])
	}
	return m.self
}

func (m *MatrixTrait[S, W, WT]) Add(other W) W {
	c := m.clone()
	return c.AddMut(other)
}

func (m *MatrixTrait[S, W, WT]) SubMut(other W) W {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		panic(ErrDimension.WithMessage("cannot subtract: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols()))
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Sub(otherData[i])
	}
	return m.self
}

func (m *MatrixTrait[S, W, WT]) TrySub(other W) (W, error) {
	return m.Sub(other), nil
}

func (m *MatrixTrait[S, W, WT]) Sub(other W) W {
	c := m.clone()
	return c.SubMut(other)
}

func (m *MatrixTrait[S, W, WT]) DoubleMut() W {
	return m.AddMut(m.self)
}

func (m *MatrixTrait[S, W, WT]) Double() W {
	c := m.clone()
	return c.DoubleMut()
}

func (m *MatrixTrait[S, W, WT]) OpInv() W {
	return m.Neg()
}

func (m *MatrixTrait[S, W, WT]) NegMut() W {
	for i := range m.v {
		m.v[i] = m.v[i].Neg()
	}
	return m.self
}

func (m *MatrixTrait[S, W, WT]) TryNeg() (W, error) {
	return m.Neg(), nil
}

func (m *MatrixTrait[S, W, WT]) Neg() W {
	c := m.clone()
	return c.NegMut()
}

func (m *MatrixTrait[S, W, WT]) IsOpIdentity() bool {
	return m.IsZero()
}

func (m *MatrixTrait[S, W, WT]) IsZero() bool {
	for i := range m.v {
		if !m.v[i].IsZero() {
			return false
		}
	}
	return true
}

func (m *MatrixTrait[S, W, WT]) IsDiagonal() bool {
	for i := range m.m {
		for j := range m.n {
			if i != j && !m.v[m.idx(i, j)].IsZero() {
				return false
			}
		}
	}
	return true
}

func (m *MatrixTrait[S, W, WT]) IsSquare() bool {
	return m.m == m.n
}

func (m *MatrixTrait[S, W, WT]) ColumnAddMut(i, j int, scalar S) (W, error) {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		return nil, ErrDimension.WithMessage("column index out of bounds: i=%d, j=%d for matrix with %d columns", i, j, m.n)
	}
	for row := range m.m {
		m.v[m.idx(row, j)] = m.v[m.idx(row, j)].Add(m.v[m.idx(row, i)].Mul(scalar))
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) ColumnAdd(i, j int, scalar S) (W, error) {
	c := m.clone()
	return c.ColumnAddMut(i, j, scalar)
}

func (m *MatrixTrait[S, W, WT]) RowAddMut(i, j int, scalar S) (W, error) {
	if i < 0 || i >= m.m || j < 0 || j >= m.m {
		return nil, ErrDimension.WithMessage("row index out of bounds: i=%d, j=%d for matrix with %d rows", i, j, m.m)
	}
	for col := range m.n {
		m.v[m.idx(j, col)] = m.v[m.idx(j, col)].Add(m.v[m.idx(i, col)].Mul(scalar))
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) RowAdd(i, j int, scalar S) (W, error) {
	c := m.clone()
	return c.RowAddMut(i, j, scalar)
}

func (m *MatrixTrait[S, W, WT]) ColumnScalarMulMut(i int, scalar S) (W, error) {
	if i < 0 || i >= m.n {
		return nil, ErrDimension.WithMessage("column index out of bounds: %d for matrix with %d columns", i, m.n)
	}
	for row := range m.m {
		m.v[m.idx(row, i)] = m.v[m.idx(row, i)].Mul(scalar)
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) ColumnScalarMul(i int, scalar S) (W, error) {
	c := m.clone()
	return c.ColumnScalarMulMut(i, scalar)
}

func (m *MatrixTrait[S, W, WT]) RowScalarMulMut(i int, scalar S) (W, error) {
	if i < 0 || i >= m.m {
		return nil, ErrDimension.WithMessage("row index out of bounds: %d for matrix with %d rows", i, m.m)
	}
	for col := range m.n {
		m.v[m.idx(i, col)] = m.v[m.idx(i, col)].Mul(scalar)
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) RowScalarMul(i int, scalar S) (W, error) {
	c := m.clone()
	return c.RowScalarMulMut(i, scalar)
}

func (m *MatrixTrait[S, W, WT]) Augment(other W) (W, error) {
	if m.m != other.rows() {
		return nil, ErrDimension.WithMessage("cannot concatenate columns: number of rows in first matrix (%d) does not match number of rows in second matrix (%d)", m.m, other.rows())
	}
	var out WT
	W(&out).init(m.m, m.n+other.cols())
	d := W(&out).data()
	otherData := other.data()
	for i := range m.m {
		copy(d[i*(m.n+other.cols()):i*(m.n+other.cols())+m.n], m.v[i*m.n:(i+1)*m.n])
		copy(d[i*(m.n+other.cols())+m.n:(i+1)*(m.n+other.cols())], otherData[i*other.cols():(i+1)*other.cols()])
	}
	return W(&out), nil
}

func (m *MatrixTrait[S, W, WT]) Stack(other W) (W, error) {
	if m.n != other.cols() {
		return nil, ErrDimension.WithMessage("cannot concatenate rows: number of columns in first matrix (%d) does not match number of columns in second matrix (%d)", m.n, other.cols())
	}
	var out WT
	W(&out).init(m.m+other.rows(), m.n)
	d := W(&out).data()
	otherData := other.data()
	copy(d[:m.m*m.n], m.v)
	copy(d[m.m*m.n:], otherData)
	return W(&out), nil
}

func (m *MatrixTrait[S, W, WT]) SwapColumnMut(i, j int) (W, error) {
	if i < 0 || i >= m.n || j < 0 || j >= m.n {
		panic(ErrDimension.WithMessage("column index out of bounds: i=%d, j=%d for matrix with %d columns", i, j, m.n))
	}
	for row := range m.m {
		idx1 := m.idx(row, i)
		idx2 := m.idx(row, j)
		m.v[idx1], m.v[idx2] = m.v[idx2], m.v[idx1]
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) SwapColumn(i, j int) (W, error) {
	c := m.clone()
	return c.SwapColumnMut(i, j)
}

func (m *MatrixTrait[S, W, WT]) SwapRowMut(i, j int) (W, error) {
	if i < 0 || i >= m.m || j < 0 || j >= m.m {
		panic(ErrDimension.WithMessage("row index out of bounds: i=%d, j=%d for matrix with %d rows", i, j, m.m))
	}
	for col := range m.n {
		idx1 := m.idx(i, col)
		idx2 := m.idx(j, col)
		m.v[idx1], m.v[idx2] = m.v[idx2], m.v[idx1]
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) SwapRow(i, j int) (W, error) {
	c := m.clone()
	return c.SwapRowMut(i, j)
}

func (m *MatrixTrait[S, W, WT]) TryMul(other W) (W, error) {
	if m.n != other.rows() {
		return nil, ErrDimension.WithMessage("cannot multiply: number of columns in first matrix (%d) does not match number of rows in second matrix (%d)", m.n, other.rows())
	}
	var out WT
	W(&out).init(m.m, other.cols())
	outData := W(&out).data()
	otherData := other.data()
	for i := range m.m {
		for j := range other.cols() {
			var sum S
			for k := range m.n {
				sum = sum.Add(m.v[m.idx(i, k)].Mul(otherData[other.idx(k, j)]))
			}
			outData[W(&out).idx(i, j)] = sum
		}
	}
	return W(&out), nil
}

func (m *MatrixTrait[S, W, WT]) Transpose() W {
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

func (m *MatrixTrait[S, W, WT]) Minor(row, col int) (W, error) {
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

func (m *MatrixTrait[S, W, WT]) HadamardProductMut(other W) (W, error) {
	if m.self.rows() != other.rows() || m.self.cols() != other.cols() {
		return nil, ErrDimension.WithMessage("cannot compute Hadamard product: dimensions of first matrix (%dx%d) do not match dimensions of second matrix (%dx%d)", m.m, m.n, other.rows(), other.cols())
	}
	otherData := other.data()
	for i := range m.v {
		m.v[i] = m.v[i].Mul(otherData[i])
	}
	return m.self, nil
}

func (m *MatrixTrait[S, W, WT]) HadamardProduct(other W) (W, error) {
	c := m.clone()
	return c.HadamardProductMut(other)
}

func (m *MatrixTrait[S, W, WT]) ScalarOp(scalar S) W {
	return m.ScalarMul(scalar)
}

func (m *MatrixTrait[S, W, WT]) ScalarMulMut(scalar S) W {
	for i := range m.v {
		m.v[i] = m.v[i].Mul(scalar)
	}
	return m.self
}

func (m *MatrixTrait[S, W, WT]) ScalarMul(scalar S) W {
	c := m.clone()
	return c.ScalarMulMut(scalar)
}

func (m *MatrixTrait[S, W, WT]) IsTorsionFree() bool {
	return m.m == 1 && m.n == 1 && m.scalarRing().IsDomain()
}

func (m *MatrixTrait[S, W, WT]) Equal(other W) bool {
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

func (m *MatrixTrait[S, W, WT]) Bytes() []byte {
	scalarSize := m.scalarRing().ElementSize()
	data := make([]byte, len(m.v)*scalarSize)
	for i, element := range m.v {
		copy(data[i*scalarSize:(i+1)*scalarSize], element.Bytes())
	}
	return data
}

func (m *MatrixTrait[S, W, WT]) HashCode() base.HashCode {
	acc := base.HashCode(1)
	for _, element := range m.v {
		acc = acc.Combine(element.HashCode())
	}
	return acc
}

func (m *MatrixTrait[S, W, WT]) String() string {
	var b strings.Builder
	// Rough preallocation: brackets/newlines plus per-element formatting. This is only a hint.
	b.Grow(4 + m.m*(6+m.n*8))

	b.WriteString("[\n")
	for i := 0; i < m.m; i++ {
		b.WriteString("  [")
		rowOff := i * m.n
		for j := 0; j < m.n; j++ {
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

func (m *MatrixTrait[S, W, WT]) clone() MatrixTrait[S, W, WT] {
	clonedSelf := m.self.Clone()
	return MatrixTrait[S, W, WT]{
		self: clonedSelf,
		m:    m.m,
		n:    m.n,
		v:    W(clonedSelf).data(),
	}
}

func (m *MatrixTrait[S, W, WT]) Clone() W {
	var cloned WT
	W(&cloned).init(m.m, m.n)
	copy(W(&cloned).data(), m.v)
	return W(&cloned)

}
