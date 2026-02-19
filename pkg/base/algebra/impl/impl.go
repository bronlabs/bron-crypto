package impl

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type monoidElementLowLevel[E any] interface {
	Set(v E)
	ct.ConditionallySelectable[E]
	ct.Equatable[E]
	Add(lhs, rhs E)
	Double(E)

	SetBytes([]byte) (ok ct.Bool)
	Bytes() []byte
	SetZero()
	IsZero() ct.Bool
	IsNonZero() ct.Bool
}

type MonoidElementLowLevel[E monoidElementLowLevel[E]] monoidElementLowLevel[E]

type MonoidElementPtrLowLevel[E MonoidElementLowLevel[E], T any] interface {
	*T
	MonoidElementLowLevel[E]
}

// *** Group.

type groupElementLowLevel[E any] interface {
	monoidElementLowLevel[E]
	Sub(lhs, rhs E)
	Neg(E)
}

type GroupElementLowLevel[E groupElementLowLevel[E]] groupElementLowLevel[E]

type GroupElementPtrLowLevel[E GroupElementLowLevel[E], T any] interface {
	*T
	GroupElementLowLevel[E]
}

type finiteGroupElementLowLevel[E any] interface {
	groupElementLowLevel[E]
	SetRandom(prng io.Reader) (ok ct.Bool)
}

type FiniteGroupElementLowLevel[E finiteGroupElementLowLevel[E]] finiteGroupElementLowLevel[E]

type FiniteGroupElementPtrLowLevel[E FiniteGroupElementLowLevel[E], T any] interface {
	*T
	FiniteGroupElementLowLevel[E]
}

// *** Ring.

type ringElementLowLevel[E any] interface {
	groupElementLowLevel[E]
	SetOne()
	IsOne() ct.Bool
	Mul(lhs, rhs E)
	Square(E)
	Inv(E) (ok ct.Bool)
	Div(lhs, rhs E) (ok ct.Bool)
	Sqrt(E) (ok ct.Bool)
}

type RingElementLowLevel[E ringElementLowLevel[E]] ringElementLowLevel[E]

type RingElementPtrLowLevel[E RingElementLowLevel[E], T any] interface {
	*T
	RingElementLowLevel[E]
}

// *** Finite Field.

type finiteFieldElementLowLevel[E any] interface {
	ringElementLowLevel[E]
	finiteGroupElementLowLevel[E]
	SetUniformBytes(componentsData ...[]byte) (ok ct.Bool)
	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteFieldElementLowLevel[E finiteFieldElementLowLevel[E]] finiteFieldElementLowLevel[E]

type FiniteFieldElementPtrLowLevel[E FiniteFieldElementLowLevel[E], T any] interface {
	*T
	FiniteFieldElementLowLevel[E]
}

// *** Prime field.

type primeFieldElementLowLevel[E any] interface {
	finiteFieldElementLowLevel[E]
	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok ct.Bool)
	SetBytesWide(data []byte) (ok ct.Bool)
	Limbs() []uint64
}

type PrimeFieldElementLowLevel[E primeFieldElementLowLevel[E]] primeFieldElementLowLevel[E]

type PrimeFieldElementPtrLowLevel[E PrimeFieldElementLowLevel[E], T any] interface {
	*T
	PrimeFieldElementLowLevel[E]
}

// *** Matrix.

type matrixLowLevel[M, Ei, S any] interface {
	finiteGroupElementLowLevel[M]
	Dimensions() (rows, cols int)
	IsSquare() ct.Bool
	IsDiagonal() ct.Bool

	// Assigning output
	Minor(out, in M, row, col int) (ok ct.Bool)
	Get(out *Ei, row, col int) (ok ct.Bool)
	GetRow(out *[]Ei, row int) (ok ct.Bool)
	GetColumn(out *[]Ei, col int) (ok ct.Bool)

	// Mutating receiver
	Transpose(in M)
	SwapRow(i, j int) (ok ct.Bool)
	SwapColumn(i, j int) (ok ct.Bool)
	RowAdd(row1, row2 int, scalar S) (ok ct.Bool)
	ColumnAdd(col1, col2 int, scalar S) (ok ct.Bool)
	RowMul(row int, scalar S) (ok ct.Bool)
	ColumnMul(col int, scalar S) (ok ct.Bool)

	KroneckerProduct(a, b M) (ok ct.Bool)
	HadamardProduct(a, b M) (ok ct.Bool)

	ScalarProduct(S, M) (ok ct.Bool)

	ConcatRows(a, b M)
	ConcatColumns(a, b M)
	SetElement(row, col int, value Ei) (ok ct.Bool)
	SetRow(row int, values *[]Ei) (ok ct.Bool)
	SetRowZero(row int) (ok ct.Bool)
	SetColumn(col int, values *[]Ei) (ok ct.Bool)
	SetColumnZero(col int) (ok ct.Bool)
}

type MatrixLowLevel[M matrixLowLevel[M, Ei, S], Ei groupElementLowLevel[Ei], S ringElementLowLevel[S]] interface {
	matrixLowLevel[M, Ei, S]
	Mul(a, b M) (ok ct.Bool)
	Inv(M) (ok ct.Bool)
}

type MatrixLowLevelPtr[M MatrixLowLevel[M, Ei, S], Ei groupElementLowLevel[Ei], S ringElementLowLevel[S], T any] interface {
	*T
	MatrixLowLevel[M, Ei, S]
}

type squareMatrixLowLevel[M, Ei, S any] interface {
	matrixLowLevel[M, Ei, S]
	ringElementLowLevel[M]
	Trace(out *Ei) (ok ct.Bool)
	Determinant(out *Ei) (ok ct.Bool)
}

type SquareMatrixLowLevel[M squareMatrixLowLevel[M, Ei, S], Ei groupElementLowLevel[Ei], S ringElementLowLevel[S]] interface {
	squareMatrixLowLevel[M, Ei, S]
}

type SquareMatrixLowLevelPtr[M SquareMatrixLowLevel[M, Ei, S], Ei groupElementLowLevel[Ei], S ringElementLowLevel[S], T any] interface {
	*T
	SquareMatrixLowLevel[M, Ei, S]
}
