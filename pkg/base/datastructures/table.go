package datastructures

import (
	"iter"
)

// AbstractMatrix defines basic matrix operations for any matrix-like data structure.
// T is the concrete matrix type and C is the type used for dimension counts.
type AbstractMatrix[T, C any] interface {
	// Dimensions returns the number of rows (n) and columns (m) in the matrix.
	Dimensions() (n, m C)
	// Transpose returns a new matrix with rows and columns swapped.
	Transpose() T
	// SubMatrix returns a sub-matrix from row1 to row2 and col1 to col2 (exclusive).
	SubMatrix(row1, row2, col1, col2 int) T
	// IsSquare returns true if the matrix has equal rows and columns.
	IsSquare() bool
	// IsDiagonal returns true if all non-diagonal elements are zero.
	IsDiagonal() bool
}

type immutableTable[E, T any] interface {
	AbstractMatrix[T, int]

	Get(row, col int) E
	GetRow(row int) []E
	GetColumn(col int) []E

	IterRows() iter.Seq[iter.Seq[E]]
	IterRows2() iter.Seq2[int, iter.Seq[E]]
	IterColumns() iter.Seq[iter.Seq[E]]
	IterColumns2() iter.Seq2[int, iter.Seq[E]]

	Clonable[T]
}

type mutableTable[E, T any] interface {
	immutableTable[E, T]
	Set(row, col int, value E) error
	SetRow(row int, values ...E) error
	SetColumn(col int, values ...E) error

	InsertRow(row int, values ...E) error
	InsertColumn(col int, values ...E) error

	DeleteRow(row int) error
	DeleteColumn(col int) error
}

// ImmutableTable is a read-only two-dimensional table of elements.
type ImmutableTable[E any] immutableTable[E, ImmutableTable[E]]

// Table is a mutable two-dimensional table of elements supporting row and column operations.
type Table[E any] mutableTable[E, Table[E]]
