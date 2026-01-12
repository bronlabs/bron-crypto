package datastructures

import (
	"encoding/json"
	"iter"
)

type AbstractMatrix[T, C any] interface {
	Dimensions() (n, m C)
	Transpose() T
	SubMatrix(row1, row2, col1, col2 int) T
	IsSquare() bool
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
	json.Marshaler
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

type ImmutableTable[E any] immutableTable[E, ImmutableTable[E]]

type Table[E any] mutableTable[E, Table[E]]
