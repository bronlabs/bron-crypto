package testutils

import (
	"testing"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/fields"
	"github.com/stretchr/testify/require"
)

type BinaryOpVectors[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	Vectors []BinaryOpVector[FP, F] `json:"vectors"`
}

type BinaryOpVector[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	A FiniteFieldJson[FP, F] `json:"a"`
	B FiniteFieldJson[FP, F] `json:"b"`
	C FiniteFieldJson[FP, F] `json:"c"`
}

type BinaryOpVectorsWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	Vectors []BinaryOpVectorWithOk[FP, F] `json:"vectors"`
}

type BinaryOpVectorWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	A  FiniteFieldJson[FP, F] `json:"a"`
	B  FiniteFieldJson[FP, F] `json:"b"`
	C  FiniteFieldJson[FP, F] `json:"c"`
	Ok uint64                 `json:"ok"`
}

type UnaryOpVectors[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	Vectors []UnaryOpVector[FP, F] `json:"vectors"`
}

type UnaryOpVector[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	A FiniteFieldJson[FP, F] `json:"a"`
	C FiniteFieldJson[FP, F] `json:"c"`
}

type UnaryOpVectorsWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	Vectors []UnaryOpVectorWithOk[FP, F] `json:"vectors"`
}

type UnaryOpVectorWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any] struct {
	A  FiniteFieldJson[FP, F] `json:"a"`
	C  FiniteFieldJson[FP, F] `json:"c"`
	Ok uint64                 `json:"ok"`
}

func TestUnaryOp[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any](tb testing.TB, a, c *F, op func(c, a *F)) {
	var actualC F
	op(&actualC, a)
	require.True(tb, FP(&actualC).Equals(c) == 1)
}

func TestUnaryOpWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any](tb testing.TB, a, c *F, ok uint64, op func(c, a *F) uint64) {
	var actualC F
	actualOk := op(&actualC, a)
	require.True(tb, FP(&actualC).Equals(c) == 1)
	require.True(tb, actualOk == ok)
}

func TestBinaryOp[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any](tb testing.TB, a, b, c *F, op func(c, a, b *F)) {
	var actualC F
	op(&actualC, a, b)
	require.True(tb, FP(&actualC).Equals(c) == 1)
}

func TestBinaryOpWithOk[FP fields.FiniteFieldElementPtrConstraint[FP, F], F any](tb testing.TB, a, b, c *F, ok uint64, op func(c, a, b *F) uint64) {
	var actualC F
	actualOk := op(&actualC, a, b)
	require.True(tb, FP(&actualC).Equals(c) == 1)
	require.True(tb, actualOk == ok)
}
