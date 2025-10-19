package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/stretchr/testify/require"
)

type BinaryOpVectors[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	Vectors []BinaryOpVector[FP, F] `json:"vectors"`
}

type BinaryOpVector[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	A FiniteFieldElementJson[FP, F] `json:"a"`
	B FiniteFieldElementJson[FP, F] `json:"b"`
	C FiniteFieldElementJson[FP, F] `json:"c"`
}

type BinaryOpVectorsWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	Vectors []BinaryOpVectorWithOk[FP, F] `json:"vectors"`
}

type BinaryOpVectorWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	A  FiniteFieldElementJson[FP, F] `json:"a"`
	B  FiniteFieldElementJson[FP, F] `json:"b"`
	C  FiniteFieldElementJson[FP, F] `json:"c"`
	Ok ct.Bool                       `json:"ok"`
}

type UnaryOpVectors[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	Vectors []UnaryOpVector[FP, F] `json:"vectors"`
}

type UnaryOpVector[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	A FiniteFieldElementJson[FP, F] `json:"a"`
	C FiniteFieldElementJson[FP, F] `json:"c"`
}

type UnaryOpVectorsWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	Vectors []UnaryOpVectorWithOk[FP, F] `json:"vectors"`
}

type UnaryOpVectorWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any] struct {
	A  FiniteFieldElementJson[FP, F] `json:"a"`
	C  FiniteFieldElementJson[FP, F] `json:"c"`
	Ok ct.Bool                       `json:"ok"`
}

func TestUnaryOp[FP impl.FiniteFieldElementPtr[FP, F], F any](tb testing.TB, a, c *F, op func(c, a *F)) {
	tb.Helper()
	var actualC F
	op(&actualC, a)
	require.True(tb, FP(&actualC).Equal(c) == 1)
}

func TestUnaryOpWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any](tb testing.TB, a, c *F, ok ct.Bool, op func(c, a *F) ct.Bool) {
	tb.Helper()
	var actualC F
	actualOk := op(&actualC, a)
	require.True(tb, FP(&actualC).Equal(c) == 1)
	require.True(tb, actualOk == ok)
}

func TestBinaryOp[FP impl.FiniteFieldElementPtr[FP, F], F any](tb testing.TB, a, b, c *F, op func(c, a, b *F)) {
	tb.Helper()
	var actualC F
	op(&actualC, a, b)
	require.True(tb, FP(&actualC).Equal(c) == 1)
}

func TestBinaryOpWithOk[FP impl.FiniteFieldElementPtr[FP, F], F any](tb testing.TB, a, b, c *F, ok ct.Bool, op func(c, a, b *F) ct.Bool) {
	tb.Helper()
	var actualC F
	actualOk := op(&actualC, a, b)
	require.True(tb, FP(&actualC).Equal(c) == 1)
	require.True(tb, actualOk == ok)
}
