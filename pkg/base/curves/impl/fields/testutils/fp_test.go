package testutils_test

import (
	_ "embed"
	"encoding/json"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

//go:embed vectors/fp.add.gen.json
var fpAddVectors string

//go:embed vectors/fp.sub.gen.json
var fpSubVectors string

//go:embed vectors/fp.neg.gen.json
var fpNegVectors string

//go:embed vectors/fp.mul.gen.json
var fpMulVectors string

//go:embed vectors/fp.div.gen.json
var fpDivVectors string

//go:embed vectors/fp.inv.gen.json
var fpInvVectors string

//go:embed vectors/fp.square.gen.json
var fpSquareVectors string

//go:embed vectors/fp.sqrt.gen.json
var fpSqrtVectors string

func Test_FpAdd(t *testing.T) {
	var vectors testutils.BinaryOpVectors[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpAddVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testutils.TestFp).Add)
	}
}

func Test_FpSub(t *testing.T) {
	var vectors testutils.BinaryOpVectors[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpSubVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testutils.TestFp).Sub)
	}
}

func Test_FpNeg(t *testing.T) {
	var vectors testutils.UnaryOpVectors[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpNegVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testutils.TestFp).Neg)
	}
}

func Test_FpMul(t *testing.T) {
	var vectors testutils.BinaryOpVectors[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpMulVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testutils.TestFp).Mul)
	}
}

func Test_FpDiv(t *testing.T) {
	var vectors testutils.BinaryOpVectorsWithOk[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpDivVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOpWithOk(t, &vector.A.V, &vector.B.V, &vector.C.V, vector.Ok, (*testutils.TestFp).Div)
	}
}

func Test_FpInv(t *testing.T) {
	var vectors testutils.UnaryOpVectorsWithOk[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpInvVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOpWithOk(t, &vector.A.V, &vector.C.V, vector.Ok, (*testutils.TestFp).Inv)
	}
}

func Test_FpSquare(t *testing.T) {
	var vectors testutils.UnaryOpVectors[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpSquareVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testutils.TestFp).Square)
	}
}

func Test_FpSqrt(t *testing.T) {
	var vectors testutils.UnaryOpVectorsWithOk[*testutils.TestFp, testutils.TestFp]
	err := json.Unmarshal([]byte(fpSqrtVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		var actualC testutils.TestFp
		actualOk := actualC.Sqrt(&vector.A.V)
		require.Equal(t, vector.Ok, actualOk)

		if vector.Ok != 0 {
			var actualCNeg testutils.TestFp
			actualCNeg.Neg(&actualC)
			okP := actualC.Equals(&vector.C.V)
			okN := actualCNeg.Equals(&vector.C.V)
			require.Equal(t, vector.Ok, okP|okN)
		}
	}
}
