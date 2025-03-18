package fields_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/fields/testutils"

	_ "embed"
)

var (
	_ fields.QuadraticFieldExtensionArithmetic[*testutils.TestFp] = testFp2Params{}
)

type testFp2Params struct{}

func (testFp2Params) MulByQuadraticNonResidue(out, in *testutils.TestFp) {
	var residue, result testutils.TestFp
	residue.SetUint64(7)
	residue.Neg(&residue)
	result.Mul(in, &residue)

	out.Set(&result)
}

// Fp2 = Fp[u]/(u^2 + 7)
type testFp2 = fields.QuadraticFieldExtensionImpl[*testutils.TestFp, testFp2Params, testutils.TestFp]

//go:embed vectors/fp2.add.gen.json
var fp2AddVectors string

//go:embed vectors/fp2.sub.gen.json
var fp2SubVectors string

//go:embed vectors/fp2.neg.gen.json
var fp2NegVectors string

//go:embed vectors/fp2.mul.gen.json
var fp2MulVectors string

//go:embed vectors/fp2.div.gen.json
var fp2DivVectors string

//go:embed vectors/fp2.inv.gen.json
var fp2InvVectors string

//go:embed vectors/fp2.square.gen.json
var fp2SquareVectors string

//go:embed vectors/fp2.sqrt.gen.json
var fp2SqrtVectors string

func Test_Fp2Add(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2AddVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp2).Add)
	}
}

func Test_Fp2Sub(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2SubVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp2).Sub)
	}
}

func Test_Fp2Neg(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2NegVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp2).Neg)
	}
}

func Test_Fp2Mul(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2MulVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp2).Mul)
	}
}

func Test_Fp2Div(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectorsWithOk[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2DivVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOpWithOk(t, &vector.A.V, &vector.B.V, &vector.C.V, vector.Ok, (*testFp2).Div)
	}
}

func Test_Fp2Inv(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2InvVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOpWithOk(t, &vector.A.V, &vector.C.V, vector.Ok, (*testFp2).Inv)
	}
}

func Test_Fp2Square(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2SquareVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp2).Square)
	}
}

func Test_Fp2Sqrt(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp2, testFp2]
	err := json.Unmarshal([]byte(fp2SqrtVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		var actualC testFp2
		actualOk := actualC.Sqrt(&vector.A.V)
		require.Equal(t, vector.Ok, actualOk)

		if vector.Ok != 0 {
			var actualCNeg testFp2
			actualCNeg.Neg(&actualC)
			okP := actualC.Equals(&vector.C.V)
			okN := actualCNeg.Equals(&vector.C.V)
			require.Equal(t, vector.Ok, okP|okN)
		}
	}
}
