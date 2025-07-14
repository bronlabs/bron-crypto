package fields_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields/testutils"

	_ "embed"
)

var (
	_ fields.QuadraticFieldExtensionArithmetic[*testFp6] = testFp12Params{}
)

type testFp12Params struct{}

func (testFp12Params) MulByQuadraticNonResidue(out, in *testFp6) {
	// v + 5 == [5, 1, 0]
	var residue, result testFp6
	residue.U0.U0.SetUint64(5)
	residue.U0.U1.SetZero()
	residue.U1.SetOne()
	residue.U2.SetZero()
	result.Mul(in, &residue)

	out.Set(&result)
}

// Fp2 = Fp[u]/(u^2 + 7)
// Fp6 = Fp2[v]/(v^3 - (u + 4))
// Fp12 = Fp6[w]/(w^2 - (v + 5))
type testFp12 = fields.QuadraticFieldExtensionImpl[*testFp6, testFp12Params, testFp6]

//go:embed vectors/fp12.add.gen.json
var fp12AddVectors string

//go:embed vectors/fp12.sub.gen.json
var fp12SubVectors string

//go:embed vectors/fp12.neg.gen.json
var fp12NegVectors string

//go:embed vectors/fp12.mul.gen.json
var fp12MulVectors string

//go:embed vectors/fp12.div.gen.json
var fp12DivVectors string

//go:embed vectors/fp12.inv.gen.json
var fp12InvVectors string

//go:embed vectors/fp12.square.gen.json
var fp12SquareVectors string

//go:embed vectors/fp12.sqrt.gen.json
var fp12SqrtVectors string

func Test_Fp12Add(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12AddVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp12).Add)
	}
}

func Test_Fp12Sub(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12SubVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp12).Sub)
	}
}

func Test_Fp12Neg(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12NegVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp12).Neg)
	}
}

func Test_Fp12Mul(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12MulVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp12).Mul)
	}
}

func Test_Fp12Div(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectorsWithOk[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12DivVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOpWithOk(t, &vector.A.V, &vector.B.V, &vector.C.V, vector.Ok, (*testFp12).Div)
	}
}

func Test_Fp12Inv(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12InvVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOpWithOk(t, &vector.A.V, &vector.C.V, vector.Ok, (*testFp12).Inv)
	}
}

func Test_Fp12Square(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12SquareVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp12).Square)
	}
}

func Test_Fp12Sqrt(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp12, testFp12]
	err := json.Unmarshal([]byte(fp12SqrtVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		var actualC testFp12
		actualOk := actualC.Sqrt(&vector.A.V)
		require.Equal(t, vector.Ok, actualOk)

		if vector.Ok != 0 {
			var actualCNeg testFp12
			actualCNeg.Neg(&actualC)
			okP := actualC.Equal(&vector.C.V)
			okN := actualCNeg.Equal(&vector.C.V)
			require.Equal(t, vector.Ok, okP|okN)
		}
	}
}
