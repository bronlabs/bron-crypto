package fields_test

import (
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields/testutils"

	_ "embed"
)

var (
	_ fields.CubicFieldExtensionArith[*testutils.TestFp] = testFp3Params{}
)

type testFp3Params struct{}

func (testFp3Params) RootOfUnity(out *testutils.TestFp) {
	out.SetUint64(199245557)
}

func (testFp3Params) ProgenitorExponent() []uint8 {
	e, _ := new(big.Int).SetString("0x120a96a0e0364d812075bf", 0)
	eBytes := e.Bytes()
	slices.Reverse(eBytes)
	return eBytes
}

func (t testFp3Params) E() uint64 {
	return testutils.TestFpE
}

func (testFp3Params) MulByCubicNonResidue(out, in *testutils.TestFp) {
	var residue, result testutils.TestFp
	residue.SetUint64(5)
	result.Mul(in, &residue)

	out.Set(&result)
}

// Fp2 = Fp[u]/(u^3 - 5)
type testFp3 = fields.CubicFieldExtensionImpl[*testutils.TestFp, testFp3Params, testutils.TestFp]

//go:embed vectors/fp3.add.gen.json
var fp3AddVectors string

//go:embed vectors/fp3.sub.gen.json
var fp3SubVectors string

//go:embed vectors/fp3.neg.gen.json
var fp3NegVectors string

//go:embed vectors/fp3.mul.gen.json
var fp3MulVectors string

//go:embed vectors/fp3.div.gen.json
var fp3DivVectors string

//go:embed vectors/fp3.inv.gen.json
var fp3InvVectors string

//go:embed vectors/fp3.square.gen.json
var fp3SquareVectors string

//go:embed vectors/fp3.sqrt.gen.json
var fp3SqrtVectors string

func Test_Fp3Add(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3AddVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp3).Add)
	}
}

func Test_Fp3Sub(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3SubVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp3).Sub)
	}
}

func Test_Fp3Neg(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3NegVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp3).Neg)
	}
}

func Test_Fp3Mul(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3MulVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp3).Mul)
	}
}

func Test_Fp3Div(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectorsWithOk[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3DivVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOpWithOk(t, &vector.A.V, &vector.B.V, &vector.C.V, vector.Ok, (*testFp3).Div)
	}
}

func Test_Fp3Inv(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3InvVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOpWithOk(t, &vector.A.V, &vector.C.V, vector.Ok, (*testFp3).Inv)
	}
}

func Test_Fp3Square(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3SquareVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp3).Square)
	}
}

func Test_Fp3Sqrt(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp3, testFp3]
	err := json.Unmarshal([]byte(fp3SqrtVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		var actualC testFp3
		actualOk := actualC.Sqrt(&vector.A.V)
		require.Equal(t, vector.Ok, actualOk)

		if vector.Ok != 0 {
			var actualCNeg testFp3
			actualCNeg.Neg(&actualC)
			okP := actualC.Equals(&vector.C.V)
			okN := actualCNeg.Equals(&vector.C.V)
			require.Equal(t, vector.Ok, okP|okN)
		}
	}
}
