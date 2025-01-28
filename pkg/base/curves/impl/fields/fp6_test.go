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
	_ fields.CubicFieldExtensionArith[*testFp2] = testFp6Params{}
)

type testFp6Params struct{}

func (testFp6Params) RootOfUnity(out *testFp2) {
	out.U0.SetZero()
	out.U1.SetUint64(655417564)
}

func (testFp6Params) ProgenitorExponent() []uint8 {
	x, _ := new(big.Int).SetString("0x28afb3d797425f9c374bd75b15988f8b75c22233bdc7", 0)
	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	return xBytes
}

func (t testFp6Params) E() uint64 {
	return testutils.TestFpE + 1
}

func (testFp6Params) MulByCubicNonResidue(out, in *testFp2) {
	// u + 4
	var residue, result testFp2
	residue.U0.SetUint64(4)
	residue.U1.SetUint64(1)
	result.Mul(in, &residue)

	out.Set(&result)
}

// Fp2 = Fp[u]/(u^2 + 7)
// Fp6 = Fp2[v]/(v^3 - (u + 4))
type testFp6 = fields.CubicFieldExtensionImpl[*testFp2, testFp6Params, testFp2]

//go:embed vectors/fp6.add.gen.json
var fp6AddVectors string

//go:embed vectors/fp6.sub.gen.json
var fp6SubVectors string

//go:embed vectors/fp6.neg.gen.json
var fp6NegVectors string

//go:embed vectors/fp6.mul.gen.json
var fp6MulVectors string

//go:embed vectors/fp6.div.gen.json
var fp6DivVectors string

//go:embed vectors/fp6.inv.gen.json
var fp6InvVectors string

//go:embed vectors/fp6.sqrt.gen.json
var fp6SqrtVectors string

//go:embed vectors/fp6.square.gen.json
var fp6SquareVectors string

func Test_Fp6Add(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6AddVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp6).Add)
	}
}

func Test_Fp6Sub(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6SubVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp6).Sub)
	}
}

func Test_Fp6Neg(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6NegVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp6).Neg)
	}
}

func Test_Fp6Mul(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectors[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6MulVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOp(t, &vector.A.V, &vector.B.V, &vector.C.V, (*testFp6).Mul)
	}
}

func Test_Fp6Div(t *testing.T) {
	t.Parallel()

	var vectors testutils.BinaryOpVectorsWithOk[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6DivVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestBinaryOpWithOk(t, &vector.A.V, &vector.B.V, &vector.C.V, vector.Ok, (*testFp6).Div)
	}
}

func Test_Fp6Inv(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6InvVectors), &vectors)
	require.NoError(t, err)

	for i, vector := range vectors.Vectors {
		println(i)
		testutils.TestUnaryOpWithOk(t, &vector.A.V, &vector.C.V, vector.Ok, (*testFp6).Inv)
	}
}

func Test_Fp6Square(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectors[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6SquareVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		testutils.TestUnaryOp(t, &vector.A.V, &vector.C.V, (*testFp6).Square)
	}
}

func Test_Fp6Sqrt(t *testing.T) {
	t.Parallel()

	var vectors testutils.UnaryOpVectorsWithOk[*testFp6, testFp6]
	err := json.Unmarshal([]byte(fp6SqrtVectors), &vectors)
	require.NoError(t, err)

	for _, vector := range vectors.Vectors {
		var actualC testFp6
		actualOk := actualC.Sqrt(&vector.A.V)
		require.Equal(t, vector.Ok, actualOk)

		if vector.Ok != 0 {
			var actualCNeg testFp6
			actualCNeg.Neg(&actualC)
			okP := actualC.Equals(&vector.C.V)
			okN := actualCNeg.Equals(&vector.C.V)
			require.Equal(t, vector.Ok, okP|okN)
		}
	}
}
