package impl_test

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"

	_ "embed"
)

type rfc9380TestVectorsG2 struct {
	Dst     string                `json:"dst"`
	Suite   string                `json:"suite"`
	Vectors []rfc9360TestVectorG2 `json:"vectors"`
}

type rfc9360TestVectorG2 struct {
	Msg string               `json:"msg"`
	P   rfc9380TestPointG2   `json:"p"`
	U   [][2]string          `json:"u"`
	Q   []rfc9380TestPointG2 `json:"q"`
}

type rfc9380TestPointG2 struct {
	X [2]string `json:"x"`
	Y [2]string `json:"y"`
}

//go:embed testvectors/bls12381g2_xmd_sha256_sswu_ro.json
var roTestVectorsG2Json string

func Test_HashToCurveG2(t *testing.T) {
	t.Parallel()

	var testVectors rfc9380TestVectorsG2
	err := json.Unmarshal([]byte(roTestVectorsG2Json), &testVectors)
	require.NoError(t, err)

	for _, testVector := range testVectors.Vectors {
		t.Run(testVector.Msg, func(t *testing.T) {
			t.Parallel()

			var p bls12381Impl.G2Point
			p.Hash(testVectors.Dst, []byte(testVector.Msg))

			var px, py bls12381Impl.Fp2
			p.ToAffine(&px, &py)
			px0Bytes := px.U0.Bytes()
			px1Bytes := px.U1.Bytes()
			py0Bytes := py.U0.Bytes()
			py1Bytes := py.U1.Bytes()

			px0ExpectedBytes, err := hex.DecodeString(testVector.P.X[0])
			require.NoError(t, err)
			slices.Reverse(px0ExpectedBytes)
			px1ExpectedBytes, err := hex.DecodeString(testVector.P.X[1])
			require.NoError(t, err)
			slices.Reverse(px1ExpectedBytes)
			py0ExpectedBytes, err := hex.DecodeString(testVector.P.Y[0])
			require.NoError(t, err)
			slices.Reverse(py0ExpectedBytes)
			py1ExpectedBytes, err := hex.DecodeString(testVector.P.Y[1])
			require.NoError(t, err)
			slices.Reverse(py1ExpectedBytes)

			require.Equal(t, px0ExpectedBytes, px0Bytes)
			require.Equal(t, px1ExpectedBytes, px1Bytes)
			require.Equal(t, py0ExpectedBytes, py0Bytes)
			require.Equal(t, py1ExpectedBytes, py1Bytes)
		})
	}
}
