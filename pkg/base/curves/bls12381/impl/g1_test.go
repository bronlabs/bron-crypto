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

type rfc9380TestVectorsG1 struct {
	Dst     string                `json:"dst"`
	Suite   string                `json:"suite"`
	Vectors []rfc9360TestVectorG1 `json:"vectors"`
}

type rfc9360TestVectorG1 struct {
	Msg string               `json:"msg"`
	P   rfc9380TestPointG1   `json:"p"`
	U   []string             `json:"u"`
	Q   []rfc9380TestPointG1 `json:"q"`
}

type rfc9380TestPointG1 struct {
	X string `json:"x"`
	Y string `json:"y"`
}

//go:embed testvectors/bls12381g1_xmd_sha256_sswu_ro.json
var roTestVectorsG1Json string

func Test_HashToCurveG1(t *testing.T) {
	t.Parallel()

	var testVectors rfc9380TestVectorsG1
	err := json.Unmarshal([]byte(roTestVectorsG1Json), &testVectors)
	require.NoError(t, err)

	for _, testVector := range testVectors.Vectors {
		t.Run(testVector.Msg, func(t *testing.T) {
			t.Parallel()

			var p bls12381Impl.G1Point
			p.Hash(testVectors.Dst, []byte(testVector.Msg))

			var px, py bls12381Impl.Fp
			p.ToAffine(&px, &py)
			pxBytes := px.Bytes()
			pyBytes := py.Bytes()

			pxExpectedBytes, err := hex.DecodeString(testVector.P.X)
			require.NoError(t, err)
			slices.Reverse(pxExpectedBytes)
			pyExpectedBytes, err := hex.DecodeString(testVector.P.Y)
			require.NoError(t, err)
			slices.Reverse(pyExpectedBytes)

			require.Equal(t, pxExpectedBytes, pxBytes)
			require.Equal(t, pyExpectedBytes, pyBytes)
		})
	}
}
