package impl_test

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/k256/impl"

	_ "embed"
)

type rfc9380TestVectors struct {
	Dst     string              `json:"dst"`
	Suite   string              `json:"suite"`
	Vectors []rfc9360TestVector `json:"vectors"`
}

type rfc9360TestVector struct {
	Msg string             `json:"msg"`
	P   rfc9380TestPoint   `json:"p"`
	U   []string           `json:"u"`
	Q   []rfc9380TestPoint `json:"q"`
}

type rfc9380TestPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

//go:embed testvectors/secp256k1_xmd_sha256_sswu_ro.json
var roTestVectorsJson string

func Test_HashToCurve(t *testing.T) {
	t.Parallel()

	var testVectors rfc9380TestVectors
	err := json.Unmarshal([]byte(roTestVectorsJson), &testVectors)
	require.NoError(t, err)

	for _, testVector := range testVectors.Vectors {
		t.Run(testVector.Msg, func(t *testing.T) {
			t.Parallel()

			var p impl.Point
			p.Hash(testVectors.Dst, []byte(testVector.Msg))

			var px, py impl.Fp
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
