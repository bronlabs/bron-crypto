package impl_test

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"

	_ "embed"
)

//go:embed testvectors/vesta_xmd_blake2b_sswu_ro.json
var roTestVectorsVestaJson string

func Test_HashToCurveVesta(t *testing.T) {
	t.Parallel()

	var testVectors rfc9380TestVectors
	err := json.Unmarshal([]byte(roTestVectorsVestaJson), &testVectors)
	require.NoError(t, err)

	for _, testVector := range testVectors.Vectors {
		t.Run(testVector.Msg, func(t *testing.T) {
			t.Parallel()

			var p pastaImpl.VestaPoint
			p.Hash(testVectors.Dst, []byte(testVector.Msg))

			var px, py pastaImpl.Fq
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
