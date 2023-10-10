package bls12381_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	itu "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
)

type pointG2 struct {
	Input struct {
		Point itu.HexBytes `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

type hashedPointG2 struct {
	Input struct {
		Message string `json:"msg"`
	} `json:"input"`
	Output struct {
		X itu.HexBytes `json:"x"`
		Y itu.HexBytes `json:"y"`
	} `json:"output"`
}

func Test_HashToPointBLS12381G2(t *testing.T) {
	t.Parallel()

	curve := bls12381.NewG2()

	// https://datatracker.ietf.org/doc/html/rfc9380 (Appendix J)
	tests := []testCase{
		{
			message: "",
			x:       "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
			y:       "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d60503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
		},
		{
			message: "abc",
			x:       "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
			y:       "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd161787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
		},
		{
			message: "abcdef0123456789",
			x:       "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
			y:       "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
		},
		{
			message: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			x:       "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb9119a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
			y:       "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e566214f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
		},
		{
			message: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			x:       "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d0156901a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
			y:       "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab520b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
		},
	}

	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			p := curve.Point().Hash([]byte(theTest.message))
			pBytes := p.ToAffineUncompressed()
			pBytesExpected, err := hex.DecodeString(theTest.x + theTest.y)
			require.NoError(t, err)
			require.Equal(t, pBytes, pBytesExpected)
		})
	}
}

func testHashToG2(t *testing.T, vector *hashedPointG2) {
	t.Helper()

	actual := bls12381.NewG2().Point().Hash([]byte(vector.Input.Message))
	require.EqualValues(t, actual.X().Bytes(), vector.Output.X, "X coordinate")
	require.EqualValues(t, actual.Y().Bytes(), vector.Output.Y, "Y coordinate")
}

// these test vectors are from the eth implementation
func TestHashToG2Vectors(t *testing.T) {
	t.Parallel()
	hashedDir := filepath.Join(dir, "hash_to_G2")

	files, err := os.ReadDir(hashedDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(hashedDir, file.Name()))
		require.NoError(t, err)

		var vector *hashedPointG2
		json.Unmarshal(content, &vector)

		require.NotNil(t, vector)
		require.NotNil(t, vector.Input)
		require.NotNil(t, vector.Output)

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			testHashToG2(t, vector)
		})
	}
}

func testDeserializationG2(t *testing.T, vector *pointG2) {
	t.Helper()

	x, err := bls12381.NewG2().Point().FromAffineCompressed(vector.Input.Point)
	if vector.Output {
		require.NoError(t, err)
	} else {
		if x != nil && x.IsIdentity() {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

// these test vectors are from the eth implementation
func TestDeserializationTestVectorsG2(t *testing.T) {
	t.Parallel()
	signDir := filepath.Join(dir, "deserialization_G2")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *pointG2
		json.Unmarshal(content, &vector)

		require.NotNil(t, vector)
		require.NotNil(t, vector.Input)

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			testDeserializationG2(t, vector)
		})
	}
}
