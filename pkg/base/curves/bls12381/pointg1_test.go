package bls12381_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	itu "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
)

const dir = "./vectors"

type testCase struct {
	message string
	x       string
	y       string
}

type pointG1 struct {
	Input struct {
		Point itu.HexBytes `json:"pubkey"`
	} `json:"input"`
	Output bool `json:"output"`
}

func Test_HashToPointBLS12381G1(t *testing.T) {
	t.Parallel()

	curve := bls12381.NewG1()
	curve.SetCustomHasher("QUUX-V01-CS02-with-")

	// https://datatracker.ietf.org/doc/html/rfc9380#appendix-J
	tests := []testCase{
		{
			message: "",
			x:       "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
			y:       "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
		},
		{
			message: "abc",
			x:       "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
			y:       "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
		},
		{
			message: "abcdef0123456789",
			x:       "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
			y:       "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
		},
		{
			message: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			x:       "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
			y:       "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
		},
		{
			message: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			x:       "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
			y:       "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
		},
	}

	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			ex, err := new(saferith.Nat).SetHex(strings.ToUpper(theTest.x))
			require.NoError(t, err)
			ey, err := new(saferith.Nat).SetHex(strings.ToUpper(theTest.y))
			require.NoError(t, err)
			expected, err := curve.Point().Set(ex, ey)
			require.NoError(t, err)
			p, err := curve.Point().Hash([]byte(theTest.message))
			require.NoError(t, err)
			require.NoError(t, err)
			require.True(t, p.Equal(expected))
		})
	}
}

func testDeserializationG1(t *testing.T, vector *pointG1) {
	t.Helper()

	x, err := bls12381.NewG1().Point().FromAffineCompressed(vector.Input.Point)
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
func TestDeserializationTestVectorsG1(t *testing.T) {
	t.Parallel()
	signDir := filepath.Join(dir, "deserialization_G1")

	files, err := os.ReadDir(signDir)
	require.NoError(t, err)

	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(signDir, file.Name()))
		require.NoError(t, err)

		var vector *pointG1
		json.Unmarshal(content, &vector)

		require.NotNil(t, vector)
		require.NotNil(t, vector.Input)

		t.Run(file.Name(), func(t *testing.T) {
			t.Parallel()
			testDeserializationG1(t, vector)
		})
	}
}
