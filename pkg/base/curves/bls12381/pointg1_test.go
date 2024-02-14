package bls12381_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	itu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
)

const dir = "./vectors"

type pointG1 struct {
	Input struct {
		Point itu.HexBytes `json:"pubkey"`
	} `json:"input"`
	Output bool `json:"output"`
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
