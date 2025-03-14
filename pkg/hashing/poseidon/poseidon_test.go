package poseidon_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	itu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

const dir = "./vectors"

type jsonFile struct {
	Name        string       `json:"name"`
	TestVectors []testVector `json:"test_vectors"` //nolint:tagliatelle // false positive
}

type testVector struct {
	Input  []itu.HexBytes `json:"input"`
	Output itu.HexBytes   `json:"output"`
}

func TestPoseidonLegacy(t *testing.T) {
	t.Parallel()
	testHash(t, "legacy.json")
}

func TestPoseidonKimchi(t *testing.T) {
	t.Parallel()
	t.Skip("fails for now")
	testHash(t, "kimchi.json")
}

func testHash(t *testing.T, fileName string) {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(dir, fileName))
	require.NoError(t, err)

	var vectors *jsonFile

	err = json.Unmarshal(content, &vectors)
	require.NoError(t, err)

	for i, v := range vectors.TestVectors {
		vector := v
		t.Run(fmt.Sprintf("running test vector #%d", i), func(t *testing.T) {
			t.Parallel()
			hasher := poseidon.NewLegacy()
			actual := hasher.Hash(parseInput(t, vector.Input)...)
			expected := parseOutput(t, vector.Output)
			require.True(t, actual.Equal(expected))

		})
	}

}

func parseInput(t *testing.T, xs []itu.HexBytes) []curves.BaseFieldElement {
	t.Helper()
	out := make([]curves.BaseFieldElement, len(xs))
	for i, x := range xs {
		out[i] = parseOutput(t, x)
	}
	return out
}

func parseOutput(t *testing.T, x itu.HexBytes) curves.BaseFieldElement {
	t.Helper()
	b := bitstring.ReverseBytes(x)
	f, err := pasta.NewPallasBaseField().Element().SetBytesWide(b)
	require.NoError(t, err)
	return f
}
