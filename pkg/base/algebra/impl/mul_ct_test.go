package impl_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScalarMulLowLevelHasNoSecretIndexedTableLookup(t *testing.T) {
	t.Parallel()

	source := readMulSource(t)
	require.NotContains(t, source, "precomputed[w]")
}

func TestMultiScalarMulLowLevelHasNoSecretWindowBuckets(t *testing.T) {
	t.Parallel()

	source := readMulSource(t)
	secretBody := between(t, source, "func MultiScalarMulLowLevel[", "func MultiScalarMulLowLevelVartimePublic[")
	require.NotContains(t, secretBody, "buckets[win]")
	require.NotContains(t, secretBody, "if win == 0")
	require.NotContains(t, secretBody, ".IsZero()")
}

func TestVariableTimeMSMIsPublicInputOnly(t *testing.T) {
	t.Parallel()

	source := readMulSource(t)
	require.Contains(t, source, "MultiScalarMulLowLevelVartimePublic")
	require.Contains(t, source, "suitable only when every scalar is public")
}

func readMulSource(t *testing.T) string {
	t.Helper()

	source, err := os.ReadFile("mul.go")
	require.NoError(t, err)
	return string(source)
}

func between(t *testing.T, source, start, end string) string {
	t.Helper()

	startIndex := strings.Index(source, start)
	require.NotEqual(t, -1, startIndex)
	endIndex := strings.Index(source[startIndex:], end)
	require.NotEqual(t, -1, endIndex)
	return source[startIndex : startIndex+endIndex]
}
