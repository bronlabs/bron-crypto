package testutils

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// AssertCanonicalSetBytes checks that SetBytes accepts canonical encodings and rejects values >= modulus.
func AssertCanonicalSetBytes(t *testing.T, name string, modulus []byte, set func([]byte) bool) {
	t.Helper()

	require.True(t, set(make([]byte, len(modulus))), "%s zero must be canonical", name)
	require.True(t, set(subOneLE(modulus)), "%s modulus-1 must be canonical", name)
	require.False(t, set(append([]byte(nil), modulus...)), "%s modulus must be rejected", name)
	require.False(t, set(addOneLE(modulus)), "%s modulus+1 must be rejected", name)
	require.False(t, set(bytes.Repeat([]byte{0xff}, len(modulus))), "%s all-ones must be rejected", name)
}

func subOneLE(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i := range out {
		if out[i] != 0 {
			out[i]--
			return out
		}
		out[i] = 0xff
	}
	return out
}

func addOneLE(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i := range out {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return out
}
