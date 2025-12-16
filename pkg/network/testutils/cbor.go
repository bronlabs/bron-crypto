package ntu

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/stretchr/testify/require"
)

// CBORRoundTrip serialises and deserialises a value, asserting round-trip fidelity.
func CBORRoundTrip[T any](tb testing.TB, v T) T {
	tb.Helper()

	data, err := serde.MarshalCBOR(v)
	require.NoError(tb, err)

	out, err := serde.UnmarshalCBOR[T](data)
	require.NoError(tb, err)
	return out
	// return v
}
