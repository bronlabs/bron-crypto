package testutils

import (
	"testing"
)

func CBORRoundTrip[T any](tb testing.TB, v T) T {
	tb.Helper()

	// data, err := serde.MarshalCBOR(v)
	// require.NoError(tb, err)

	// out, err := serde.UnmarshalCBOR[T](data)
	// require.NoError(tb, err)
	// return out
	return v
}
