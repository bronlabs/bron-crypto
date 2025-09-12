package testutils

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func CBORRoundTrip[T any](tb testing.TB, v T) T {
	tb.Helper()

	data, err := cbor.Marshal(v)
	require.NoError(tb, err)
	var out T
	err = cbor.Unmarshal(data, &out)
	require.NoError(tb, err)
	return out
}
