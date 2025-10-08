package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/stretchr/testify/require"
)

func CBORRoundTrip[T any](tb testing.TB, v T) T {
	tb.Helper()

	data, err := serde.MarshalCBOR(v)
	require.NoError(tb, err)

	out, err := serde.UnmarshalCBOR[T](data)
	require.NoError(tb, err)
	return out
}
