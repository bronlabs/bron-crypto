package impl_test

import (
	"encoding/hex"
	"slices"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
)

func dehex(t require.TestingT, p string) [impl.FieldBytes]byte {
	var out [impl.FieldBytes]byte
	x, err := hex.DecodeString(p)
	require.NoError(t, err)
	require.LessOrEqual(t, len(x), impl.FieldBytes)
	copy(out[impl.FieldBytes-len(x):], x)

	slices.Reverse(out[:])
	return out
}
