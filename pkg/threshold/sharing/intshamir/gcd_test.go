package intshamir_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/intshamir"
)

func Test_GCD(t *testing.T) {
	x := int64(24 * 24 * 24 * 24 * 24)
	y := int64(65537)

	ss, tt, gcd := intshamir.ExtendedGCD(x, y)
	require.Equal(t, int64(1), gcd)
	require.Equal(t, int64(-5394), ss)
	require.Equal(t, int64(655361), tt)
}
