package fkechacha20_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/thirdparty/golang/crypto/chacha20"
)

func TestSmoke(t *testing.T) {
	t.Parallel()
	require.GreaterOrEqual(t, chacha20.KeySize*8, base.ComputationalSecurity,
		"chacha20.KeySize must be above base.ComputationalSecurity")
}
