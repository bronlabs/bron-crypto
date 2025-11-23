package fkechacha20_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/thirdparty/golang/crypto/chacha20"
)

var _ csprng.SeedableCSPRNG = (*fkechacha20.Prng)(nil)

func TestSmoke(t *testing.T) {
	t.Parallel()
	require.GreaterOrEqual(t, chacha20.KeySize*8, base.ComputationalSecurityBits,
		"chacha20.KeySize must be above base.ComputationalSecurity")
}
