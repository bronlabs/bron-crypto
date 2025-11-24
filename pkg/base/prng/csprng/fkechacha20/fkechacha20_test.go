package fkechacha20_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/testutils"
)

func Test_Fkechacha20Prng(t *testing.T) {
	t.Parallel()
	prngGenerator := func(seed, salt []byte) (csprng.SeedableCSPRNG, error) {
		return fkechacha20.NewPrng(seed, salt)
	}
	// run the test
	testutils.PrngTester(t, 32, 24, prngGenerator)
}
