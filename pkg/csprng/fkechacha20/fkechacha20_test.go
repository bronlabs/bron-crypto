package fkechacha20_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/csprng/testutils"
)

func Test_Fkechacha20Prng(t *testing.T) {
	t.Parallel()
	// run the test
	testutils.PrngTester(t, 32, 24, fkechacha20.NewPrng)
}
