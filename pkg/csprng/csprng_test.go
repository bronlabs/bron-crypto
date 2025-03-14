package csprng_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/bronlabs/bron-crypto/pkg/csprng/fkechacha20"
	"github.com/bronlabs/bron-crypto/pkg/csprng/testutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing/tmmohash"
)

func Test_ChachaPrng(t *testing.T) {
	t.Parallel()
	// run the test
	testutils.PrngTester(t, fkechacha20.NewPrng)
}

func Test_TmmoPrng(t *testing.T) {
	t.Parallel()
	// run the test
	NewNistPrngShort := func(seed, salt []byte) (csprng.CSPRNG, error) {
		return tmmohash.NewTmmoPrng(32, 16*7, seed, salt)
	}
	testutils.PrngTester(t, NewNistPrngShort)
}
