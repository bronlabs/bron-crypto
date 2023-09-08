package csprng_test

import (
	"testing"

	"github.com/copperexchange/krypton/pkg/csprng"
	"github.com/copperexchange/krypton/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton/pkg/csprng/testutils"
	"github.com/copperexchange/krypton/pkg/hashing/tmmohash"
)

func Test_ChachaPrng(t *testing.T) {
	// run the test
	testutils.Test_prng(t, chacha20.NewChachaPRNG)
}

func Test_TmmoPrng(t *testing.T) {
	// run the test
	NewNistPrngShort := func(seed, salt []byte) (csprng.CSPRNG, error) {
		return tmmohash.NewTmmoPrng(32, 16*7, seed, salt)
	}
	testutils.Test_prng(t, NewNistPrngShort)
}
