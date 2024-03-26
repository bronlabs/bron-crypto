package csprng_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
)

func Test_ChachaPrng(t *testing.T) {
	// run the test
	testutils.PrngTester(t, fkechacha20.NewPrng)
}

func Test_TmmoPrng(t *testing.T) {
	// run the test
	NewNistPrngShort := func(seed, salt []byte) (csprng.CSPRNG, error) {
		return tmmohash.NewTmmoPrng(32, 16*7, seed, salt)
	}
	testutils.PrngTester(t, NewNistPrngShort)
}
