package fkechacha20_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
)

func Test_Fkechacha20Prng(t *testing.T) {
	t.Parallel()
	// run the test
	testutils.PrngTester(t, fkechacha20.NewPrng)
}
