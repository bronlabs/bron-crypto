package chacha_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
)

func Test_ChachaPrng(t *testing.T) {
	// run the test
	testutils.PrngTester(t, chacha.NewChachaPRNG)
}
