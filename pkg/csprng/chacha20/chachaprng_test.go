package chacha20_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/testutils"
)

func Test_ChachaPrng(t *testing.T) {
	// run the test
	testutils.Test_prng(t, chacha20.NewChachaPRNG)
}
