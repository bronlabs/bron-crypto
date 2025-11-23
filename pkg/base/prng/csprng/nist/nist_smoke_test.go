package nist_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng/nist"
)

var _ csprng.SeedableCSPRNG = (*nist.PrngNist)(nil)
